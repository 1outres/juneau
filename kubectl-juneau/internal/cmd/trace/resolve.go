package trace

import (
	"context"
	"fmt"
	"net/netip"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resolved is the post-resolution view of one TraceSession that
// kubectl needs to: build initial tuples, pick which daemons to
// connect to, and render the timeline header.
type resolved struct {
	traceID uint32

	// source / destination — at least one resolves to a real Pod or
	// Service; the other side may be an opaque IP.
	source      endpoint
	destination endpoint

	// nodes is the deduplicated set of node names whose juneaud
	// kubectl will attach a debug stream to. At minimum it includes
	// the source node (when the source is a Pod) and any backend
	// nodes for a Service destination. ObserveOnly may add nodes
	// kubectl wants to watch even when no flow has been observed
	// yet.
	nodes []string

	// initialTuples are the 5-tuples kubectl precomputes; daemons
	// install these into trace_tuple_map at session-start.
	initialTuples []juneauv1alpha1.TraceTuple
}

// endpoint is the resolved description of one side of a session.
type endpoint struct {
	displayName string
	pod         *corev1.Pod
	service     *corev1.Service
	ip          netip.Addr
	nodeName    string
	vpcID       uint32
}

// resolveSession turns the parsed Options into a resolved struct.
// Behaviour:
//
//   - If source is a Pod, fetch it for its IP, node and VPC.
//   - If destination is a Pod, fetch it; tuple is single-shot.
//   - If destination is a Service, fetch its ClusterIP. If the
//     Service has multiple backends a tuple per backend is added
//     so each post-DNAT path can be traced.
//   - Otherwise destination is a literal IP.
//
// The resolver assumes a single-cluster, single-VPC deployment for
// now; multi-VPC support requires reading NetworkInterface to learn
// the VPC ID for each Pod.
func (o *Options) resolveSession(ctx context.Context, cl client.Client) (*resolved, error) {
	out := &resolved{traceID: o.traceID}

	if o.SourcePod != "" {
		ep, err := o.resolvePodEndpoint(ctx, cl, o.SourcePod)
		if err != nil {
			return nil, fmt.Errorf("resolve source pod: %w", err)
		}
		out.source = ep
	} else if o.SourceIP != "" {
		ip, err := netip.ParseAddr(o.SourceIP)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("--from-ip must be a valid IPv4 address: %v", err)
		}
		out.source = endpoint{displayName: o.SourceIP, ip: ip}
	}

	switch {
	case o.DestPod != "":
		ep, err := o.resolvePodEndpoint(ctx, cl, o.DestPod)
		if err != nil {
			return nil, fmt.Errorf("resolve destination pod: %w", err)
		}
		out.destination = ep
	case o.DestService != "":
		ep, err := o.resolveServiceEndpoint(ctx, cl, o.DestService)
		if err != nil {
			return nil, fmt.Errorf("resolve destination service: %w", err)
		}
		out.destination = ep
	case o.DestIP != "":
		ip, err := netip.ParseAddr(o.DestIP)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("--to-ip must be a valid IPv4 address: %v", err)
		}
		out.destination = endpoint{displayName: o.DestIP, ip: ip}
	}

	out.nodes = dedupeNonEmpty(out.source.nodeName, out.destination.nodeName)

	tuple, err := o.buildPrimaryTuple(out)
	if err != nil {
		return nil, err
	}
	out.initialTuples = append(out.initialTuples, tuple)

	// Backend tuples are no longer precomputed from EndpointSlices.
	// pod_egress now emits a DNAT_APPLIED event with both the original
	// (Service ClusterIP) and post-translation (backend Pod IP)
	// tuples, and kubectl propagates the latter to peer daemons via
	// Debug.LearnTuple — see run.go's PropagateLearnedTuple. That
	// path handles arbitrary NAT (Service DNAT, NAPT, shared-Service
	// SNAT, future translations) without kubectl re-implementing
	// the dataplane's translation logic.

	return out, nil
}

func (o *Options) buildPrimaryTuple(r *resolved) (juneauv1alpha1.TraceTuple, error) {
	if !r.source.ip.IsValid() {
		return juneauv1alpha1.TraceTuple{}, fmt.Errorf("source endpoint has no resolvable IPv4 address")
	}
	if !r.destination.ip.IsValid() {
		return juneauv1alpha1.TraceTuple{}, fmt.Errorf("destination endpoint has no resolvable IPv4 address")
	}
	scope := juneauv1alpha1.TraceTupleScopeVPC
	vpcID := r.source.vpcID
	if vpcID == 0 {
		vpcID = r.destination.vpcID
	}
	if vpcID == 0 {
		// Fallback to host scope when neither side resolved a VPC.
		// Daemons will look up by host scope and may not match — the
		// user can supply --from-pod to fix this.
		scope = juneauv1alpha1.TraceTupleScopeHost
	}
	return juneauv1alpha1.TraceTuple{
		Scope:    scope,
		VPCID:    vpcID,
		SrcIP:    r.source.ip.String(),
		DstIP:    r.destination.ip.String(),
		DstPort:  o.Port,
		Protocol: o.crdProtocol(),
	}, nil
}

func (o *Options) resolvePodEndpoint(ctx context.Context, cl client.Client, ref string) (endpoint, error) {
	ns, name := splitNamespacedName(ref, o.sourceNamespace)
	var pod corev1.Pod
	if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &pod); err != nil {
		return endpoint{}, fmt.Errorf("get pod %s/%s: %w", ns, name, err)
	}
	ep := endpoint{displayName: ns + "/" + name, pod: &pod, nodeName: pod.Spec.NodeName}
	if pod.Status.PodIP != "" {
		if addr, err := netip.ParseAddr(pod.Status.PodIP); err == nil && addr.Is4() {
			ep.ip = addr
		}
	}
	// VPC discovery: fetch the NetworkInterface for this Pod and
	// derive the VPC ID from the attached Subnet → Vpc chain.
	if vpcID, err := lookupPodVPC(ctx, cl, &pod); err == nil {
		ep.vpcID = vpcID
	}
	return ep, nil
}

func (o *Options) resolveServiceEndpoint(ctx context.Context, cl client.Client, ref string) (endpoint, error) {
	ns, name := splitNamespacedName(ref, o.destNamespace)
	var svc corev1.Service
	if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &svc); err != nil {
		return endpoint{}, fmt.Errorf("get service %s/%s: %w", ns, name, err)
	}
	ep := endpoint{displayName: ns + "/" + name, service: &svc}
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
		if addr, err := netip.ParseAddr(svc.Spec.ClusterIP); err == nil && addr.Is4() {
			ep.ip = addr
		}
	}
	return ep, nil
}

// lookupPodVPC walks Pod → NetworkInterface → Subnet → Vpc to learn
// the VPC ID. Best-effort: missing links return 0 and the caller
// falls back to host scope.
func lookupPodVPC(ctx context.Context, cl client.Client, pod *corev1.Pod) (uint32, error) {
	var nwifs juneauv1alpha1.NetworkInterfaceList
	if err := cl.List(ctx, &nwifs, client.InNamespace(pod.Namespace)); err != nil {
		return 0, err
	}
	var nwif *juneauv1alpha1.NetworkInterface
	for i := range nwifs.Items {
		if nwifs.Items[i].Spec.PodRef.UID == string(pod.UID) {
			nwif = &nwifs.Items[i]
			break
		}
		if nwifs.Items[i].Spec.PodRef.Name == pod.Name {
			nwif = &nwifs.Items[i]
		}
	}
	if nwif == nil {
		return 0, apierrors.NewNotFound(corev1.Resource("networkinterfaces"), pod.Name)
	}
	if nwif.Spec.Subnet == "" {
		return 0, fmt.Errorf("NetworkInterface %s has no subnet", nwif.Name)
	}
	var subnet juneauv1alpha1.Subnet
	if err := cl.Get(ctx, types.NamespacedName{Name: nwif.Spec.Subnet}, &subnet); err != nil {
		return 0, err
	}
	if subnet.Spec.Vpc == "" {
		return 0, fmt.Errorf("subnet %s has no vpc", subnet.Name)
	}
	var vpc juneauv1alpha1.Vpc
	if err := cl.Get(ctx, types.NamespacedName{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		return 0, err
	}
	return vpc.Status.VpcID, nil
}

func dedupeNonEmpty(in ...string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
