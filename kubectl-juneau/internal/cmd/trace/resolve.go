package trace

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
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
	// install these into trace_tuple_map at session-start. Each Request
	// tuple is followed by its Reply mirror so reply packets resolve the
	// same trace_id from session start, even for flows whose request leg
	// is never observed during the session (see appendReverseTuples).
	initialTuples []juneauv1alpha1.TraceTuple
}

// maxInitialTuples mirrors the controller webhook's MaxInitialTuples
// admission cap so kubectl never emits a TraceSession the API server
// would reject after reverse mirrors double the tuple count.
const maxInitialTuples = 64

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

	// For Service destinations, pre-seed one tuple per backend so
	// destination-node hooks (vxlan_ingress, pod_ingress) match the
	// post-DNAT packet on the very first probe. The async LearnTuple
	// fan-out from run.go's PropagateLearnedTuple stays in place to
	// handle NAT classes kubectl cannot precompute (NAPT,
	// shared-Service SNAT, future translations) — but it only fires
	// after a NAT event is decoded userspace-side, which is too late
	// for the first cross-node packet of a one-shot active probe.
	if o.DestService != "" && out.destination.service != nil {
		extra, extraNodes, err := o.serviceBackendTuples(ctx, cl, out)
		if err != nil {
			return nil, err
		}
		out.initialTuples = append(out.initialTuples, extra...)
		out.nodes = dedupeNonEmpty(append(out.nodes, extraNodes...)...)
	}

	// Append the Reply mirror of every Request tuple so the dataplane
	// resolves the same trace_id for reply packets from session start —
	// even for flows whose request leg is never observed during the
	// session (the dataplane's own auto-learn only fires once it matches
	// a request). Direction is programmed authoritatively, so rendering
	// never has to infer the leg.
	out.initialTuples = appendReverseTuples(out.initialTuples)

	return out, nil
}

// appendReverseTuples returns the Request tuples followed by their
// Reply mirrors: source/destination swapped and both ports wildcarded
// to 0. The daemon's dport=0 second-chance lookup then matches reply
// packets whose ephemeral destination port kubectl cannot predict at
// session start.
//
// A mirror that duplicates an existing tuple (e.g. a symmetric
// wildcard tuple that is its own reverse) is skipped, and the total is
// capped at maxInitialTuples so the resulting TraceSession stays within
// the admission limit. Request tuples are always preserved; only
// surplus mirrors are dropped.
func appendReverseTuples(forward []juneauv1alpha1.TraceTuple) []juneauv1alpha1.TraceTuple {
	// Dedup on the BPF key fields only — direction lives in the map
	// value, so two tuples sharing a key occupy one slot. keyOf clears
	// Direction so a symmetric wildcard tuple (its own reverse) is
	// recognised as already present and does not get a conflicting Reply
	// mirror written over its Request slot.
	keyOf := func(t juneauv1alpha1.TraceTuple) juneauv1alpha1.TraceTuple {
		t.Direction = ""
		return t
	}
	seen := make(map[juneauv1alpha1.TraceTuple]struct{}, len(forward)*2)
	for _, t := range forward {
		seen[keyOf(t)] = struct{}{}
	}
	out := forward
	for _, t := range forward {
		if len(out) >= maxInitialTuples {
			break
		}
		rev := juneauv1alpha1.TraceTuple{
			Scope:     t.Scope,
			VPCID:     t.VPCID,
			SrcIP:     t.DstIP,
			DstIP:     t.SrcIP,
			SrcPort:   0,
			DstPort:   0,
			Protocol:  t.Protocol,
			Direction: juneauv1alpha1.TraceTupleDirectionReply,
		}
		if _, dup := seen[keyOf(rev)]; dup {
			continue
		}
		seen[keyOf(rev)] = struct{}{}
		out = append(out, rev)
	}
	return out
}

// serviceBackendTuples enumerates the destination Service's
// EndpointSlices and returns a tuple per (backend IP, target port)
// pair plus the deduplicated set of backend node names. Each tuple is
// keyed (sourceIP, backendIP, targetPort) so on vxlan_ingress /
// pod_ingress the post-DNAT packet matches without waiting for the
// daemon's userspace learn round-trip.
//
// Returns (nil, nil, nil) when the source has no resolvable IP or the
// destination is not actually a Service — those callers fall back to
// the primary tuple alone.
func (o *Options) serviceBackendTuples(ctx context.Context, cl client.Client, r *resolved) ([]juneauv1alpha1.TraceTuple, []string, error) {
	if !r.source.ip.IsValid() || r.destination.service == nil {
		return nil, nil, nil
	}
	svc := r.destination.service

	// Service.Spec.Ports[i].Name is the join key against
	// EndpointSlice.Ports[].Name. Find the entry that matches the
	// user-supplied --port + --proto so multi-port Services route to
	// the correct targetPort. An empty name is the legitimate
	// single-port case.
	wantPortName, found := matchingServicePortName(svc, o.Port, o.Protocol)
	if !found {
		// User asked for a port the Service does not expose. Don't
		// fabricate backend tuples — the primary tuple plus the
		// LearnTuple async path is the safer fallback.
		return nil, nil, nil
	}

	var slices discoveryv1.EndpointSliceList
	if err := cl.List(ctx, &slices,
		client.InNamespace(svc.Namespace),
		client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name},
	); err != nil {
		return nil, nil, fmt.Errorf("list endpointslices for %s/%s: %w", svc.Namespace, svc.Name, err)
	}

	scope := juneauv1alpha1.TraceTupleScopeVPC
	vpcID := r.source.vpcID
	if vpcID == 0 {
		scope = juneauv1alpha1.TraceTupleScopeHost
	}
	proto := o.crdProtocol()

	var (
		tuples []juneauv1alpha1.TraceTuple
		nodes  []string
	)
	for _, sl := range slices.Items {
		if sl.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}
		targetPort := pickEndpointPort(sl.Ports, wantPortName, proto)
		if targetPort == 0 {
			continue
		}
		for _, ep := range sl.Endpoints {
			if !endpointReady(ep) {
				continue
			}
			for _, addr := range ep.Addresses {
				ip, err := netip.ParseAddr(addr)
				if err != nil || !ip.Is4() {
					continue
				}
				tuples = append(tuples, juneauv1alpha1.TraceTuple{
					Scope:     scope,
					VPCID:     vpcID,
					SrcIP:     r.source.ip.String(),
					DstIP:     ip.String(),
					DstPort:   targetPort,
					Protocol:  proto,
					Direction: juneauv1alpha1.TraceTupleDirectionRequest,
				})
				if ep.NodeName != nil && *ep.NodeName != "" {
					nodes = append(nodes, *ep.NodeName)
				}
			}
		}
	}
	return tuples, nodes, nil
}

// matchingServicePortName returns the Service port name (possibly
// empty) whose Port and Protocol match the user-requested values. The
// second return is false when no entry matches.
func matchingServicePortName(svc *corev1.Service, port int32, proto string) (string, bool) {
	want := corev1.ProtocolTCP
	switch strings.ToLower(proto) {
	case "udp":
		want = corev1.ProtocolUDP
	case "icmp":
		// Services do not expose ICMP; let the caller skip backend
		// seeding for ICMP traces.
		return "", false
	}
	for _, sp := range svc.Spec.Ports {
		if sp.Port != port {
			continue
		}
		got := sp.Protocol
		if got == "" {
			got = corev1.ProtocolTCP
		}
		if got != want {
			continue
		}
		return sp.Name, true
	}
	return "", false
}

// pickEndpointPort selects the EndpointSlice port corresponding to
// wantName + proto. An exact name match wins over a wildcard fallback;
// the fallback handles legacy unnamed ports on single-port Services.
func pickEndpointPort(ports []discoveryv1.EndpointPort, wantName string, proto juneauv1alpha1.TraceProtocol) int32 {
	var fallback int32
	for _, p := range ports {
		if p.Port == nil || !endpointPortMatchesProto(p, proto) {
			continue
		}
		name := ""
		if p.Name != nil {
			name = *p.Name
		}
		if name == wantName {
			return *p.Port
		}
		if fallback == 0 {
			fallback = *p.Port
		}
	}
	return fallback
}

func endpointPortMatchesProto(p discoveryv1.EndpointPort, proto juneauv1alpha1.TraceProtocol) bool {
	if p.Protocol == nil {
		return proto == juneauv1alpha1.TraceProtocolTCP
	}
	switch *p.Protocol {
	case corev1.ProtocolTCP:
		return proto == juneauv1alpha1.TraceProtocolTCP
	case corev1.ProtocolUDP:
		return proto == juneauv1alpha1.TraceProtocolUDP
	}
	return false
}

// endpointReady mirrors the kubelet contract: missing Conditions is
// treated as ready (legacy slice). NotReady backends would never
// receive DNAT'd traffic, so seeding their tuples is wasted state.
func endpointReady(ep discoveryv1.Endpoint) bool {
	if ep.Conditions.Ready == nil {
		return true
	}
	return *ep.Conditions.Ready
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
		Scope:     scope,
		VPCID:     vpcID,
		SrcIP:     r.source.ip.String(),
		DstIP:     r.destination.ip.String(),
		DstPort:   o.Port,
		Protocol:  o.crdProtocol(),
		Direction: juneauv1alpha1.TraceTupleDirectionRequest,
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
