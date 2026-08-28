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
	// ifname is the Pod NIC the trace is scoped to, empty when the
	// caller named none. A Pod with several NICs sits in a different
	// network on each, and the data plane keys its tuples by which.
	ifname string
	// networkName is the Subnet or L2Network that NIC joined. It is
	// what did or did not hand out an address for it.
	networkName string
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
		ep, err := o.resolvePodEndpoint(ctx, cl, o.SourcePod, o.SourceInterface, o.sourceNamespace)
		if err != nil {
			return nil, fmt.Errorf("resolve source pod: %w", err)
		}
		out.source = ep
	}
	if o.SourceIP != "" {
		ip, err := netip.ParseAddr(o.SourceIP)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("--from-ip must be a valid IPv4 address: %v", err)
		}
		out.source.ip = ip
		if out.source.pod == nil {
			out.source.displayName = o.SourceIP
		}
	}

	switch {
	case o.DestPod != "":
		ep, err := o.resolvePodEndpoint(ctx, cl, o.DestPod, o.DestInterface, o.destNamespace)
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
	}
	if o.DestIP != "" {
		ip, err := netip.ParseAddr(o.DestIP)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("--to-ip must be a valid IPv4 address: %v", err)
		}
		out.destination.ip = ip
		if out.destination.pod == nil && out.destination.service == nil {
			out.destination.displayName = o.DestIP
		}
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

	// A flow that leaves its Vpc — through a VpcPeering or a
	// TransitGateway — is seen on the far side under the destination
	// Vpc's id, because every hook resolves trace_tuple_map with the
	// vpc_id of the Subnet the packet is in. Without a copy scoped to
	// that id the receiving node's vxlan_ingress / pod_ingress hooks
	// never match and the timeline stops at the sending node.
	out.initialTuples = append(out.initialTuples,
		crossVPCTuples(out.initialTuples, out.destination.vpcID)...)

	// Append the Reply mirror of every Request tuple so the dataplane
	// resolves the same trace_id for reply packets from session start —
	// even for flows whose request leg is never observed during the
	// session (the dataplane's own auto-learn only fires once it matches
	// a request). Direction is programmed authoritatively, so rendering
	// never has to infer the leg.
	out.initialTuples = appendReverseTuples(out.initialTuples)

	return out, nil
}

// crossVPCTuples returns a copy of every tuple in forward rescoped to
// vpcID, so the same flow also resolves on nodes that see it under the
// destination Vpc's identity. Tuples already scoped to vpcID are left
// alone, and an unresolved id (0) adds nothing.
//
// The whole batch is dropped when it would push the session past
// maxInitialTuples, because the reply mirrors appended afterwards still
// need room and a partial set of scopes is more confusing than none.
func crossVPCTuples(forward []juneauv1alpha1.TraceTuple, vpcID uint32) []juneauv1alpha1.TraceTuple {
	if vpcID == 0 {
		return nil
	}
	var out []juneauv1alpha1.TraceTuple
	for _, t := range forward {
		if t.VPCID == vpcID {
			continue
		}
		t.Scope = juneauv1alpha1.TraceTupleScopeVPC
		t.VPCID = vpcID
		out = append(out, t)
	}
	if len(forward)+len(out) > maxInitialTuples {
		return nil
	}
	return out
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
		return juneauv1alpha1.TraceTuple{}, fmt.Errorf(
			"the source has no address juneau knows about; give one with --from-ip%s", noAddressHint(r.source))
	}
	if !r.destination.ip.IsValid() {
		return juneauv1alpha1.TraceTuple{}, fmt.Errorf(
			"the destination has no address juneau knows about; give one with --to-ip%s", noAddressHint(r.destination))
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

// resolvePodEndpoint reads one side of a session out of a Pod.
//
// ifname picks which of the Pod's NICs the trace is about. Left empty
// it means the Pod itself: status.podIP for the address and a
// best-effort walk to the Vpc, which is what a trace of the Pod's own
// traffic wants and what this command has always done.
//
// Named, it means that NIC and nothing else. Both the address and the
// Vpc come from its NetworkInterface, and a NIC that is not there is
// an error rather than a quiet fall back to the Pod — the user asked
// about a specific NIC, and answering about a different one would be
// worse than saying no.
func (o *Options) resolvePodEndpoint(ctx context.Context, cl client.Client, ref, ifname, defaultNs string) (endpoint, error) {
	ns, name := splitNamespacedName(ref, defaultNs)
	var pod corev1.Pod
	if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &pod); err != nil {
		return endpoint{}, fmt.Errorf("get pod %s/%s: %w", ns, name, err)
	}
	ep := endpoint{displayName: ns + "/" + name, pod: &pod, nodeName: pod.Spec.NodeName}

	if ifname == "" {
		if pod.Status.PodIP != "" {
			if addr, err := netip.ParseAddr(pod.Status.PodIP); err == nil && addr.Is4() {
				ep.ip = addr
			}
		}
		// VPC discovery: fetch the NetworkInterface for this Pod and
		// derive the VPC ID from the attached network → Vpc chain.
		if vpcID, err := lookupPodVPC(ctx, cl, &pod); err == nil {
			ep.vpcID = vpcID
		}
		return ep, nil
	}

	nwif, err := findPodNetworkInterface(ctx, cl, &pod, ifname)
	if err != nil {
		return endpoint{}, err
	}
	vpcID, err := nicVpcID(ctx, cl, nwif)
	if err != nil {
		return endpoint{}, fmt.Errorf("read the Vpc of %s: %w", nwif.Name, err)
	}
	addr, err := nicAddress(nwif)
	if err != nil {
		return endpoint{}, err
	}

	ep.displayName = ns + "/" + name + ":" + ifname
	ep.ifname = ifname
	ep.networkName = nicNetworkName(nwif)
	ep.vpcID = vpcID
	// An L2Network without a CIDR hands the NIC no address, and the
	// workload picks one juneau never sees. Leaving the field unset is
	// what makes buildPrimaryTuple ask the user for it, rather than
	// keying the trace on the address of a different NIC.
	ep.ip = addr
	return ep, nil
}

// noAddressHint adds the reason a NIC has no address, when the caller
// named one and the answer is on the object.
func noAddressHint(ep endpoint) string {
	if ep.ifname == "" {
		return ""
	}
	return fmt.Sprintf(" (%s hands out no address on %s)", ep.networkName, ep.ifname)
}

// nicNetworkName returns the network the NIC joined. nicVpcID has
// already rejected a NIC that names neither, so one of the two is set.
func nicNetworkName(nwif *juneauv1alpha1.NetworkInterface) string {
	if nwif.Spec.L2Network != "" {
		return nwif.Spec.L2Network
	}
	return nwif.Spec.Subnet
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

// lookupPodVPC learns the Vpc id of a Pod's own address, which lives
// on its primary NIC. Best-effort: missing links return an error the
// caller swallows to fall back to host scope.
func lookupPodVPC(ctx context.Context, cl client.Client, pod *corev1.Pod) (uint32, error) {
	nwif, err := findPodNetworkInterface(ctx, cl, pod, juneauv1alpha1.PodPrimaryInterfaceName)
	if err != nil {
		return 0, err
	}
	return nicVpcID(ctx, cl, nwif)
}

// findPodNetworkInterface returns the NetworkInterface backing one NIC
// of a Pod.
//
// A match on the Pod UID wins outright. A match on the name alone is
// kept as the answer only if no UID match turns up, because a Pod that
// was recreated under the same name leaves the NetworkInterface of the
// old instance behind for a moment.
func findPodNetworkInterface(ctx context.Context, cl client.Client, pod *corev1.Pod, ifname string) (*juneauv1alpha1.NetworkInterface, error) {
	var nwifs juneauv1alpha1.NetworkInterfaceList
	if err := cl.List(ctx, &nwifs, client.InNamespace(pod.Namespace)); err != nil {
		return nil, err
	}
	var byName *juneauv1alpha1.NetworkInterface
	for i := range nwifs.Items {
		podRef := nwifs.Items[i].Spec.PodRef
		if podRef.Interface != ifname {
			continue
		}
		if podRef.UID == string(pod.UID) {
			return &nwifs.Items[i], nil
		}
		if podRef.Name == pod.Name {
			byName = &nwifs.Items[i]
		}
	}
	if byName != nil {
		return byName, nil
	}
	return nil, fmt.Errorf("pod %s/%s has no NetworkInterface for %q: %w",
		pod.Namespace, pod.Name, ifname,
		apierrors.NewNotFound(corev1.Resource("networkinterfaces"), pod.Name))
}

// nicVpcID reads the Vpc identity the data plane stamps on the frames
// of one NIC. Every hook resolves trace_tuple_map with it, so a trace
// that carries the wrong one matches nothing at all.
//
// The two kinds of network a NIC joins reach it by different routes: a
// Subnet names its Vpc, an L2Network names its own. Both end at
// Vpc.status.vpcID, which is the number the data plane writes.
func nicVpcID(ctx context.Context, cl client.Client, nwif *juneauv1alpha1.NetworkInterface) (uint32, error) {
	var vpcName string
	switch {
	case nwif.Spec.Subnet != "":
		var subnet juneauv1alpha1.Subnet
		if err := cl.Get(ctx, types.NamespacedName{Name: nwif.Spec.Subnet}, &subnet); err != nil {
			return 0, err
		}
		if subnet.Spec.Vpc == "" {
			return 0, fmt.Errorf("subnet %s has no vpc", subnet.Name)
		}
		vpcName = subnet.Spec.Vpc
	case nwif.Spec.L2Network != "":
		var network juneauv1alpha1.L2Network
		if err := cl.Get(ctx, types.NamespacedName{Name: nwif.Spec.L2Network}, &network); err != nil {
			return 0, err
		}
		if network.Spec.Vpc == "" {
			return 0, fmt.Errorf("l2network %s has no vpc", network.Name)
		}
		vpcName = network.Spec.Vpc
	default:
		return 0, fmt.Errorf("NetworkInterface %s names neither a subnet nor an l2Network", nwif.Name)
	}

	var vpc juneauv1alpha1.Vpc
	if err := cl.Get(ctx, types.NamespacedName{Name: vpcName}, &vpc); err != nil {
		return 0, err
	}
	return vpc.Status.VpcID, nil
}

// nicAddress is the address juneau handed one NIC, and the zero Addr
// when it handed out none. An L2Network without a CIDR is the case
// that reaches here: the workload addresses the segment itself, so
// there is nothing for kubectl to read and the caller has to ask the
// user instead.
//
// status.address is written in CIDR form; a bare address is accepted
// too, the same way the daemon reads the field.
func nicAddress(nwif *juneauv1alpha1.NetworkInterface) (netip.Addr, error) {
	raw := nwif.Status.Address
	if raw == "" {
		return netip.Addr{}, nil
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(raw)
		if prefixErr != nil {
			return netip.Addr{}, fmt.Errorf(
				"NetworkInterface %s carries an address kubectl cannot read (%q): %w", nwif.Name, raw, err)
		}
		addr = prefix.Addr()
	}
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf(
			"NetworkInterface %s carries a non-IPv4 address (%q); trace is IPv4 only", nwif.Name, raw)
	}
	return addr, nil
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
