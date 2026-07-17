// Package serviceloadbalancer drives the per-Node userspace
// programming for Juneau Service LoadBalancer (type=LoadBalancer)
// resources.
//
// The package is intentionally split from the existing
// reconciler/service package: ClusterIP and LoadBalancer share
// EndpointSlice plumbing but diverge sharply at the dataplane —
// LoadBalancer needs a separate ingress map (lb_service_map), a
// reverse-NAT representation, and a per-node "advertise this VIP?"
// gating that the ClusterIP path does not have. Keeping them in
// distinct packages avoids a god-object reconciler that has to
// branch on policy at every step.
//
// Phase 6 ships the userspace machinery with a Programmer interface
// behind which Phase 7 can drop in the eBPF map programmer. The
// types below are deliberately framework-agnostic — they describe
// what the dataplane needs to know, not how it stores it.
package serviceloadbalancer

import (
	"net"

	corev1 "k8s.io/api/core/v1"
)

// LBService is the desired-state snapshot for one
// ServiceLoadBalancer on this node. Empty Backends means the SLB is
// known but has no local backend; the Programmer should still record
// the VIP so dataplane tools can see "VIP advertised but unbacked"
// during transitions.
type LBService struct {
	// Key is the namespaced SLB resource name ("ns/name"). It is the
	// stable handle the Programmer uses to scope updates and
	// deletions; the rest of the struct is fully replaceable.
	Key string

	// VIP is the LoadBalancer external IP. Always IPv4 in the
	// initial release; the Phase 1 webhook enforces it.
	VIP net.IP

	// Ports is the ordered list of (port, protocol, targetPort)
	// triples the dataplane should DNAT for this VIP. Sorted by
	// (Port, Protocol) so the Programmer can rely on stable ordering
	// when deciding whether a re-program is needed.
	Ports []LBServicePort

	// Backends is the local-only set of resolved backends, one per
	// (port × endpoint) pair. The Programmer typically uses the
	// (Port, Proto) prefix to bucket backends per port at write time.
	Backends []LBBackend

	// Advertising captures whether this node is currently expected
	// to advertise the VIP. Reflects status.advertisingNodes
	// membership at reconcile time. The data plane need not gate
	// programming on this — even on a non-advertising node the maps
	// can hold backend entries — but the field is recorded so debug
	// tooling can correlate "VIP populated but not advertised" with
	// upstream BGP status.
	Advertising bool
}

// LBServicePort mirrors ServiceLoadBalancer.status.ports. TargetPort
// is the integer port published on the backend Pod (string-named
// ports are resolved upstream by the SLB controller so the dataplane
// always sees an integer).
type LBServicePort struct {
	Name       string
	Port       uint16
	Protocol   corev1.Protocol
	TargetPort uint16
}

// LBBackend is one resolved backend the dataplane should DNAT to.
// All backends in an LBService.Backends slice are local to this
// node — the iTP=Local filter happens upstream in the reconciler.
type LBBackend struct {
	// PodIP is the address packets are DNAT'd to. IPv4 only.
	PodIP net.IP

	// TargetPort is the L4 port matching LBServicePort.TargetPort
	// for this backend. Stored alongside ServicePort so the
	// dataplane can dispatch without re-correlating.
	ServicePort uint16
	TargetPort  uint16
	Protocol    corev1.Protocol

	// SubnetID is the Subnet VNI when the backend lives on a
	// Juneau-managed Pod, 0 when the backend is on a host-network
	// Pod (currently unsupported in Phase 6 — such backends are
	// dropped at resolution time and never make it to a Programmer
	// call).
	SubnetID uint32

	// Pod metadata captured for diagnostics; the BPF programmer can
	// ignore them.
	PodNamespace string
	PodName      string
}

// Key returns the ports entry's BPF map key form (port, proto).
// Provided as a helper so the reconciler and Programmer agree on the
// canonical bucket without duplicating the logic.
func (p LBServicePort) Key() (uint16, corev1.Protocol) { return p.Port, p.Protocol }
