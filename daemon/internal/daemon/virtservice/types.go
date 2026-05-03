// Package virtservice exposes a tenant-aware "virtual service" plane
// that lives in the daemon's userspace and serves Pod traffic destined
// for per-Subnet virtual VIPs (DNS today; arbitrary L7 services in the
// future).
//
// The plane is layered so that each L7 service can be written against
// stdlib-shaped APIs (net.Conn, net.PacketConn) without ever importing
// BPF or AF_PACKET internals:
//
//   1. BPF classifier (pod_egress.c) catches Pod packets to known
//      virtual VIPs and redirects them to a TAP device, capturing
//      tenant + return-path metadata in virtual_service_flow_map.
//
//   2. The packet plane (subpackage packetplane) reads the redirected
//      frames from TAP, looks up the captured metadata, dispatches to
//      handlers, and sends responses straight back via AF_PACKET on the
//      Pod's host-side veth — never via the host routing table, which
//      has no native vpc_id dimension.
//
//   3. Built-in services (subpackage dns and friends) plug into the
//      packet plane via the Registry interface in this package, so the
//      service code never sees a TAP fd, an ifindex, or a BPF map.
//
// Doc handoff:
//   /tmp/juneau-virtual-service-plane-dns-handoff.md (in tree only as a
//   design reference; the file lives under /tmp by convention).
package virtservice

import (
	"context"
	"net"
	"net/netip"
)

// TenantID identifies the Subnet (and by extension the owning VPC) a
// packet belongs to. The packet plane reconstructs this from
// virtual_service_flow_map after reading a frame from TAP, so handlers
// always know which tenant they are answering on behalf of.
type TenantID struct {
	VPCID    uint32
	SubnetID uint32
}

// ServiceID is the daemon-internal identifier for a registered virtual
// service. DNS gets a well-known constant (ServiceIDDNS); future
// services should pick the next free uint32 to keep BPF map values
// auditable.
type ServiceID uint32

const (
	// ServiceIDDNS is the well-known ID for the built-in per-Subnet
	// virtual DNS resolver (UDP/53 + TCP/53 on .2).
	ServiceIDDNS ServiceID = 1
)

// Protocol is the L4 protocol the virtual service binds. Mirrors the
// IPPROTO_* numbers stored in BPF maps and AF_PACKET headers so no
// translation table is needed at the boundary.
type Protocol uint8

const (
	ProtocolUDP Protocol = 17 // IPPROTO_UDP
	ProtocolTCP Protocol = 6  // IPPROTO_TCP
)

// VirtualAddr is the (IP, port, proto) tuple a virtual service binds
// to inside a tenant. The IP is always the per-Subnet virtual VIP for
// a Subnet-scoped service (e.g. Subnet.status.dns for DNS).
type VirtualAddr struct {
	IP    netip.Addr
	Port  uint16
	Proto Protocol
}

// ServiceSpec describes a single tenant-scoped binding the registry
// must program into BPF and route to a handler. The same VirtualService
// can register many specs (e.g. one per (Subnet × {UDP, TCP})).
type ServiceSpec struct {
	ID         ServiceID
	Tenant     TenantID
	Addr       VirtualAddr
	ServiceMAC net.HardwareAddr
}

// PacketHandler handles a single inbound UDP frame destined for a
// virtual service. Implementations receive the L4 payload plus the
// reconstructed flow metadata; they call WriteResponse on the supplied
// Responder to send the reply back to the originating Pod via AF_PACKET.
//
// Lifetime: the payload byte slice is owned by the dispatcher and must
// not be retained after the handler returns. Copy if needed.
type PacketHandler interface {
	HandlePacket(ctx context.Context, req PacketRequest, resp Responder) error
}

// PacketRequest carries the request payload along with the metadata the
// dispatcher reconstructed from virtual_service_flow_map.
type PacketRequest struct {
	Tenant     TenantID
	Service    ServiceID
	Addr       VirtualAddr        // service-side address (dst of the request)
	ClientIP   netip.Addr         // Pod-side source IP
	ClientPort uint16             // Pod-side source port
	Payload    []byte             // L4 payload only; no IP / UDP headers
}

// Responder is what handlers use to send a single response payload
// back to the Pod. The packet plane attaches IP / UDP / Ethernet
// headers and dispatches via AF_PACKET on the Pod's host-side veth.
type Responder interface {
	WriteResponse(payload []byte) error
}

// Registry is the entry point virtual services use to bind themselves
// to tenants. The intentional shape mirrors net.Listener / net.PacketConn
// concepts so future L7 services don't have to know how the plane works
// underneath — they ask for a handler hook (UDP) or a listener (TCP)
// scoped to a tenant + virtual address, and the registry deals with
// the BPF / TAP / netstack wiring.
type Registry interface {
	// RegisterUDPHandler binds handler to packets that arrive on
	// (tenant, addr) in the packet plane. It is an error to register
	// twice for the same (tenant, addr) tuple. The returned
	// Unregister function removes the binding and cleans up BPF
	// state.
	RegisterUDPHandler(spec ServiceSpec, handler PacketHandler) (Unregister, error)

	// ListenTCP binds a tenant-scoped TCP listener at (tenant, addr)
	// in the gVisor netstack. Inbound TCP segments are demuxed to
	// the returned Listener; the caller Accept()s as if it owned a
	// regular net.Listener. Like RegisterUDPHandler, the returned
	// Unregister rolls back BPF / netstack state.
	//
	// The Listener and the Unregister are independent: closing the
	// Listener does not deregister the BPF entry. Always call
	// Unregister when retiring the binding.
	ListenTCP(spec ServiceSpec) (net.Listener, Unregister, error)
}

// Unregister tears down a previously-registered binding. Idempotent —
// calling it twice is a no-op.
type Unregister func() error
