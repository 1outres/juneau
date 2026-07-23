// Package netstack hides every gVisor type behind a small,
// daemon-shaped facade. Two reasons:
//
//  1. gvisor.dev/gvisor/pkg/tcpip is intentionally not semver-stable.
//     Pinning the import surface here means upgrades touch one
//     package, not every L7 service.
//
//  2. The daemon's tenant model (vpc_id + Pod return-path) doesn't
//     cleanly map onto stack.NICOptions. Building the bridge once,
//     here, avoids leaking gVisor concepts into the DNS resolver.
//
// Operationally the facade owns:
//
//   - one shared stack.Stack (TCP + IPv4 only — UDP terminates in
//     the upstream packet plane, not gVisor);
//   - one channel.Endpoint per VPC, exposed as a tcpip.NIC, with
//     every Subnet's DNS VIP added as a per-NIC protocol address;
//   - a per-NIC drain goroutine that pulls outbound segments out of
//     channel.Endpoint, joins them with return-path metadata
//     captured at request time, and ships them via AF_PACKET on the
//     originating Pod's host-side veth.
//
// Inbound TCP segments are injected via Inject(); outbound segments
// are returned to the network via the supplied packetplane.Sender.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/1outres/juneau/daemon/internal/daemon/virtservice/packetplane"
)

// Facade is the daemon-side handle to the embedded gVisor netstack
// instance. Construct once at startup; share across every TCP
// virtual service (DNS today).
type Facade struct {
	stack  *stack.Stack
	sender *packetplane.Sender

	mu    sync.Mutex
	nics  map[uint32]*vpcNIC           // vpc_id -> NIC bundle
	flows map[returnFlowKey]ReturnPath // outbound demux table
}

// vpcNIC bundles everything tied to one VPC's NIC. The drain
// goroutine reads outbound packets from endpoint and sends them via
// the shared sender, joining them with returnPath metadata recorded
// when the matching inbound packet was injected.
type vpcNIC struct {
	nicID    tcpip.NICID
	endpoint *channel.Endpoint
	addrs    map[netip.Addr]struct{} // VIPs registered on this NIC

	cancel context.CancelFunc
	done   chan struct{}
}

// returnFlowKey indexes outbound TCP packets back to the Pod that
// originated the request. Keyed on (vpc, pod_ip, pod_port,
// service_ip, service_port) — every field is unambiguous within a
// VPC NIC because Pod IPs in a single VPC do not overlap (Subnets
// inside a Vpc carve disjoint CIDRs).
type returnFlowKey struct {
	VPCID       uint32
	PodIP       netip.Addr
	PodPort     uint16
	ServiceIP   netip.Addr
	ServicePort uint16
}

// ReturnPath is the AF_PACKET dispatch metadata captured at request
// time for one TCP flow. Mirrors packetplane.Flow's return-path
// fields but is decoupled so tests can populate it without faking
// the whole flow.
type ReturnPath struct {
	PodIfindex int
	PodMAC     net.HardwareAddr
	ServiceMAC net.HardwareAddr
}

// New constructs a Facade with a fresh gVisor stack configured for
// TCP/IPv4. sender is borrowed; the facade does not close it.
func New(sender *packetplane.Sender) *Facade {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	return &Facade{
		stack:  s,
		sender: sender,
		nics:   map[uint32]*vpcNIC{},
		flows:  map[returnFlowKey]ReturnPath{},
	}
}

// Stop cancels every drain goroutine and tears down NICs. Safe to
// call multiple times.
func (f *Facade) Stop() error {
	f.mu.Lock()
	nics := f.nics
	f.nics = map[uint32]*vpcNIC{}
	f.mu.Unlock()

	for _, n := range nics {
		if n.cancel != nil {
			n.cancel()
		}
		if n.done != nil {
			<-n.done
		}
		n.endpoint.Close()
		f.stack.RemoveNIC(n.nicID)
	}
	return nil
}

// EnsureNIC lazily creates a NIC for vpcID and adds vip as a local
// IPv4 address on it (no-op if already present). The drain goroutine
// for the NIC starts on the first creation.
//
// ctx scopes the drain goroutine; passing the daemon's run-context
// keeps the NIC alive for the daemon's lifetime.
func (f *Facade) EnsureNIC(ctx context.Context, vpcID uint32, vip netip.Addr) error {
	if !vip.Is4() {
		return fmt.Errorf("netstack: only IPv4 VIPs supported, got %s", vip)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	n, ok := f.nics[vpcID]
	if !ok {
		nicID := tcpip.NICID(vpcID)
		// MTU 9000 is intentionally large: the drain loop reads
		// whole IP packets from gVisor and gVisor never produces
		// frames larger than the endpoint MTU. We rely on TCP MSS
		// negotiation to keep on-wire packets within the
		// underlay's MTU. BPF / AF_PACKET don't fragment.
		ep := channel.New(1024, 9000, "")
		opts := stack.NICOptions{Name: fmt.Sprintf("juneau-vpc-%d", vpcID)}
		if errt := f.stack.CreateNICWithOptions(nicID, ep, opts); errt != nil {
			return fmt.Errorf("create NIC for vpc %d: %s", vpcID, errt)
		}

		n = &vpcNIC{
			nicID:    nicID,
			endpoint: ep,
			addrs:    map[netip.Addr]struct{}{},
		}

		drainCtx, cancel := context.WithCancel(ctx)
		n.cancel = cancel
		n.done = make(chan struct{})
		go func() {
			defer close(n.done)
			f.drainLoop(drainCtx, n, vpcID)
		}()

		f.nics[vpcID] = n
	}

	if _, exists := n.addrs[vip]; exists {
		return nil
	}
	addr4 := vip.As4()
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr4[:]),
			PrefixLen: 32,
		},
	}
	if errt := f.stack.AddProtocolAddress(n.nicID, protoAddr, stack.AddressProperties{}); errt != nil {
		return fmt.Errorf("add VIP %s on NIC %d: %s", vip, n.nicID, errt)
	}
	n.addrs[vip] = struct{}{}
	return nil
}

// RemoveVIP removes vip from vpcID's NIC. The NIC itself is kept
// alive (a future Subnet may re-add a VIP); explicit destruction
// happens at Facade.Stop only.
func (f *Facade) RemoveVIP(vpcID uint32, vip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nics[vpcID]
	if !ok {
		return nil
	}
	if _, present := n.addrs[vip]; !present {
		return nil
	}
	addr4 := vip.As4()
	if errt := f.stack.RemoveAddress(n.nicID, tcpip.AddrFromSlice(addr4[:])); errt != nil {
		return fmt.Errorf("remove VIP %s from NIC %d: %s", vip, n.nicID, errt)
	}
	delete(n.addrs, vip)
	return nil
}

// ListenTCP binds a TCP listener on (vpcID NIC, vip:port). Returns a
// stdlib-shaped net.Listener so callers don't see gonet types. The
// caller must EnsureNIC first.
func (f *Facade) ListenTCP(vpcID uint32, vip netip.Addr, port uint16) (net.Listener, error) {
	if !vip.Is4() {
		return nil, fmt.Errorf("netstack: only IPv4 VIPs supported, got %s", vip)
	}
	f.mu.Lock()
	n, ok := f.nics[vpcID]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("netstack: vpc %d has no NIC; call EnsureNIC first", vpcID)
	}
	if _, addrOk := n.addrs[vip]; !addrOk {
		return nil, fmt.Errorf("netstack: VIP %s not on NIC for vpc %d", vip, vpcID)
	}

	addr4 := vip.As4()
	full := tcpip.FullAddress{
		NIC:  n.nicID,
		Addr: tcpip.AddrFromSlice(addr4[:]),
		Port: port,
	}
	l, err := listenTCPOnNIC(f.stack, full, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("netstack: listen TCP on NIC %d: %w", n.nicID, err)
	}
	return l, nil
}

// listenTCPOnNIC is the device-bound counterpart of gonet.ListenTCP.
// FullAddress.NIC only selects the NIC used to validate the local address;
// gVisor's port reservation remains device-agnostic unless SO_BINDTODEVICE is
// set on the endpoint before Bind. Juneau VPCs may use overlapping VIPs, so
// every listener must reserve its address and port within its VPC NIC.
func listenTCPOnNIC(s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (net.Listener, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %s", err)
	}

	closeEndpoint := true
	defer func() {
		if closeEndpoint {
			ep.Close()
		}
	}()

	if err := ep.SocketOptions().SetBindToDevice(int32(addr.NIC)); err != nil {
		return nil, fmt.Errorf("bind endpoint to NIC %d: %s", addr.NIC, err)
	}
	if err := ep.Bind(addr); err != nil {
		return nil, fmt.Errorf("bind %s:%d: %s", addr.Addr, addr.Port, err)
	}
	const listenBacklog = 4096
	if err := ep.Listen(listenBacklog); err != nil {
		return nil, fmt.Errorf("listen %s:%d: %s", addr.Addr, addr.Port, err)
	}

	closeEndpoint = false
	return gonet.NewTCPListener(s, &wq, ep), nil
}

// Inject delivers an IPv4 packet (no Ethernet header) into vpcID's
// NIC and records the return-path metadata for the matching outbound
// flow so the drain loop can demux replies back to the right Pod.
//
// The caller is the dispatcher; flow describes the inbound 5-tuple.
func (f *Facade) Inject(vpcID uint32, ipPacket []byte, flow packetplane.Flow) error {
	if len(ipPacket) < 20 {
		return errors.New("netstack: ipPacket too short")
	}
	f.mu.Lock()
	n, ok := f.nics[vpcID]
	if ok {
		// Record return path BEFORE injecting so the drain loop
		// can never observe an outbound packet without metadata.
		key := returnFlowKey{
			VPCID:       vpcID,
			PodIP:       flow.ClientIP,
			PodPort:     flow.ClientPort,
			ServiceIP:   flow.ServiceIP,
			ServicePort: flow.ServicePort,
		}
		f.flows[key] = ReturnPath{
			PodIfindex: flow.PodIfindex,
			PodMAC:     flow.PodMAC,
			ServiceMAC: flow.ServiceMAC,
		}
	}
	f.mu.Unlock()

	if !ok {
		return fmt.Errorf("netstack: vpc %d has no NIC", vpcID)
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ipPacket),
	})
	defer pkt.DecRef()
	n.endpoint.InjectInbound(ipv4.ProtocolNumber, pkt)
	return nil
}

// drainLoop pulls outbound packets from a NIC's channel.Endpoint and
// hands them off to the AF_PACKET sender, prepending the per-flow
// Ethernet header reconstructed from f.flows.
func (f *Facade) drainLoop(ctx context.Context, n *vpcNIC, vpcID uint32) {
	for {
		pkt := n.endpoint.ReadContext(ctx)
		if pkt == nil {
			return // channel closed or ctx cancelled
		}
		if err := f.handleOutbound(vpcID, pkt); err != nil {
			zap.S().Debugf("netstack: drain handle error vpc=%d: %v", vpcID, err)
		}
		pkt.DecRef()
	}
}

// handleOutbound builds the Ethernet frame for a single drained
// packet and sends it via AF_PACKET. Looks up the return path by
// reverse 5-tuple — the outbound packet's src is the service VIP
// and its dst is the Pod.
func (f *Facade) handleOutbound(vpcID uint32, pkt *stack.PacketBuffer) error {
	view := pkt.ToView()
	defer view.Release()
	ipBytes := view.AsSlice()
	if len(ipBytes) < header.IPv4MinimumSize {
		return errors.New("outbound IP packet too short")
	}
	if header.IPVersion(ipBytes) != 4 {
		return errors.New("outbound packet is not IPv4")
	}
	ipHdr := header.IPv4(ipBytes)
	if !ipHdr.IsValid(len(ipBytes)) {
		return errors.New("outbound IPv4 header is invalid")
	}
	if ipHdr.Protocol() != uint8(header.TCPProtocolNumber) {
		// Stray non-TCP outbound (ICMP unreachable etc.). For
		// initial implementation we drop; future work can route
		// these via the same scheme once we bind their flow keys.
		return nil
	}

	srcAddr := ipHdr.SourceAddress()
	dstAddr := ipHdr.DestinationAddress()
	srcIP := ipv4FromSlice(srcAddr.AsSlice())
	dstIP := ipv4FromSlice(dstAddr.AsSlice())
	tcpHdr := header.TCP(ipBytes[ipHdr.HeaderLength():])
	if len(tcpHdr) < header.TCPMinimumSize {
		return errors.New("outbound TCP header too short")
	}
	srcPort := tcpHdr.SourcePort()
	dstPort := tcpHdr.DestinationPort()

	key := returnFlowKey{
		VPCID:       vpcID,
		PodIP:       dstIP, // outbound dst → original src (Pod)
		PodPort:     dstPort,
		ServiceIP:   srcIP, // outbound src → service VIP
		ServicePort: srcPort,
	}
	f.mu.Lock()
	rp, ok := f.flows[key]
	f.mu.Unlock()
	if !ok {
		return fmt.Errorf("no return path for outbound %s:%d -> %s:%d (vpc=%d)", srcIP, srcPort, dstIP, dstPort, vpcID)
	}

	// Track FIN/RST so we can age out flow entries; RST means the
	// connection is going away immediately, FIN starts a graceful
	// close. Either way the Pod's response port may be reused soon
	// by a different flow, so we drop our tracking.
	flags := tcpHdr.Flags()
	const finRst = header.TCPFlagFin | header.TCPFlagRst
	if flags&finRst != 0 {
		f.mu.Lock()
		delete(f.flows, key)
		f.mu.Unlock()
	}

	frame := make([]byte, packetplane.EthernetHeaderLen+len(ipBytes))
	copy(frame[0:6], rp.PodMAC)
	copy(frame[6:12], rp.ServiceMAC)
	frame[12] = 0x08
	frame[13] = 0x00
	copy(frame[packetplane.EthernetHeaderLen:], ipBytes)

	return f.sender.SendTo(rp.PodIfindex, rp.PodMAC, frame)
}

// ipv4FromSlice converts a network-byte-order 4-byte slice to a
// netip.Addr without allocations.
func ipv4FromSlice(b []byte) netip.Addr {
	if len(b) != 4 {
		return netip.Addr{}
	}
	var arr [4]byte
	copy(arr[:], b)
	return netip.AddrFrom4(arr)
}
