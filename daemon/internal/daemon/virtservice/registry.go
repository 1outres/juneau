package virtservice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/virtservice/packetplane"
)

// NetstackFacade is the abstract operations the registry needs from
// the gVisor TCP plane. Stubbed out so unit tests don't have to
// instantiate a real stack.
type NetstackFacade interface {
	EnsureNIC(ctx context.Context, vpcID uint32, vip netipAddr) error
	RemoveVIP(vpcID uint32, vip netipAddr) error
	ListenTCP(vpcID uint32, vip netipAddr, port uint16) (net.Listener, error)
	Inject(vpcID uint32, ipPacket []byte, flow packetplane.Flow) error
}

// registry is the concrete Registry implementation. It programs
// virtual_service_map (so the BPF classifier knows which packets to
// redirect), wires UDP handlers and TCP listeners through the
// packet-plane Dispatcher / netstack Facade, and supplies the glue
// Responder used by handlers to send UDP responses out via AF_PACKET.
type registry struct {
	dispatcher *packetplane.Dispatcher
	flowTable  *packetplane.FlowTable
	sender     *packetplane.Sender
	tap        *packetplane.TAP
	bpfMap     *ebpf.Map // virtual_service_map
	netstack   NetstackFacade
	netCtx     context.Context

	mu       sync.Mutex
	bindings map[bindingKey]*binding
}

// netipAddr is an alias used only to keep the NetstackFacade interface
// signatures readable. Real callers pass netip.Addr; the alias avoids
// a stuttering import path in the interface definition.
type netipAddr = netip.Addr

type bindingKey struct {
	tenant TenantID
	addr   VirtualAddr
}

type binding struct {
	spec     ServiceSpec
	handler  PacketHandler // nil for TCP listener bindings
	bpfKey   bpf.PodEgressVirtualServiceKey
	listener net.Listener // populated for TCP bindings
	isTCP    bool
}

// NewRegistry constructs a Registry over the supplied packet plane
// primitives. The caller retains ownership of all dependencies; the
// registry only reads/writes them, never closes them.
//
// netCtx scopes any background goroutines the registry starts on
// behalf of TCP listeners (per-VPC NIC drain in netstack). Pass the
// daemon's run-context.
func NewRegistry(netCtx context.Context, dispatcher *packetplane.Dispatcher, flow *packetplane.FlowTable, sender *packetplane.Sender, tap *packetplane.TAP, virtServiceMap *ebpf.Map, netstack NetstackFacade) Registry {
	return &registry{
		dispatcher: dispatcher,
		flowTable:  flow,
		sender:     sender,
		tap:        tap,
		bpfMap:     virtServiceMap,
		netstack:   netstack,
		netCtx:     netCtx,
		bindings:   map[bindingKey]*binding{},
	}
}

func (r *registry) RegisterUDPHandler(spec ServiceSpec, handler PacketHandler) (Unregister, error) {
	if handler == nil {
		return nil, errors.New("virtservice: handler must not be nil")
	}
	if spec.Addr.Proto != ProtocolUDP {
		return nil, fmt.Errorf("virtservice: RegisterUDPHandler requires UDP, got %d", spec.Addr.Proto)
	}
	if !spec.Addr.IP.Is4() {
		return nil, fmt.Errorf("virtservice: only IPv4 virtual addresses supported, got %s", spec.Addr.IP)
	}
	if len(spec.ServiceMAC) != 6 {
		return nil, fmt.Errorf("virtservice: ServiceMAC must be 6 bytes, got %d", len(spec.ServiceMAC))
	}

	key := bindingKey{tenant: spec.Tenant, addr: spec.Addr}

	r.mu.Lock()
	if _, ok := r.bindings[key]; ok {
		r.mu.Unlock()
		return nil, fmt.Errorf("virtservice: already registered for tenant=%+v addr=%+v", spec.Tenant, spec.Addr)
	}
	r.mu.Unlock()

	bpfKey := bpf.PodEgressVirtualServiceKey{
		SubnetId: spec.Tenant.SubnetID,
		DstIp:    networkOrderIP(spec.Addr.IP),
		DstPort:  htonsU16(spec.Addr.Port),
		Proto:    uint8(spec.Addr.Proto),
	}
	bpfVal := bpf.PodEgressVirtualServiceVal{
		ServiceId:  uint32(spec.ID),
		TapIfindex: uint32(r.tap.Ifindex()),
	}
	copy(bpfVal.ServiceMac[:], spec.ServiceMAC)

	if err := r.bpfMap.Update(&bpfKey, &bpfVal, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("virtservice: program virtual_service_map: %w", err)
	}

	dispatcherKey := packetplane.HandlerKey{
		SubnetID: spec.Tenant.SubnetID,
		DstIP:    spec.Addr.IP,
		DstPort:  spec.Addr.Port,
		Proto:    uint8(spec.Addr.Proto),
	}
	udpHandler := r.makeUDPDispatcherCallback(spec, handler)
	if err := r.dispatcher.RegisterUDP(dispatcherKey, udpHandler); err != nil {
		// Roll back BPF write so a half-registered binding doesn't
		// leave the classifier silently dropping traffic.
		_ = r.bpfMap.Delete(&bpfKey)
		return nil, fmt.Errorf("virtservice: register UDP handler: %w", err)
	}

	r.mu.Lock()
	r.bindings[key] = &binding{spec: spec, handler: handler, bpfKey: bpfKey}
	r.mu.Unlock()

	zap.S().Infof("virtservice: registered UDP service id=%d tenant=%+v addr=%s:%d", spec.ID, spec.Tenant, spec.Addr.IP, spec.Addr.Port)

	return func() error {
		return r.unregister(key)
	}, nil
}

func (r *registry) ListenTCP(spec ServiceSpec) (net.Listener, Unregister, error) {
	if spec.Addr.Proto != ProtocolTCP {
		return nil, nil, fmt.Errorf("virtservice: ListenTCP requires TCP, got %d", spec.Addr.Proto)
	}
	if !spec.Addr.IP.Is4() {
		return nil, nil, fmt.Errorf("virtservice: only IPv4 virtual addresses supported, got %s", spec.Addr.IP)
	}
	if len(spec.ServiceMAC) != 6 {
		return nil, nil, fmt.Errorf("virtservice: ServiceMAC must be 6 bytes, got %d", len(spec.ServiceMAC))
	}
	if r.netstack == nil {
		return nil, nil, errors.New("virtservice: netstack facade not configured")
	}

	key := bindingKey{tenant: spec.Tenant, addr: spec.Addr}

	r.mu.Lock()
	if _, ok := r.bindings[key]; ok {
		r.mu.Unlock()
		return nil, nil, fmt.Errorf("virtservice: already registered for tenant=%+v addr=%+v", spec.Tenant, spec.Addr)
	}
	r.mu.Unlock()

	// Bring up the gVisor NIC + add the VIP before BPF / dispatcher
	// programming, so a packet that arrives the moment we flip BPF
	// has a place to land.
	if err := r.netstack.EnsureNIC(r.netCtx, spec.Tenant.VPCID, spec.Addr.IP); err != nil {
		return nil, nil, fmt.Errorf("virtservice: ensure NIC for vpc %d: %w", spec.Tenant.VPCID, err)
	}
	listener, err := r.netstack.ListenTCP(spec.Tenant.VPCID, spec.Addr.IP, spec.Addr.Port)
	if err != nil {
		_ = r.netstack.RemoveVIP(spec.Tenant.VPCID, spec.Addr.IP)
		return nil, nil, fmt.Errorf("virtservice: ListenTCP on vpc %d: %w", spec.Tenant.VPCID, err)
	}

	bpfKey := bpf.PodEgressVirtualServiceKey{
		SubnetId: spec.Tenant.SubnetID,
		DstIp:    networkOrderIP(spec.Addr.IP),
		DstPort:  htonsU16(spec.Addr.Port),
		Proto:    uint8(spec.Addr.Proto),
	}
	bpfVal := bpf.PodEgressVirtualServiceVal{
		ServiceId:  uint32(spec.ID),
		TapIfindex: uint32(r.tap.Ifindex()),
	}
	copy(bpfVal.ServiceMac[:], spec.ServiceMAC)

	if err := r.bpfMap.Update(&bpfKey, &bpfVal, ebpf.UpdateAny); err != nil {
		_ = listener.Close()
		_ = r.netstack.RemoveVIP(spec.Tenant.VPCID, spec.Addr.IP)
		return nil, nil, fmt.Errorf("virtservice: program virtual_service_map: %w", err)
	}

	dispatcherKey := packetplane.HandlerKey{
		SubnetID: spec.Tenant.SubnetID,
		DstIP:    spec.Addr.IP,
		DstPort:  spec.Addr.Port,
		Proto:    uint8(spec.Addr.Proto),
	}
	tcpHandler := r.makeTCPDispatcherCallback(spec)
	if err := r.dispatcher.RegisterTCP(dispatcherKey, tcpHandler); err != nil {
		_ = r.bpfMap.Delete(&bpfKey)
		_ = listener.Close()
		_ = r.netstack.RemoveVIP(spec.Tenant.VPCID, spec.Addr.IP)
		return nil, nil, fmt.Errorf("virtservice: register TCP dispatcher: %w", err)
	}

	r.mu.Lock()
	r.bindings[key] = &binding{
		spec:     spec,
		bpfKey:   bpfKey,
		listener: listener,
		isTCP:    true,
	}
	r.mu.Unlock()

	zap.S().Infof("virtservice: listening TCP id=%d tenant=%+v addr=%s:%d", spec.ID, spec.Tenant, spec.Addr.IP, spec.Addr.Port)

	return listener, func() error {
		return r.unregister(key)
	}, nil
}

// makeTCPDispatcherCallback adapts the netstack injector into the
// dispatcher's TCP handler signature. The dispatcher hands us the
// raw IPv4 packet (no Ethernet header), exactly what gVisor wants.
func (r *registry) makeTCPDispatcherCallback(spec ServiceSpec) packetplane.TCPHandler {
	return func(_ context.Context, flow packetplane.Flow, ipPacket []byte) error {
		return r.netstack.Inject(spec.Tenant.VPCID, ipPacket, flow)
	}
}

func (r *registry) unregister(key bindingKey) error {
	r.mu.Lock()
	b, ok := r.bindings[key]
	if ok {
		delete(r.bindings, key)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}

	// Remove the dispatcher binding first so any in-flight TAP frame
	// for this VIP is dropped with "no handler" rather than getting
	// routed to a deleted handler.
	dispatcherKey := packetplane.HandlerKey{
		SubnetID: b.spec.Tenant.SubnetID,
		DstIP:    b.spec.Addr.IP,
		DstPort:  b.spec.Addr.Port,
		Proto:    uint8(b.spec.Addr.Proto),
	}
	if b.isTCP {
		r.dispatcher.UnregisterTCP(dispatcherKey)
	} else {
		r.dispatcher.UnregisterUDP(dispatcherKey)
	}

	if err := r.bpfMap.Delete(&b.bpfKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("virtservice: delete virtual_service_map: %w", err)
	}

	if b.isTCP {
		if b.listener != nil {
			_ = b.listener.Close()
		}
		if r.netstack != nil {
			if err := r.netstack.RemoveVIP(b.spec.Tenant.VPCID, b.spec.Addr.IP); err != nil {
				zap.S().Warnf("virtservice: remove VIP from netstack: %v", err)
			}
		}
	}
	return nil
}

// makeUDPDispatcherCallback adapts the public PacketHandler API into
// the dispatcher's internal callback shape, while constructing the
// per-flow Responder that handlers use to write their replies.
func (r *registry) makeUDPDispatcherCallback(spec ServiceSpec, handler PacketHandler) packetplane.UDPHandler {
	return func(ctx context.Context, flow packetplane.Flow, payload []byte) error {
		req := PacketRequest{
			Tenant:     spec.Tenant,
			Service:    spec.ID,
			Addr:       spec.Addr,
			ClientIP:   flow.ClientIP,
			ClientPort: flow.ClientPort,
			Payload:    payload,
		}
		resp := &udpResponder{flow: flow, sender: r.sender}
		return handler.HandlePacket(ctx, req, resp)
	}
}

// udpResponder builds a UDP/IPv4/Ethernet response off the flow
// metadata captured at request time and sends it via AF_PACKET on
// the Pod's host-side veth.
type udpResponder struct {
	flow   packetplane.Flow
	sender *packetplane.Sender
}

func (r *udpResponder) WriteResponse(payload []byte) error {
	frame, err := packetplane.BuildUDPResponse(r.flow, payload)
	if err != nil {
		return err
	}
	return r.sender.SendTo(r.flow.PodIfindex, r.flow.PodMAC, frame)
}

// htonsU16 swaps a uint16 to network byte order. Local helper so the
// registry doesn't reach into packetplane for what is essentially a
// boundary conversion.
func htonsU16(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

// networkOrderIP encodes an IPv4 netip.Addr as a host-uint32 whose
// in-memory representation matches BPF's __be32 (i.e. raw network
// byte order on a little-endian host). The bpf2go-generated struct
// uses uint32 for __be32 fields, so we need to write the same bytes
// the kernel would.
func networkOrderIP(a netip.Addr) uint32 {
	if !a.Is4() {
		return 0
	}
	b := a.As4()
	return binary.LittleEndian.Uint32(b[:])
}
