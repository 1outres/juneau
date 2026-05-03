package packetplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"

	"go.uber.org/zap"
)

// HandlerKey identifies a (TenantID, VirtualAddr) binding for the
// dispatcher's routing table. Mirrors the BPF virtual_service_map key
// but only the subset the dispatcher needs (subnet_id + IP + port +
// proto, all in host byte order so the table is human-readable).
type HandlerKey struct {
	SubnetID uint32
	DstIP    netip.Addr
	DstPort  uint16
	Proto    uint8
}

// UDPHandler is the dispatcher-facing callback for a single inbound
// UDP datagram. It receives the L4 payload (no headers) plus the
// flow metadata reconstructed from the BPF flow map; it must NOT
// retain payload past the call (the dispatcher reuses its read
// buffer).
type UDPHandler func(ctx context.Context, flow Flow, payload []byte) error

// TCPHandler is the dispatcher-facing callback for a single inbound
// TCP segment. Unlike UDP we hand over the *full* IPv4+TCP packet
// (no Ethernet header) because gVisor's netstack does its own
// IP-layer demux: it expects to be fed raw IPv4 bytes via
// channel.Endpoint.InjectInbound. payload is owned by the dispatcher
// and must be copied if retained past the call.
type TCPHandler func(ctx context.Context, flow Flow, ipPacket []byte) error

// Dispatcher reads frames from a TAP, parses Eth/IP/UDP, looks up
// (subnet, dst IP, dst port, proto) in its handler table, joins it
// with virtual_service_flow_map metadata, and invokes the registered
// handler. Handlers run synchronously on the dispatcher goroutine so
// expensive work (upstream DNS forwarding, etc.) should be offloaded
// to its own goroutine inside the handler.
//
// One Dispatcher serves one TAP. The intent is one TAP per node, so a
// single Dispatcher routes every virtual service.
type Dispatcher struct {
	tap       *TAP
	flowTable *FlowTable
	bufSize   int

	mu          sync.RWMutex
	handlers    map[HandlerKey]UDPHandler
	tcpHandlers map[HandlerKey]TCPHandler
}

// NewDispatcher returns a Dispatcher bound to tap and flow. bufSize is
// the per-read scratch buffer size and should be at least the TAP MTU
// + Ethernet header (1514 for the standard 1500 MTU). Pass 0 for the
// default.
func NewDispatcher(tap *TAP, flow *FlowTable, bufSize int) *Dispatcher {
	if bufSize <= 0 {
		bufSize = 65536
	}
	return &Dispatcher{
		tap:         tap,
		flowTable:   flow,
		bufSize:     bufSize,
		handlers:    map[HandlerKey]UDPHandler{},
		tcpHandlers: map[HandlerKey]TCPHandler{},
	}
}

// RegisterUDP installs handler for the given key. Returns an error if a
// handler is already bound to the same key (callers must Unregister
// first if they want to replace).
func (d *Dispatcher) RegisterUDP(key HandlerKey, handler UDPHandler) error {
	if handler == nil {
		return errors.New("packetplane: UDP handler must not be nil")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.handlers[key]; ok {
		return fmt.Errorf("packetplane: UDP handler already registered for %+v", key)
	}
	d.handlers[key] = handler
	return nil
}

// UnregisterUDP removes a previously-registered handler. Calling with
// no matching key is a no-op so callers can defer this safely.
func (d *Dispatcher) UnregisterUDP(key HandlerKey) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.handlers, key)
}

// RegisterTCP installs a TCP handler for the given key (subnet × VIP ×
// port × proto=TCP). Same uniqueness contract as RegisterUDP.
func (d *Dispatcher) RegisterTCP(key HandlerKey, handler TCPHandler) error {
	if handler == nil {
		return errors.New("packetplane: TCP handler must not be nil")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.tcpHandlers[key]; ok {
		return fmt.Errorf("packetplane: TCP handler already registered for %+v", key)
	}
	d.tcpHandlers[key] = handler
	return nil
}

// UnregisterTCP removes a TCP handler binding. Idempotent.
func (d *Dispatcher) UnregisterTCP(key HandlerKey) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.tcpHandlers, key)
}

// lookup is a small helper that returns the handler under RLock.
func (d *Dispatcher) lookup(key HandlerKey) (UDPHandler, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	h, ok := d.handlers[key]
	return h, ok
}

func (d *Dispatcher) lookupTCP(key HandlerKey) (TCPHandler, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	h, ok := d.tcpHandlers[key]
	return h, ok
}

// Run blocks reading frames from the TAP until ctx is cancelled or the
// TAP fd hits an unrecoverable error. Errors per-frame (parse failures,
// missing flow metadata, handler errors) are logged at debug level and
// otherwise swallowed so a single malformed packet cannot kill the
// dispatcher.
func (d *Dispatcher) Run(ctx context.Context) error {
	if d.tap == nil || d.tap.Fd() == nil {
		return errors.New("packetplane: dispatcher started without an open TAP")
	}

	buf := make([]byte, d.bufSize)
	fd := d.tap.Fd()

	// Wake the read goroutine when ctx is cancelled by closing the fd
	// — there is no portable Go way to interrupt a blocking read on a
	// netdev fd otherwise.
	go func() {
		<-ctx.Done()
		_ = fd.Close()
	}()

	for {
		n, err := fd.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			// Closed fd from the cancellation goroutine surfaces as
			// "use of closed file"; treat that as a clean exit.
			if errors.Is(err, errClosedFile) {
				return nil
			}
			// PathError wrapping ErrClosed
			if errors.Is(err, errClosed) {
				return nil
			}
			return fmt.Errorf("read TAP: %w", err)
		}
		if n == 0 {
			continue
		}

		d.handleFrame(ctx, buf[:n])
	}
}

// errClosed and errClosedFile capture the two error sentinels os.File
// surfaces when the underlying fd is closed under us. We compare via
// errors.Is in Run so Run can distinguish a clean shutdown from a
// real I/O failure.
var (
	errClosed     = io.ErrClosedPipe
	errClosedFile = errors.New("file already closed")
)

// handleFrame parses a single TAP frame and dispatches it. All errors
// are non-fatal; we log at debug to keep the data path quiet under
// adversarial Pod traffic.
func (d *Dispatcher) handleFrame(ctx context.Context, frame []byte) {
	if len(frame) < EthernetHeaderLen+IPv4HeaderLen {
		zap.S().Debugf("packetplane: short frame (%d bytes)", len(frame))
		return
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != EtherTypeIPv4 {
		// Non-IPv4 traffic should not reach here under normal
		// classifier rules, but log so misconfigurations show up.
		zap.S().Debugf("packetplane: dropping non-IPv4 frame ethertype=0x%04x", etherType)
		return
	}

	ip := frame[EthernetHeaderLen:]
	if len(ip) < IPv4HeaderLen {
		return
	}
	ihl := int(ip[0]&0x0F) * 4
	if ihl < IPv4HeaderLen || ihl > len(ip) {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl || totalLen > len(ip) {
		return
	}
	// BPF stamps the originating subnet_id into iph->id before
	// redirect (see handle_virtual_service in pod_egress.c). It's
	// the only TAP-readable identifier of tenant context, so flow
	// lookup MUST key on it — Pod IPs can overlap across VPCs and
	// scanning the flow map by 5-tuple alone would steer responses
	// to the wrong Pod under overlap.
	subnetID := uint32(binary.BigEndian.Uint16(ip[4:6]))

	proto := ip[9]
	srcIP := addrFromBytes(ip[12:16])
	dstIP := addrFromBytes(ip[16:20])

	switch proto {
	case 17: // UDP
		d.handleUDP(ctx, subnetID, ip[ihl:totalLen], srcIP, dstIP)
	case 6: // TCP
		d.handleTCP(ctx, subnetID, ip[:totalLen], ip[ihl:totalLen], srcIP, dstIP)
	default:
		zap.S().Debugf("packetplane: dropping unsupported proto %d", proto)
	}
}

func (d *Dispatcher) handleUDP(ctx context.Context, subnetID uint32, l4 []byte, srcIP, dstIP netip.Addr) {
	if len(l4) < UDPHeaderLen {
		return
	}
	srcPort := binary.BigEndian.Uint16(l4[0:2])
	dstPort := binary.BigEndian.Uint16(l4[2:4])
	udpLen := int(binary.BigEndian.Uint16(l4[4:6]))
	if udpLen < UDPHeaderLen || udpLen > len(l4) {
		return
	}
	payload := l4[UDPHeaderLen:udpLen]

	flow, ok, err := d.flowTable.Lookup(subnetID, srcIP, dstIP, srcPort, dstPort, 17)
	if err != nil {
		zap.S().Debugf("packetplane: UDP flow lookup error: %v", err)
		return
	}
	if !ok {
		// Stale packet (Pod's request hit the TAP after the LRU
		// evicted the flow, or before BPF committed it). Drop.
		zap.S().Debugf("packetplane: no flow metadata for UDP subnet=%d %s:%d -> %s:%d", subnetID, srcIP, srcPort, dstIP, dstPort)
		return
	}

	key := HandlerKey{
		SubnetID: subnetID,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Proto:    17,
	}
	handler, ok := d.lookup(key)
	if !ok {
		zap.S().Debugf("packetplane: no UDP handler for %+v", key)
		return
	}

	if err := handler(ctx, flow, payload); err != nil {
		zap.S().Warnf("packetplane: UDP handler error for %+v: %v", key, err)
	}
}

// handleTCP routes a TCP segment to the registered TCP handler. The
// handler receives the full IPv4 packet (header + TCP) because gVisor
// netstack expects to perform IP-layer demux itself; we only consume
// the L4 ports for handler-table lookup and flow correlation.
func (d *Dispatcher) handleTCP(ctx context.Context, subnetID uint32, ipPacket, l4 []byte, srcIP, dstIP netip.Addr) {
	if len(l4) < 20 {
		return
	}
	srcPort := binary.BigEndian.Uint16(l4[0:2])
	dstPort := binary.BigEndian.Uint16(l4[2:4])

	flow, ok, err := d.flowTable.Lookup(subnetID, srcIP, dstIP, srcPort, dstPort, 6)
	if err != nil {
		zap.S().Debugf("packetplane: TCP flow lookup error: %v", err)
		return
	}
	if !ok {
		zap.S().Debugf("packetplane: no flow metadata for TCP subnet=%d %s:%d -> %s:%d", subnetID, srcIP, srcPort, dstIP, dstPort)
		return
	}

	key := HandlerKey{
		SubnetID: subnetID,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Proto:    6,
	}
	handler, ok := d.lookupTCP(key)
	if !ok {
		zap.S().Debugf("packetplane: no TCP handler for %+v", key)
		return
	}
	if err := handler(ctx, flow, ipPacket); err != nil {
		zap.S().Warnf("packetplane: TCP handler error for %+v: %v", key, err)
	}
}
