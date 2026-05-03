package packetplane

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"
)

// FlowKey selects a single virtual-service flow in BPF
// virtual_service_flow_map. Mirrors the C struct in daemon/bpf/maps.h
// byte-for-byte (subnet_id is host-order; IPs / ports are network
// byte order to match BPF's iph->saddr / iph->daddr / tcp.dest layout).
type FlowKey struct {
	SubnetID uint32
	SrcIP    [4]byte // network byte order
	DstIP    [4]byte
	SrcPort  uint16 // network byte order
	DstPort  uint16
	Proto    uint8
	// Pad must be exported: cilium/ebpf decodes via encoding/binary's
	// reflection path, which panics on unexported fields.
	Pad [3]byte
}

// FlowVal mirrors virtual_service_flow_val. Only the fields the
// userspace dispatcher needs to build the response are exported in
// the higher-level Flow type below.
type FlowVal struct {
	VPCID      uint32
	ServiceID  uint32
	PodIfindex uint32
	PodMAC     [6]byte
	ServiceMAC [6]byte
	// Pad mirrors the C struct's explicit 2-byte padding.
	Pad [2]byte
	// AlignPad is the implicit 6-byte tail padding the C compiler
	// inserts so LastSeenNS lands on an 8-byte boundary. Without it,
	// our struct is 34 bytes but the BPF map value is 40, and
	// cilium/ebpf reports "doesn't consume all data".
	AlignPad [6]byte
	// All padding fields must be exported because cilium/ebpf decodes
	// via encoding/binary's reflection path, which panics on unexported
	// fields.
	LastSeenNS uint64
}

// Flow is the dispatcher-friendly view of a single flow_map entry.
// IP / port fields use Go-native types so handlers don't see byte
// arrays at the boundary.
type Flow struct {
	SubnetID    uint32
	VPCID       uint32
	ServiceID   uint32
	ClientIP    netip.Addr
	ClientPort  uint16
	ServiceIP   netip.Addr
	ServicePort uint16
	Proto       uint8
	PodIfindex  int
	PodMAC      net.HardwareAddr
	ServiceMAC  net.HardwareAddr
}

// FlowTable wraps the BPF flow map with a typed Lookup that returns
// dispatcher-friendly values. The wrapper is intentionally thin —
// it never caches, so handlers always observe the latest BPF state
// and stale entries cleaned up by the LRU map automatically.
type FlowTable struct {
	m *ebpf.Map
}

// NewFlowTable adopts the supplied BPF map (the daemon's
// virtual_service_flow_map handle) and returns a typed wrapper.
func NewFlowTable(m *ebpf.Map) *FlowTable { return &FlowTable{m: m} }

// Lookup fetches the flow metadata for the given Pod-side 5-tuple +
// subnet. Returns (Flow, true, nil) on hit, (zero, false, nil) when
// the entry is absent (likely raced — UDP packet arrived before the
// BPF map update committed; caller should drop), or an error for any
// other syscall failure.
func (t *FlowTable) Lookup(subnetID uint32, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, proto uint8) (Flow, bool, error) {
	if t == nil || t.m == nil {
		return Flow{}, false, errors.New("packetplane: flow table is nil")
	}
	if !srcIP.Is4() || !dstIP.Is4() {
		return Flow{}, false, fmt.Errorf("packetplane: only IPv4 flows supported (src=%s, dst=%s)", srcIP, dstIP)
	}

	key := FlowKey{
		SubnetID: subnetID,
		SrcIP:    srcIP.As4(),
		DstIP:    dstIP.As4(),
		SrcPort:  htons(srcPort),
		DstPort:  htons(dstPort),
		Proto:    proto,
	}

	var val FlowVal
	if err := t.m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Flow{}, false, nil
		}
		return Flow{}, false, fmt.Errorf("flow lookup: %w", err)
	}

	return Flow{
		SubnetID:    subnetID,
		VPCID:       val.VPCID,
		ServiceID:   val.ServiceID,
		ClientIP:    srcIP,
		ClientPort:  srcPort,
		ServiceIP:   dstIP,
		ServicePort: dstPort,
		Proto:       proto,
		PodIfindex:  int(val.PodIfindex),
		PodMAC:      append(net.HardwareAddr(nil), val.PodMAC[:]...),
		ServiceMAC:  append(net.HardwareAddr(nil), val.ServiceMAC[:]...),
	}, true, nil
}

// Touch refreshes last_seen_ns on the supplied flow without changing
// its other fields. Useful for long-lived UDP "flows" where the
// daemon-side handler needs to extend the LRU lifetime around the
// response. Best-effort: a stale flow that has been evicted between
// Lookup and Touch is silently ignored.
func (t *FlowTable) Touch(subnetID uint32, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, proto uint8, nowNS uint64) error {
	key := FlowKey{
		SubnetID: subnetID,
		SrcIP:    srcIP.As4(),
		DstIP:    dstIP.As4(),
		SrcPort:  htons(srcPort),
		DstPort:  htons(dstPort),
		Proto:    proto,
	}
	var val FlowVal
	if err := t.m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	val.LastSeenNS = nowNS
	if err := t.m.Update(&key, &val, ebpf.UpdateExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	return nil
}
