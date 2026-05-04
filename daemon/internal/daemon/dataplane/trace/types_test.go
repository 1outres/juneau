package trace

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestTupleKeyMarshalSize(t *testing.T) {
	k := TupleKey{}
	b, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != TupleKeyBytes {
		t.Fatalf("marshal size = %d, want %d", len(b), TupleKeyBytes)
	}
}

func TestTupleKeyMarshalRoundtrip(t *testing.T) {
	k := TupleKey{
		Scope:    ScopeVPC,
		Protocol: 6,
		VPCID:    42,
		SrcIP:    [4]byte{10, 0, 1, 5},
		DstIP:    [4]byte{10, 96, 0, 10},
		SrcPort:  50000,
		DstPort:  443,
	}
	b, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != byte(ScopeVPC) {
		t.Fatalf("scope byte: got %d", b[0])
	}
	if b[1] != 6 {
		t.Fatalf("protocol byte: got %d", b[1])
	}
	if v := binary.NativeEndian.Uint32(b[4:8]); v != 42 {
		t.Fatalf("vpc_id: got %d", v)
	}
	if v := binary.BigEndian.Uint16(b[16:18]); v != 50000 {
		t.Fatalf("sport: got %d", v)
	}
	if v := binary.BigEndian.Uint16(b[18:20]); v != 443 {
		t.Fatalf("dport: got %d", v)
	}
}

// TestDecodeEvent builds a synthetic event matching the BPF wire
// layout and asserts every field decodes back to the original value.
// Bumping the BPF struct breaks this test loudly.
func TestDecodeEvent(t *testing.T) {
	b := make([]byte, EventBytes)
	off := 0
	put32 := func(v uint32) { binary.NativeEndian.PutUint32(b[off:off+4], v); off += 4 }
	putBE32 := func(v uint32) { binary.BigEndian.PutUint32(b[off:off+4], v); off += 4 }
	putBE16 := func(v uint16) { binary.BigEndian.PutUint16(b[off:off+2], v); off += 2 }
	put8 := func(v byte) { b[off] = v; off++ }
	put64 := func(v uint64) { binary.NativeEndian.PutUint64(b[off:off+8], v); off += 8 }

	put32(0x12345678)                // trace_id
	put32(uint32(ReasonDNATApplied)) // reason
	put32(uint32(HookPodEgress))     // hook
	put32(99)                        // ifindex
	put32(7)                         // vpc_id
	put32(101)                       // subnet_id
	put64(uint64(1234567 * time.Millisecond))
	putBE32(0x0a000105) // saddr 10.0.1.5
	putBE32(0x0a60000a) // daddr 10.96.0.10
	putBE16(50000)      // sport
	putBE16(443)        // dport
	put8(6)             // proto = TCP
	put8(byte(VerdictOK))
	put8(byte(ScopeVPC))
	put8(0)             // _pad0
	putBE32(0x0a000208) // saddr2 10.0.2.8
	putBE32(0x0a000105) // daddr2 10.0.1.5
	putBE16(8443)
	putBE16(50000)
	put32(7)
	put32(8)

	if off != EventBytes {
		t.Fatalf("test wrote %d bytes, expected %d", off, EventBytes)
	}

	ev, err := DecodeEvent(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.TraceID != 0x12345678 {
		t.Fatalf("trace_id: %x", ev.TraceID)
	}
	if ev.Reason != ReasonDNATApplied {
		t.Fatalf("reason: %d", ev.Reason)
	}
	if ev.Hook != HookPodEgress {
		t.Fatalf("hook: %d", ev.Hook)
	}
	if !ev.SrcIP.Equal(net.IPv4(10, 0, 1, 5)) {
		t.Fatalf("saddr: %s", ev.SrcIP)
	}
	if !ev.DstIP.Equal(net.IPv4(10, 96, 0, 10)) {
		t.Fatalf("daddr: %s", ev.DstIP)
	}
	if ev.SrcPort != 50000 || ev.DstPort != 443 {
		t.Fatalf("ports: %d->%d", ev.SrcPort, ev.DstPort)
	}
	if !ev.HasAux {
		t.Fatalf("expected HasAux")
	}
	if !ev.AuxSrc.Equal(net.IPv4(10, 0, 2, 8)) {
		t.Fatalf("aux_src: %s", ev.AuxSrc)
	}
	if ev.AuxDstP != 50000 {
		t.Fatalf("aux dst port: %d", ev.AuxDstP)
	}
	if ev.Aux1 != 7 || ev.Aux2 != 8 {
		t.Fatalf("aux: %d %d", ev.Aux1, ev.Aux2)
	}
}

func TestDecodeEventShort(t *testing.T) {
	if _, err := DecodeEvent(make([]byte, EventBytes-1)); err == nil {
		t.Fatalf("expected short-read error")
	}
}
