// Package trace contains the daemon-side trace plumbing: BPF map
// programming, ringbuf decoding, and the in-process event bus that
// fans out events to subscribers (today: the debug gRPC server,
// tomorrow: future analyzers).
//
// The package owns no goroutines on construction — Start methods are
// explicit so the dataplane manager controls lifecycle. All public
// types are safe for concurrent use unless documented otherwise.
package trace

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Wire layout of struct juneau_trace_event from daemon/bpf/trace.h.
// Decoder lives in this file so bumps to the BPF struct are caught by
// a single failing test rather than rippling silent shifts through
// dispatch.
//
// Keep field offsets in lockstep with trace.h.

// EventBytes is the on-the-wire size of a single ringbuf record. The
// constant exists so tests can verify the BPF/userspace layouts agree
// without hard-coding the value at the call site.
const EventBytes = 4*6 + 8 + 4 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + 4 + 4 + 2 + 2 + 4 + 4

// Reason mirrors the TRACE_REASON_* constants in trace.h. Numbers are
// stable across releases — appending is fine, renumbering is not.
type Reason uint32

const (
	ReasonUnspecified Reason = 0

	ReasonEnterPodEgress    Reason = 100
	ReasonEnterPodIngress   Reason = 101
	ReasonEnterVxlanIngress Reason = 102
	ReasonEnterNodeIngress  Reason = 103

	ReasonMissIfindexSubnet Reason = 200
	ReasonMissSubnet        Reason = 201
	ReasonMissFIBTable      Reason = 202
	ReasonMissFIBRoute      Reason = 203
	ReasonMissARP           Reason = 204
	ReasonMissFDB           Reason = 205
	ReasonMissService       Reason = 206
	ReasonMissBackend       Reason = 207
	ReasonMissConntrack     Reason = 208

	ReasonPolicyACLPass Reason = 300
	ReasonPolicyACLDrop Reason = 301
	ReasonPolicySGPass  Reason = 302
	ReasonPolicySGDrop  Reason = 303

	ReasonServiceLookupHit       Reason = 400
	ReasonServiceBackendSelected Reason = 401
	ReasonDNATApplied            Reason = 402
	ReasonSNATApplied            Reason = 403
	ReasonNAPTAllocated          Reason = 404
	ReasonReverseNATApplied      Reason = 405

	ReasonRedirectIfindex Reason = 500
	ReasonRedirectVxlan   Reason = 501
	ReasonPassKernel      Reason = 502
	ReasonDropShot        Reason = 503
)

// Hook mirrors TRACE_HOOK_* in trace.h.
type Hook uint32

const (
	HookUnknown      Hook = 0
	HookPodEgress    Hook = 1
	HookPodIngress   Hook = 2
	HookVxlanIngress Hook = 3
	HookNodeIngress  Hook = 4
)

// Verdict mirrors TRACE_VERDICT_* in trace.h.
type Verdict uint8

const (
	VerdictOK       Verdict = 0
	VerdictDrop     Verdict = 1
	VerdictRedirect Verdict = 2
)

// Scope mirrors TRACE_SCOPE_* in trace.h.
type Scope uint8

const (
	ScopeHost Scope = 0
	ScopeVPC  Scope = 1
)

// Direction mirrors TRACE_DIR_* in trace.h: the authoritative leg a
// tuple (and every event resolved through it) belongs to.
type Direction uint8

const (
	DirUnspecified Direction = 0
	DirRequest     Direction = 1
	DirReply       Direction = 2
)

// TupleVal is the userspace mirror of struct trace_tuple_val. Layout
// matches the BPF side byte-for-byte (8 bytes): trace_id, direction,
// and 3 bytes of explicit padding so the kernel value size agrees.
type TupleVal struct {
	TraceID   uint32
	Direction uint8
	Pad       [3]uint8
}

// CaptureFlag mirrors TRACE_CAP_* in trace.h.
type CaptureFlag uint32

const (
	CapturePacketMeta CaptureFlag = 0x01
	CaptureMapMiss    CaptureFlag = 0x02
	CapturePolicy     CaptureFlag = 0x04
	CaptureNAT        CaptureFlag = 0x08
)

// CaptureLevel mirrors TRACE_LEVEL_* in trace.h.
type CaptureLevel uint8

const (
	LevelSummary  CaptureLevel = 0
	LevelDecision CaptureLevel = 1
	LevelVerbose  CaptureLevel = 2
)

// TupleKey is the userspace mirror of struct trace_tuple_key. Memory
// layout matches the BPF side byte-for-byte; see TupleKeyBytes for
// the marshalled size.
type TupleKey struct {
	Scope    Scope
	Protocol uint8
	VPCID    uint32
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16 // network byte order on the wire
	DstPort  uint16 // network byte order on the wire
}

// TupleKeyBytes is the marshalled key length. Asserted by tests.
const TupleKeyBytes = 1 + 1 + 2 + 4 + 4 + 4 + 2 + 2

// MarshalBinary returns the 20-byte tuple key as the BPF map sees it.
// The two reserved padding bytes after Protocol are zero so the kernel
// hash matches whatever userspace inserted.
func (k TupleKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, TupleKeyBytes)
	buf[0] = byte(k.Scope)
	buf[1] = k.Protocol
	// buf[2:4] is reserved padding; left zero.
	binary.NativeEndian.PutUint32(buf[4:8], k.VPCID)
	copy(buf[8:12], k.SrcIP[:])
	copy(buf[12:16], k.DstIP[:])
	// SrcPort / DstPort live on the wire in network byte order — the
	// BPF side stores raw __be16, so we mirror that here.
	binary.BigEndian.PutUint16(buf[16:18], k.SrcPort)
	binary.BigEndian.PutUint16(buf[18:20], k.DstPort)
	return buf, nil
}

// Event is the userspace decode of struct juneau_trace_event. All
// fields are populated in host byte order regardless of the wire
// representation; IPs are returned as net.IP for convenient
// formatting.
type Event struct {
	TraceID  uint32
	Reason   Reason
	Hook     Hook
	Ifindex  uint32
	VPCID    uint32
	SubnetID uint32
	// At is the local kernel monotonic timestamp from
	// bpf_ktime_get_ns. Operators compare At values within a single
	// node only; cross-node ordering uses receive time.
	At time.Duration

	Protocol  uint8
	Verdict   Verdict
	Scope     Scope
	Direction Direction

	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16

	// Aux tuple — populated for NAT before/after pairs, zeroed
	// otherwise.
	HasAux  bool
	AuxSrc  net.IP
	AuxDst  net.IP
	AuxSrcP uint16
	AuxDstP uint16

	Aux1 uint32
	Aux2 uint32

	// ReceivedAt is the wallclock time the daemon decoded this
	// record. Used for cross-node timeline merging when monotonic
	// timestamps cannot be compared.
	ReceivedAt time.Time
}

// DecodeEvent parses a single ringbuf record into an Event.
func DecodeEvent(b []byte) (Event, error) {
	if len(b) < EventBytes {
		return Event{}, fmt.Errorf("trace event: short read: %d < %d", len(b), EventBytes)
	}
	off := 0
	u32 := func() uint32 { v := binary.NativeEndian.Uint32(b[off : off+4]); off += 4; return v }
	be32 := func() uint32 { v := binary.BigEndian.Uint32(b[off : off+4]); off += 4; return v }
	be16 := func() uint16 { v := binary.BigEndian.Uint16(b[off : off+2]); off += 2; return v }
	u8 := func() uint8 { v := b[off]; off++; return v }
	u64 := func() uint64 { v := binary.NativeEndian.Uint64(b[off : off+8]); off += 8; return v }

	ev := Event{}
	ev.TraceID = u32()
	ev.Reason = Reason(u32())
	ev.Hook = Hook(u32())
	ev.Ifindex = u32()
	ev.VPCID = u32()
	ev.SubnetID = u32()
	ev.At = time.Duration(u64())
	src := be32()
	dst := be32()
	ev.SrcIP = ipFromBE(src)
	ev.DstIP = ipFromBE(dst)
	ev.SrcPort = be16()
	ev.DstPort = be16()
	ev.Protocol = u8()
	ev.Verdict = Verdict(u8())
	ev.Scope = Scope(u8())
	ev.Direction = Direction(u8())

	src2 := be32()
	dst2 := be32()
	sport2 := be16()
	dport2 := be16()
	if src2 != 0 || dst2 != 0 || sport2 != 0 || dport2 != 0 {
		ev.HasAux = true
		ev.AuxSrc = ipFromBE(src2)
		ev.AuxDst = ipFromBE(dst2)
		ev.AuxSrcP = sport2
		ev.AuxDstP = dport2
	}
	ev.Aux1 = u32()
	ev.Aux2 = u32()

	ev.ReceivedAt = time.Now()
	return ev, nil
}

func ipFromBE(b uint32) net.IP {
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, b)
	return out
}
