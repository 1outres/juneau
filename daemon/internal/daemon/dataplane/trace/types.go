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
	ReasonEnterL2Egress     Reason = 104
	ReasonEnterL2Ingress    Reason = 105
	ReasonEnterL2Gateway    Reason = 106

	ReasonMissIfindexSubnet Reason = 200
	ReasonMissSubnet        Reason = 201
	ReasonMissFIBTable      Reason = 202
	ReasonMissFIBRoute      Reason = 203
	ReasonMissARP           Reason = 204
	ReasonMissFDB           Reason = 205
	ReasonMissService       Reason = 206
	ReasonMissBackend       Reason = 207
	ReasonMissConntrack     Reason = 208
	ReasonMissTGWTable      Reason = 209
	ReasonMissTGWRoute      Reason = 210
	ReasonMissVpcEndpoint   Reason = 211
	ReasonMissL2Port        Reason = 212
	ReasonMissL2Network     Reason = 213
	ReasonMissL2FDB         Reason = 214
	ReasonMissL2ARP         Reason = 215
	ReasonMissL2Gateway     Reason = 216

	ReasonPolicyACLPass Reason = 300
	ReasonPolicyACLDrop Reason = 301
	ReasonPolicySGPass  Reason = 302
	ReasonPolicySGDrop  Reason = 303
	// ReasonPolicyParseDrop and ReasonPolicyEthertypeDrop mean the packet
	// was dropped without any rule rejecting it: the direction is policed
	// and the data plane could not read what it needed to judge the
	// packet — an unreadable L4 header for the first, a frame that is not
	// IPv4 for the second.
	ReasonPolicyParseDrop     Reason = 304
	ReasonPolicyEthertypeDrop Reason = 305

	ReasonServiceLookupHit       Reason = 400
	ReasonServiceBackendSelected Reason = 401
	ReasonDNATApplied            Reason = 402
	ReasonSNATApplied            Reason = 403
	ReasonNAPTAllocated          Reason = 404
	ReasonReverseNATApplied      Reason = 405
	// ReasonICMPErrorTranslated marks an ICMP error message whose
	// embedded copy of the original packet was rewritten alongside the
	// outer header. The tuple it reports is the flow the message is
	// about, not the ICMP message itself.
	ReasonICMPErrorTranslated Reason = 406

	ReasonRedirectIfindex Reason = 500
	ReasonRedirectVxlan   Reason = 501
	ReasonPassKernel      Reason = 502
	ReasonDropShot        Reason = 503
	ReasonDropBlackhole   Reason = 504

	// An L2Network has no addresses of its own, so "did it learn" and
	// "is it still flooding" are the only questions an operator can ask
	// about it. ReasonL2SplitHorizon marks a frame the overlay
	// delivered: it was copied to the local ports and deliberately not
	// sent back out.
	ReasonL2Learned      Reason = 600
	ReasonL2Flood        Reason = 601
	ReasonL2SplitHorizon Reason = 602
	// ReasonL2HairpinDrop marks a frame whose destination MAC sits on
	// the very port it came in on. A switch never sends one back out
	// there, and a workload with its own bridge behind the NIC would
	// send it straight back.
	ReasonL2HairpinDrop Reason = 603
	// ReasonL2GWLoopDrop marks a frame that has been handed to the
	// gateway port of a segment more times than juneau allows. The
	// kernel counts nothing on that path and bpf_redirect leaves the IP
	// TTL alone, so a routing loop through the gateway would run until
	// the machine stopped answering.
	ReasonL2GWLoopDrop Reason = 604
	// ReasonL2ArpAsked marks a packet the gateway could not address:
	// it put an ARP request for the destination on the segment and
	// dropped the packet, because BPF has nowhere to hold one until
	// the answer arrives. ReasonL2ArpHeld marks the same drop with no
	// request sent, because one went out for that address too
	// recently. The two look alike from outside and mean different
	// things: the first says the segment was asked and nobody
	// answered, the second says the asking is being paced.
	ReasonL2ArpAsked Reason = 605
	ReasonL2ArpHeld  Reason = 606
)

// Hook mirrors TRACE_HOOK_* in trace.h.
type Hook uint32

const (
	HookUnknown      Hook = 0
	HookPodEgress    Hook = 1
	HookPodIngress   Hook = 2
	HookVxlanIngress Hook = 3
	HookNodeIngress  Hook = 4
	HookL2Egress     Hook = 5
	HookL2Ingress    Hook = 6
	HookL2Gateway    Hook = 7
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

// flipDirection returns the opposite leg; Unspecified maps to itself.
// Mirrors trace_flip_dir, which used to live in the BPF datapath.
func flipDirection(d Direction) Direction {
	switch d {
	case DirRequest:
		return DirReply
	case DirReply:
		return DirRequest
	}
	return DirUnspecified
}

// isEnterReason reports whether r is one of the per-hook entry reasons
// (TRACE_REASON_ENTER_*). Enter events carry the packet's primary tuple
// with no aux tuple.
func isEnterReason(r Reason) bool {
	return r >= ReasonEnterPodEgress && r <= ReasonEnterNodeIngress
}

// reverseMirrorFromEvent derives the opposite-leg (reply) mirror tuple
// the BPF datapath used to auto-learn before the reverse-learn
// subprogram was removed to fit the 512-byte combined-stack ceiling. The
// daemon's ringbuf reader installs the returned tuple into
// trace_tuple_map so the return leg of a flow this node observed resolves
// the same trace_id. ok is false for events that seed no mirror.
//
// Two event classes seed a mirror, matching the two former BPF call
// sites:
//   - a NAT event (carrying a post-translation aux tuple) mirrors that
//     aux tuple with src/dst swapped, tagged the opposite of the event's
//     leg — this is the mirror kubectl cannot precompute (NAPT, SNAT);
//   - a Request-leg hook-entry event mirrors its primary tuple with
//     src/dst swapped, tagged Reply.
//
// Both wildcard the ports to 0 so the datapath's dport=0 second-chance
// lookup catches the reply's unknowable ephemeral port. The mirror is
// tagged authoritatively so rendering never infers the leg from address
// orientation.
func reverseMirrorFromEvent(ev Event) (TupleKey, Direction, bool) {
	var src, dst net.IP
	var dir Direction
	switch {
	case ev.HasAux:
		// NAT-class event: mirror the post-translation aux tuple.
		src, dst = ev.AuxDst, ev.AuxSrc
		dir = flipDirection(ev.Direction)
	case isEnterReason(ev.Reason) && ev.Direction == DirRequest:
		// A matched Reply's mirror is the Request tuple, already present,
		// so only Request-leg entries seed a mirror.
		src, dst = ev.DstIP, ev.SrcIP
		dir = DirReply
	default:
		return TupleKey{}, DirUnspecified, false
	}
	if dir == DirUnspecified {
		return TupleKey{}, DirUnspecified, false
	}
	sk, ok := ip4(src)
	if !ok {
		return TupleKey{}, DirUnspecified, false
	}
	dk, ok := ip4(dst)
	if !ok {
		return TupleKey{}, DirUnspecified, false
	}
	return TupleKey{
		Scope:    ev.Scope,
		Protocol: ev.Protocol,
		VPCID:    ev.VPCID,
		SrcIP:    sk,
		DstIP:    dk,
	}, dir, true
}

func ip4(ip net.IP) ([4]byte, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return [4]byte{}, false
	}
	var out [4]byte
	copy(out[:], v4)
	return out, true
}
