package ctstate

import "time"

// IPPROTO_* mirrored locally to avoid dragging in syscall just for a few
// constants. The eBPF data plane writes the IP header's protocol field
// straight into ct_key.proto.
const (
	ProtoICMP uint8 = 1
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
)

// TTLs control how long an entry may sit in ct_map without seeing fresh
// traffic before user-space GC drops it. With ct_map switched from LRU
// to a regular HASH (Phase 4b-3), the GC is the only mechanism that
// reaps idle flows.
const (
	TTLNew         = 120 * time.Second
	TTLEstablished = 1 * time.Hour
	TTLFinWait     = 60 * time.Second
	TTLUDP         = 60 * time.Second
	TTLICMP        = 30 * time.Second

	// TTLOther covers every protocol that has neither a state machine
	// nor a TTL of its own: GRE, ESP, AH, and any other protocol number
	// a policy rule may name. Their entries carry CT_STATE_ESTABLISHED,
	// so without this they would inherit the TCP hour.
	TTLOther = 120 * time.Second
)

// protoTTLs holds the idle timeout of every protocol that does not run
// the TCP state machine.
var protoTTLs = map[uint8]time.Duration{
	ProtoUDP:  TTLUDP,
	ProtoICMP: TTLICMP,
}

// ShouldEvict decides whether GC should drop an entry given its current
// state and the elapsed monotonic time since its last hit. CLOSED is
// always evicted: the eBPF side normally removes those inline, but we
// also catch any leftovers.
func ShouldEvict(state, proto uint8, lastSeenNs, nowNs uint64) bool {
	if state == StateClosed {
		return true
	}
	ttl, ok := entryTTL(state, proto)
	if !ok {
		return false
	}
	return elapsedNs(lastSeenNs, nowNs) > uint64(ttl.Nanoseconds())
}

// entryTTL returns how long an entry may idle. TCP is the only protocol
// the data plane tracks through a state machine, so it is the only one
// whose TTL depends on the state; every other protocol gets one flat
// timeout. ok is false for a TCP state with no TTL, which keeps the
// entry until the state moves on.
func entryTTL(state, proto uint8) (time.Duration, bool) {
	if proto != ProtoTCP {
		if ttl, ok := protoTTLs[proto]; ok {
			return ttl, true
		}
		return TTLOther, true
	}

	switch state {
	case StateNew:
		return TTLNew, true
	case StateEstablished:
		return TTLEstablished, true
	case StateFinWait:
		return TTLFinWait, true
	}
	return 0, false
}

// elapsedNs guards against clock skew where lastSeenNs ends up slightly
// ahead of now (the eBPF helper and clock_gettime both read CLOCK_MONO,
// but the GC may sample now before a packet's update lands). Treat any
// such case as "just now".
func elapsedNs(lastSeenNs, nowNs uint64) uint64 {
	if lastSeenNs >= nowNs {
		return 0
	}
	return nowNs - lastSeenNs
}
