package ctstate

import "time"

// IPPROTO_* mirrored locally to avoid dragging in syscall just for two
// constants. The eBPF data plane writes the IP header's protocol field
// straight into ct_key.proto.
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// IPPROTO_ICMP mirrored locally so ShouldEvict can apply ICMP-specific TTL.
const ProtoICMP uint8 = 1

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
)

// ShouldEvict decides whether GC should drop an entry given its current
// state and the elapsed monotonic time since its last hit. UDP and ICMP
// have no TCP state machine, so a single TTL applies regardless of state.
// CLOSED is always evicted: the eBPF side normally removes those inline,
// but we also catch any leftovers.
func ShouldEvict(state, proto uint8, lastSeenNs, nowNs uint64) bool {
	if state == StateClosed {
		return true
	}
	if proto == ProtoUDP {
		return elapsedNs(lastSeenNs, nowNs) > uint64(TTLUDP.Nanoseconds())
	}
	if proto == ProtoICMP {
		return elapsedNs(lastSeenNs, nowNs) > uint64(TTLICMP.Nanoseconds())
	}
	switch state {
	case StateNew:
		return elapsedNs(lastSeenNs, nowNs) > uint64(TTLNew.Nanoseconds())
	case StateEstablished:
		return elapsedNs(lastSeenNs, nowNs) > uint64(TTLEstablished.Nanoseconds())
	case StateFinWait:
		return elapsedNs(lastSeenNs, nowNs) > uint64(TTLFinWait.Nanoseconds())
	}
	return false
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
