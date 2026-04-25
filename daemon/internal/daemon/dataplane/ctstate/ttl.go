package ctstate

import "time"

// IPPROTO_* mirrored locally to avoid dragging in syscall just for two
// constants. The eBPF data plane writes the IP header's protocol field
// straight into ct_key.proto.
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// TTLs control how long an entry may sit in ct_map without seeing fresh
// traffic before user-space GC drops it. The eBPF hot path already
// removes entries it knows are CLOSED, so these timeouts only catch the
// stragglers (idle flows, half-open handshakes, half-closed FIN_WAIT).
const (
	TTLNew         = 30 * time.Second
	TTLEstablished = 5 * time.Minute
	TTLFinWait     = 60 * time.Second
	TTLUDP         = 30 * time.Second
)

// ShouldEvict decides whether GC should drop an entry given its current
// state and the elapsed monotonic time since its last hit. UDP has no
// state machine, so a single TTL applies regardless of state. CLOSED is
// always evicted: the eBPF side normally removes those inline, but we
// also catch any leftovers (e.g. half of a pair removed while the other
// race-survived).
func ShouldEvict(state, proto uint8, lastSeenNs, nowNs uint64) bool {
	if state == StateClosed {
		return true
	}
	if proto == ProtoUDP {
		return elapsedNs(lastSeenNs, nowNs) > uint64(TTLUDP.Nanoseconds())
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
