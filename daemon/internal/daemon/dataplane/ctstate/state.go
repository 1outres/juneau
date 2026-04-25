// Package ctstate mirrors the conntrack TCP state machine implemented in
// daemon/bpf/ct.h. The eBPF data plane writes ct_val.state on every
// packet; user-space GC and tests read those values, so the constants and
// transition logic must agree with the kernel-side definitions.
package ctstate

const (
	StateNew         uint8 = 0
	StateEstablished uint8 = 1
	StateFinWait     uint8 = 2
	StateClosed      uint8 = 3
)

const (
	FlagFin uint8 = 0x01
	FlagSyn uint8 = 0x02
	FlagRst uint8 = 0x04
	FlagAck uint8 = 0x10
)

// DeriveNextState advances cur given the TCP flags observed on a single
// packet. RST forces an immediate CLOSED so that the caller drops both
// directions of the flow. FIN walks NEW/ESTABLISHED → FIN_WAIT once, and
// FIN_WAIT → CLOSED on the second FIN (either side closing). A pure ACK
// from NEW promotes to ESTABLISHED; SYN+ACK is treated the same way
// because the ACK bit is what indicates handshake progress.
func DeriveNextState(cur, flags uint8) uint8 {
	if flags&FlagRst != 0 {
		return StateClosed
	}
	if flags&FlagFin != 0 {
		if cur == StateFinWait {
			return StateClosed
		}
		return StateFinWait
	}
	if cur == StateNew && flags&FlagAck != 0 {
		return StateEstablished
	}
	return cur
}

// InitialStateForSYN picks the starting state when handle_service installs
// a fresh CT entry. A SYN means we caught the flow at its open and should
// require a handshake completion before promoting to ESTABLISHED. Without
// a SYN we assume the entry was created mid-flow and skip directly to
// ESTABLISHED so it does not languish in NEW until GC reaps it.
func InitialStateForSYN(flags uint8) uint8 {
	if flags&FlagSyn != 0 {
		return StateNew
	}
	return StateEstablished
}
