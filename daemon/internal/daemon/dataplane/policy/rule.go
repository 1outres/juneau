// Package policy is the data-plane-side rule expansion + BPF projection
// for SecurityGroup (and, in future, NetworkACL). It deliberately knows
// nothing about the SecurityGroup CRD type — callers translate
// user-facing rules into the abstract Rule type below and hand the
// result to a Store implementation. This split keeps the BPF I/O code
// reusable across multiple resource kinds.
package policy

// Direction selects the side of a flow a rule applies to.
type Direction uint8

const (
	DirIngress Direction = 0
	DirEgress  Direction = 1
)

// PeerKind describes how a rule resolves the peer side of a flow.
type PeerKind uint8

const (
	PeerKindCIDR PeerKind = 0
	// PeerKindSG matches when the peer's NetworkInterface is a member of
	// the named SecurityGroup (resolved via sg_membership_map).
	PeerKindSG PeerKind = 1
)

// Verdict is the outcome of a successful match. v1 emits ALLOW only;
// DENY exists in the BPF layout to leave room for explicit deny rules.
type Verdict uint8

const (
	VerdictDeny  Verdict = 0
	VerdictAllow Verdict = 1
)

// Proto values mirror IP protocol numbers, with 0 used as "any".
const (
	ProtoAny  uint8 = 0
	ProtoICMP uint8 = 1
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
)

// PortAny is a sentinel range matching every L4 destination port.
const (
	PortAnyLo uint16 = 0
	PortAnyHi uint16 = 0xFFFF
)

// Rule is the flat, post-expansion form a Store consumes. One Rule maps
// to one slot in the BPF inner array.
//
// Fields are intentionally chosen to let the BPF writer copy values
// straight into the bpf2go-generated PodEgressSgRule struct.
type Rule struct {
	Direction Direction

	// Proto is an IP protocol number, or ProtoAny for protocol="all".
	Proto uint8

	// PortLo / PortHi specify an inclusive port range. Use
	// (PortAnyLo, PortAnyHi) for "any port".
	PortLo uint16
	PortHi uint16

	PeerKind PeerKind

	// For PeerKindCIDR: the CIDR base address (network byte order) and
	// prefix length. For PeerKindSG: PeerV4 carries the peer SG ID
	// (host byte order) and PeerPrefixlen is unused.
	PeerV4        uint32
	PeerPrefixlen uint8

	Verdict Verdict
}

// RuleSet is what one SecurityGroup expands into. Counts mirror the
// summary controllers project into status.
type RuleSet struct {
	GroupID uint32

	// Rules is a single flat slice covering both directions. Entries
	// where Direction=0 do NOT imply ingress: see Direction field.
	Rules []Rule

	IngressCount   int
	EgressCount    int
	HasEgressRules bool
	RulesetVersion uint64
}
