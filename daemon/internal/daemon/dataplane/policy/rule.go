// Package policy is the data-plane-side rule expansion + BPF projection
// for SecurityGroup (and, in future, NetworkACL). It deliberately knows
// nothing about the SecurityGroup CRD type — callers translate
// user-facing rules into the abstract Rule type below and hand the
// result to a Store implementation. This split keeps the BPF I/O code
// reusable across multiple resource kinds.
package policy

import (
	"fmt"
	"slices"
)

// Direction selects the side of a flow a rule applies to.
type Direction uint8

const (
	DirIngress Direction = 0
	DirEgress  Direction = 1
)

func (d Direction) String() string {
	switch d {
	case DirIngress:
		return "ingress"
	case DirEgress:
		return "egress"
	default:
		return fmt.Sprintf("Direction(%d)", uint8(d))
	}
}

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

// Proto values mirror IP protocol numbers. Every value in 0..255 is a
// real protocol number, so the wildcard has to sit outside that range:
// ProtoAny is 0xFFFF, which keeps protocol number 0 (HOPOPT) usable as
// an ordinary rule.
const (
	ProtoAny  uint16 = 0xFFFF
	ProtoICMP uint16 = 1
	ProtoTCP  uint16 = 6
	ProtoUDP  uint16 = 17
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
// straight into the bpf2go-generated PodEgressSgRule / PodEgressAclRule
// structs. Layers that do not use a particular field (e.g. SG ignores
// Priority because it has no ordered semantics; ACL ignores PeerKind
// because peers are CIDR-only) leave it at the zero value, which the
// per-layer writer maps to the appropriate "wildcard" / "default"
// behaviour.
type Rule struct {
	Direction Direction

	// Proto is an IP protocol number, or ProtoAny for protocol="all".
	Proto uint16

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

	// Priority is meaningful only for ordered policy layers
	// (NetworkACL). SG ignores it. The ACL writer is responsible for
	// sorting rules by Priority before writing the inner array; lower
	// values evaluate first.
	Priority uint16
}

// RuleSet is the post-expansion form one policy resource (SG or ACL)
// flattens into.
//
// The directions are separate slices because the BPF rule array is
// split into two fixed windows, one per direction. Keeping them apart
// here is what makes it impossible for a full ingress list to push the
// egress rules out of the array, which is exactly what a shared slice
// plus a "sort ingress first" convention used to allow.
//
// Both layers reuse this struct; the per-layer Store reads only the
// fields its BPF meta map cares about (e.g. SGStore ignores
// HasIngressRules because SecurityGroup ingress is always
// deny-by-default, while ACLStore respects it because NetworkACL
// supports per-direction default-allow).
type RuleSet struct {
	// GroupID is the cluster-wide identifier for the resource: SG
	// GroupID for SecurityGroup, ACLID for NetworkACL. Both layers
	// reuse the same field so the Rotator-driven write path is
	// identical.
	GroupID uint32

	// Ingress and Egress each hold one direction's post-expansion
	// entries. For ordered layers (NetworkACL) each slice is sorted by
	// Priority asc so the BPF evaluator can scan that direction's
	// window front-to-back and short-circuit on first match.
	Ingress []Rule
	Egress  []Rule

	// HasIngressRules / HasEgressRules report whether the spec
	// declared the direction explicitly. They drive default-allow vs
	// default-deny behaviour at evaluation time.
	HasIngressRules bool
	HasEgressRules  bool

	RulesetVersion uint64
}

// ruleWindow is one direction's slice of a BPF inner rule array.
type ruleWindow struct {
	Direction Direction
	Base      uint32
	Rules     []Rule
}

// windows returns both direction windows in slot order. perDirection
// is the window size the layer's BPF array was built with: ingress
// occupies slots [0, perDirection), egress [perDirection,
// 2*perDirection).
func (rs RuleSet) windows(perDirection int) [2]ruleWindow {
	return [2]ruleWindow{
		{Direction: DirIngress, Base: 0, Rules: rs.Ingress},
		{Direction: DirEgress, Base: uint32(perDirection), Rules: rs.Egress},
	}
}

// clone detaches the rule slices from the caller, so a snapshot kept
// after Apply returns cannot be mutated behind its holder's back.
func (rs RuleSet) clone() RuleSet {
	rs.Ingress = slices.Clone(rs.Ingress)
	rs.Egress = slices.Clone(rs.Egress)
	return rs
}
