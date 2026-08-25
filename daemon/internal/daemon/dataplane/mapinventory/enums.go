package mapinventory

import (
	"fmt"
	"sort"
	"strings"
)

// EnumDict resolves a numeric to a label. Lookup misses fall back to
// a stringified hex form so kubectl always shows something. Constructed
// once at package init; treat values as immutable at runtime.
type EnumDict struct {
	// Name is a stable identifier ("ct_action", "fib_route_type").
	// Surfaced through schema.Type as "enum:<name>" so kubectl can
	// drive table formatting.
	Name string

	values map[uint64]string
}

// NewEnumDict builds a dictionary from a value→label map. Names with
// duplicate values are accepted (last wins) but the input map should
// not contain them in practice.
func NewEnumDict(name string, values map[uint64]string) *EnumDict {
	cp := make(map[uint64]string, len(values))
	for k, v := range values {
		cp[k] = v
	}
	return &EnumDict{Name: name, values: cp}
}

// Render returns the label for v, falling back to a hex encoding when
// no label is defined. Always returns a non-empty string.
func (d *EnumDict) Render(v uint64) string {
	if d == nil {
		return fmt.Sprintf("0x%x", v)
	}
	if name, ok := d.values[v]; ok {
		return name
	}
	return fmt.Sprintf("0x%x", v)
}

// FlagDict holds an ordered list of (bit, label) pairs. Render expands
// a bitmask into a list of labels in declaration order so output is
// stable across daemon restarts.
type FlagDict struct {
	Name string

	bits []flagBit
}

type flagBit struct {
	mask  uint64
	label string
}

// NewFlagDict builds a flag dictionary. Bits should be supplied in the
// order the user wants them rendered (typically ascending bit position).
func NewFlagDict(name string, bits []FlagBit) *FlagDict {
	cp := make([]flagBit, len(bits))
	for i, b := range bits {
		cp[i] = flagBit{mask: b.Mask, label: b.Label}
	}
	return &FlagDict{Name: name, bits: cp}
}

// FlagBit is the public input shape for NewFlagDict.
type FlagBit struct {
	Mask  uint64
	Label string
}

// Render expands v into the list of set labels. Unrepresented bits do
// not appear in the output; callers that need to surface unknown bits
// should also include the raw u64 value (proto: BPFMapField.u64).
func (d *FlagDict) Render(v uint64) []string {
	if d == nil || v == 0 {
		return nil
	}
	out := make([]string, 0, len(d.bits))
	for _, b := range d.bits {
		if v&b.mask == b.mask && b.mask != 0 {
			out = append(out, b.label)
		}
	}
	return out
}

// LabelOrder is exposed for tests / debug rendering: returns the
// per-bit labels in declaration order.
func (d *FlagDict) LabelOrder() []string {
	if d == nil {
		return nil
	}
	out := make([]string, len(d.bits))
	for i, b := range d.bits {
		out[i] = b.label
	}
	return out
}

// ----- Built-in dictionaries ---------------------------------------------
//
// These mirror the constants in daemon/bpf/maps.h. Keep them in sync
// when new constants are added — a registry-time test in
// register_test.go will catch drift in struct layout but cannot
// detect a stale enum entry.

// CTActionEnum maps ct_val.action → label. 9 is retired: it used to be
// CT_ACTION_POLICY_PASS, before policy admission moved to
// policy_ct_map. The label stays so old dumps still read, and the
// value must not be reused.
var CTActionEnum = NewEnumDict("ct_action", map[uint64]string{
	1: "CT_ACTION_DNAT",
	2: "CT_ACTION_SNAT",
	3: "CT_ACTION_NAPT_OUT",
	4: "CT_ACTION_NAPT_IN",
	5: "CT_ACTION_SVC_NAPT_OUT",
	6: "CT_ACTION_SVC_NAPT_IN",
	7: "CT_ACTION_SVC_SHARED_OUT",
	8: "CT_ACTION_SVC_SHARED_IN",
	9: "CT_ACTION_POLICY_PASS_RETIRED",
})

// PolicyHookEnum maps policy_ct_key.hook → label: the enforcement
// point that admitted the flow.
var PolicyHookEnum = NewEnumDict("policy_hook", map[uint64]string{
	1: "POLICY_HOOK_POD_EGRESS",
	2: "POLICY_HOOK_POD_INGRESS",
})

// CTStateEnum maps ct_val.state → label.
var CTStateEnum = NewEnumDict("ct_state", map[uint64]string{
	0: "CT_STATE_NEW",
	1: "CT_STATE_ESTABLISHED",
	2: "CT_STATE_FIN_WAIT",
	3: "CT_STATE_CLOSED",
})

// FIBRouteTypeEnum maps fib_val.type → label.
var FIBRouteTypeEnum = NewEnumDict("fib_route_type", map[uint64]string{
	1: "FIB_ROUTE_TYPE_CONNECTED",
	2: "FIB_ROUTE_TYPE_ENDPOINT",
	3: "FIB_ROUTE_TYPE_INTERNET_GATEWAY",
	4: "FIB_ROUTE_TYPE_SERVICE",
	6: "FIB_ROUTE_TYPE_NAPT",
	7: "FIB_ROUTE_TYPE_PEERING",
	8: "FIB_ROUTE_TYPE_TRANSIT",
	9: "FIB_ROUTE_TYPE_BLACKHOLE",
})

// BackendKindEnum maps backend_val.kind → label.
var BackendKindEnum = NewEnumDict("backend_kind", map[uint64]string{
	0: "BACKEND_KIND_POD",
	1: "BACKEND_KIND_HOST_REMOTE",
	2: "BACKEND_KIND_HOST_LOCAL",
})

// IPProtoEnum maps standard L4 protocol numbers to their canonical
// names. Used by maps that store iph->protocol verbatim.
var IPProtoEnum = NewEnumDict("ip_proto", map[uint64]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
})

// SGDirEnum maps sg_rule.direction → label.
var SGDirEnum = NewEnumDict("sg_dir", map[uint64]string{
	0: "SG_DIR_INGRESS",
	1: "SG_DIR_EGRESS",
})

// SGPeerKindEnum maps sg_rule.peer_kind → label.
var SGPeerKindEnum = NewEnumDict("sg_peer_kind", map[uint64]string{
	0: "SG_PEER_KIND_CIDR",
	1: "SG_PEER_KIND_SG",
})

// SGVerdictEnum maps sg_rule.verdict / acl_rule.verdict → label.
// SG and ACL share verdict semantics (DENY=0, ALLOW=1) but ACL adds
// VERDICT_PASS=2; keep them as one dictionary.
var ACLVerdictEnum = NewEnumDict("acl_verdict", map[uint64]string{
	0: "ACL_VERDICT_DENY",
	1: "ACL_VERDICT_ALLOW",
	2: "ACL_VERDICT_PASS",
})

var SGVerdictEnum = NewEnumDict("sg_verdict", map[uint64]string{
	0: "SG_VERDICT_DENY",
	1: "SG_VERDICT_ALLOW",
})

// ACLDirEnum maps acl_rule.direction → label.
var ACLDirEnum = NewEnumDict("acl_dir", map[uint64]string{
	0: "ACL_DIR_INGRESS",
	1: "ACL_DIR_EGRESS",
})

// CTScopeEnum mirrors the ct_key.scope semantics: 0 means "host
// keyspace" (NAPT inbound), any other value is the caller's vpc_id
// rendered as a number rather than a label. Render falls back to the
// hex form for non-zero scopes which is the desired behaviour.
var CTScopeEnum = NewEnumDict("ct_scope", map[uint64]string{
	0: "CT_SCOPE_HOST",
})

// SVCFlagDict expands service_val.flags. Keep order ascending by bit.
var SVCFlagDict = NewFlagDict("svc_flag", []FlagBit{
	{Mask: 1 << 0, Label: "SVC_FLAG_SHARED"},
	{Mask: 1 << 1, Label: "SVC_FLAG_HAS_ACL"},
	{Mask: 1 << 2, Label: "SVC_FLAG_AFFINITY_CLIENT_IP"},
	{Mask: 1 << 3, Label: "SVC_FLAG_INTERNAL_LOCAL"},
})

// VirtSvcFlagDict reserves the field even though no bits are defined
// yet. Keeping it in the registry means we can add bits without a
// schema-shape change.
var VirtSvcFlagDict = NewFlagDict("virtsvc_flag", []FlagBit{})

// DescribeBuiltins is exposed for `kubectl juneau bpf list` callers
// that want to render the available dictionaries (e.g. -o tree). Not
// shipped on the wire today; reserved for future use.
func DescribeBuiltins() string {
	enums := []*EnumDict{
		CTActionEnum, CTStateEnum, PolicyHookEnum, FIBRouteTypeEnum,
		BackendKindEnum, IPProtoEnum, SGDirEnum, SGPeerKindEnum,
		SGVerdictEnum, ACLDirEnum, ACLVerdictEnum, CTScopeEnum,
	}
	flagDicts := []*FlagDict{SVCFlagDict, VirtSvcFlagDict}

	var b strings.Builder
	for _, e := range enums {
		fmt.Fprintf(&b, "enum %s:\n", e.Name)
		keys := make([]uint64, 0, len(e.values))
		for k := range e.values {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, k := range keys {
			fmt.Fprintf(&b, "  %d -> %s\n", k, e.values[k])
		}
	}
	for _, fd := range flagDicts {
		fmt.Fprintf(&b, "flags %s:\n", fd.Name)
		for _, lab := range fd.LabelOrder() {
			fmt.Fprintf(&b, "  %s\n", lab)
		}
	}
	return b.String()
}
