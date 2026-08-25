package policy

import (
	"fmt"

	"github.com/cilium/ebpf"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// ACLStore writes RuleSets into the NetworkACL-related BPF maps. It
// is the only thing in the daemon that pokes acl_meta_map /
// acl_rule_table directly; reconcilers treat the resolved RuleSet as
// opaque.
//
// Mirrors SGStore in structure: a Rotator drives the atomic
// rotate-and-swap of the per-ACL inner map; this type owns the
// ACL-specific encoding (Rule → bpf.PodEgressAclRule) plus the
// placement of each direction in its own window.
type ACLStore struct {
	table        ruleTable
	meta         metaTable
	invalidation *invalidator
}

// aclLayer labels the NetworkACL layer in logs and errors.
const aclLayer = "networkacl"

// NewACLStore wraps the ACL BPF maps owned by pod_egress.
//
// innerSpec is the spec of the per-ACL rule array. Rotator copies it
// per Apply so the shared object is never mutated.
//
// bumper is what tells the data plane to stop trusting the flows it
// admitted under the rules this store is about to replace.
func NewACLStore(meta, rules *ebpf.Map, innerSpec *ebpf.MapSpec, bumper Bumper) *ACLStore {
	return newACLStore(NewRotator(aclLayer, rules, meta, innerSpec), meta, bumper)
}

func newACLStore(table ruleTable, meta metaTable, bumper Bumper) *ACLStore {
	return &ACLStore{
		table:        table,
		meta:         meta,
		invalidation: newInvalidator(aclLayer, bumper),
	}
}

// MaxACLEntriesPerDirection is how many expanded entries ONE direction
// of a NetworkACL can hold, so acl_rules_inner_proto is twice this.
// It comes from the API contract because the webhook rejects specs
// above it and the controller reports the cost against it;
// TestRuleWindowsMatchTheCompiledMapSizes ties it to the compiled map.
const MaxACLEntriesPerDirection = juneauv1alpha1.NetworkACLMaxEntriesPerDirection

// Apply writes (or rewrites) the rules + meta for one NetworkACL.
//
// Caller invariants:
//
//   - each direction of rs MUST be sorted by priority asc so the BPF
//     evaluator can scan its window front-to-back and short-circuit on
//     the first match. ExpandNetworkACL produces this order.
//   - rs.GroupID is reused as the ACL identifier (acl_id), keyed into
//     acl_meta_map / acl_rule_table.
//
// A direction holding more than MaxACLEntriesPerDirection entries is
// installed fail-closed (see fitRuleSet) and reported as a
// *CapacityError. Those errors are returned only after the write, so
// the data plane is already consistent by the time a caller sees one.
func (s *ACLStore) Apply(rs RuleSet) error {
	if rs.GroupID == 0 {
		return fmt.Errorf("policy: cannot apply ACL RuleSet with id=0")
	}

	installed, capacityErr := fitRuleSet(aclLayer, rs, MaxACLEntriesPerDirection)

	writeRules := func(inner ruleArray) error {
		for _, window := range installed.windows(MaxACLEntriesPerDirection) {
			for i, r := range window.Rules {
				v := bpf.PodEgressAclRule{
					Direction: uint8(r.Direction),
					Proto:     r.Proto,
					PortLo:    r.PortLo,
					PortHi:    r.PortHi,
					Prefixlen: r.PeerPrefixlen,
					Verdict:   uint8(r.Verdict),
					Priority:  r.Priority,
					PeerV4:    r.PeerV4,
				}
				slot := window.Base + uint32(i)
				if err := inner.Update(slot, v, ebpf.UpdateAny); err != nil {
					return fmt.Errorf("write acl %d %s rule %d: %w", rs.GroupID, window.Direction, i, err)
				}
			}
		}
		return nil
	}

	writeMeta := func() error {
		meta := bpf.PodEgressAclMetaVal{
			IngressCount:   uint32(len(installed.Ingress)),
			EgressCount:    uint32(len(installed.Egress)),
			RulesetVersion: installed.RulesetVersion,
		}
		if installed.HasIngressRules {
			meta.HasIngressRules = 1
		}
		if installed.HasEgressRules {
			meta.HasEgressRules = 1
		}
		return s.meta.Update(rs.GroupID, meta, ebpf.UpdateAny)
	}

	if err := s.table.Apply(rs.GroupID, writeRules, writeMeta); err != nil {
		return err
	}

	if err := s.invalidation.applied(rs.GroupID, installed.clone()); err != nil {
		return err
	}

	return capacityErr
}

// Delete removes both the rule inner map handle and the meta entry.
// Idempotent.
func (s *ACLStore) Delete(aclID uint32) error {
	if err := s.table.Delete(aclID); err != nil {
		return err
	}
	return s.invalidation.deleted(aclID)
}

// CloseAll releases every retained inner-map handle. Used by Manager
// on shutdown.
func (s *ACLStore) CloseAll() error {
	return s.table.CloseAll()
}
