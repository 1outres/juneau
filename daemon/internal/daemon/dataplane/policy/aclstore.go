package policy

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"

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
// MaxRulesPerACL truncation policy.
type ACLStore struct {
	table        ruleTable
	meta         *ebpf.Map
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

func newACLStore(table ruleTable, meta *ebpf.Map, bumper Bumper) *ACLStore {
	return &ACLStore{
		table:        table,
		meta:         meta,
		invalidation: newInvalidator(aclLayer, bumper),
	}
}

// MaxRulesPerACL mirrors MAX_RULES_PER_ACL in maps.h. Callers that
// pre-validate rule counts should compare against this.
const MaxRulesPerACL = 16

// Apply writes (or rewrites) the rules + meta for one NetworkACL.
//
// Caller invariants:
//
//   - rs.Rules MUST be sorted by (direction, priority asc) so the BPF
//     evaluator can scan front-to-back and short-circuit on the first
//     match. ExpandNetworkACL produces this order.
//   - rs.GroupID is reused as the ACL identifier (acl_id), keyed into
//     acl_meta_map / acl_rule_table.
//
// If len(rs.Rules) exceeds MaxRulesPerACL, Apply truncates and returns
// ErrACLRuleLimitExceeded; the prefix that fit is still installed so
// traffic does not stall on a half-published ruleset.
func (s *ACLStore) Apply(rs RuleSet) error {
	if rs.GroupID == 0 {
		return fmt.Errorf("policy: cannot apply ACL RuleSet with id=0")
	}

	limitExceeded := false
	rules := rs.Rules
	if len(rules) > MaxRulesPerACL {
		rules = rules[:MaxRulesPerACL]
		limitExceeded = true
	}

	writeRules := func(inner *ebpf.Map) error {
		for i, r := range rules {
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
			key := uint32(i)
			if err := inner.Update(key, v, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("write acl %d rule %d: %w", rs.GroupID, i, err)
			}
		}
		return nil
	}

	writeMeta := func() error {
		meta := bpf.PodEgressAclMetaVal{
			IngressCount:   uint32(rs.IngressCount),
			EgressCount:    uint32(rs.EgressCount),
			RulesetVersion: rs.RulesetVersion,
		}
		if rs.HasIngressRules {
			meta.HasIngressRules = 1
		}
		if rs.HasEgressRules {
			meta.HasEgressRules = 1
		}
		return s.meta.Update(rs.GroupID, meta, ebpf.UpdateAny)
	}

	if err := s.table.Apply(rs.GroupID, writeRules, writeMeta); err != nil {
		return err
	}

	installed := rs
	installed.Rules = slices.Clone(rules)
	if err := s.invalidation.applied(rs.GroupID, installed); err != nil {
		return err
	}

	if limitExceeded {
		return ErrACLRuleLimitExceeded
	}
	return nil
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

// ErrACLRuleLimitExceeded mirrors ErrRuleLimitExceeded. Apply still
// wrote the prefix that fit; callers surface this as
// status.RulesValid=False.
var ErrACLRuleLimitExceeded = errors.New("policy: rule count exceeds MaxRulesPerACL")
