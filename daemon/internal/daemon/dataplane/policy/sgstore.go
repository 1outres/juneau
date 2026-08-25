package policy

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// SGStore writes RuleSets into the SG-related BPF maps. It is the only
// thing in the daemon that pokes at sg_meta_map / sg_rule_table; every
// other reconciler treats the resolved RuleSet as opaque.
//
// SGStore delegates the inner-map create/swap/close dance to a Rotator
// so the same machinery is reused by ACLStore. SGStore itself only
// owns the SG-specific encoding (Rule → bpf.PodEgressSgRule) and the
// MaxRulesPerSG truncation policy.
type SGStore struct {
	table        ruleTable
	meta         *ebpf.Map
	invalidation *invalidator
}

// sgLayer labels the SecurityGroup layer in logs and errors.
const sgLayer = "securitygroup"

// NewSGStore wraps the BPF maps owned by pod_egress.
//
// innerSpec is the spec of the per-SG rule array that the
// HASH_OF_MAPS hands out as values. Rotator copies it on each Apply
// so the shared object is never mutated.
//
// bumper is what tells the data plane to stop trusting the flows it
// admitted under the rules this store is about to replace.
func NewSGStore(meta, rules *ebpf.Map, innerSpec *ebpf.MapSpec, bumper Bumper) *SGStore {
	return newSGStore(NewRotator(sgLayer, rules, meta, innerSpec), meta, bumper)
}

func newSGStore(table ruleTable, meta *ebpf.Map, bumper Bumper) *SGStore {
	return &SGStore{
		table:        table,
		meta:         meta,
		invalidation: newInvalidator(sgLayer, bumper),
	}
}

// MaxRulesPerSG mirrors MAX_RULES_PER_SG in maps.h. Callers that
// pre-validate rule counts should compare against this constant.
const MaxRulesPerSG = 8

// Apply writes (or rewrites) the rules + meta for one SG. If
// len(rs.Rules) exceeds MaxRulesPerSG, Apply truncates and returns
// ErrRuleLimitExceeded; the prefix that fit is still installed so
// traffic does not stall on a half-published ruleset.
func (s *SGStore) Apply(rs RuleSet) error {
	if rs.GroupID == 0 {
		return fmt.Errorf("policy: cannot apply RuleSet with GroupID=0")
	}

	limitExceeded := false
	rules := rs.Rules
	if len(rules) > MaxRulesPerSG {
		rules = rules[:MaxRulesPerSG]
		limitExceeded = true
	}

	writeRules := func(inner *ebpf.Map) error {
		for i, r := range rules {
			v := bpf.PodEgressSgRule{
				Direction:     uint8(r.Direction),
				Proto:         r.Proto,
				PortLo:        r.PortLo,
				PortHi:        r.PortHi,
				PeerKind:      uint8(r.PeerKind),
				PeerPrefixlen: r.PeerPrefixlen,
				PeerV4:        r.PeerV4,
				Verdict:       uint8(r.Verdict),
			}
			key := uint32(i)
			if err := inner.Update(key, v, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("write sg %d rule %d: %w", rs.GroupID, i, err)
			}
		}
		return nil
	}

	writeMeta := func() error {
		meta := bpf.PodEgressSgMetaVal{
			IngressCount:   uint32(rs.IngressCount),
			EgressCount:    uint32(rs.EgressCount),
			RulesetVersion: uint32(rs.RulesetVersion),
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
		return ErrRuleLimitExceeded
	}
	return nil
}

// Delete removes both the rule inner map handle and the meta entry.
// Idempotent.
func (s *SGStore) Delete(groupID uint32) error {
	if err := s.table.Delete(groupID); err != nil {
		return err
	}
	return s.invalidation.deleted(groupID)
}

// CloseAll releases every retained inner-map handle. Used by Manager
// on shutdown.
func (s *SGStore) CloseAll() error {
	return s.table.CloseAll()
}

// ErrRuleLimitExceeded indicates the ruleset overflowed MaxRulesPerSG.
// Apply still wrote the prefix that fit, so traffic should not stall;
// callers should set Status.RulesValid=False and surface a clear reason.
var ErrRuleLimitExceeded = errors.New("policy: rule count exceeds MaxRulesPerSG")
