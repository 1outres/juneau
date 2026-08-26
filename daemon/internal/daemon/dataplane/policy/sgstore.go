package policy

import (
	"fmt"

	"github.com/cilium/ebpf"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// SGStore writes RuleSets into the SG-related BPF maps. It is the only
// thing in the daemon that pokes at sg_meta_map / sg_rule_table; every
// other reconciler treats the resolved RuleSet as opaque.
//
// SGStore delegates the inner-map create/swap/close dance to a Rotator
// so the same machinery is reused by ACLStore. SGStore itself only
// owns the SG-specific encoding (Rule → bpf.PodEgressSgRule) and the
// placement of each direction in its own window.
type SGStore struct {
	table        ruleTable
	meta         metaTable
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

func newSGStore(table ruleTable, meta metaTable, bumper Bumper) *SGStore {
	return &SGStore{
		table:        table,
		meta:         meta,
		invalidation: newInvalidator(sgLayer, bumper),
	}
}

// MaxSGEntriesPerDirection is how many expanded entries ONE direction
// of a SecurityGroup can hold, so sg_rules_inner_proto is twice this.
// It is lower than the NetworkACL budget because SG rules expand over
// peers as well as ports, and the evaluator scans every SG attached to
// the interface. See MaxACLEntriesPerDirection for where the number
// comes from.
const MaxSGEntriesPerDirection = juneauv1alpha1.SecurityGroupMaxEntriesPerDirection

// Apply writes (or rewrites) the rules + meta for one SG.
//
// A direction holding more than MaxSGEntriesPerDirection entries is
// installed fail-closed (see fitRuleSet) and reported as a
// *CapacityError. Those errors are returned only after the write, so
// the data plane is already consistent by the time a caller sees one.
func (s *SGStore) Apply(rs RuleSet) error {
	if rs.GroupID == 0 {
		return fmt.Errorf("policy: cannot apply RuleSet with GroupID=0")
	}

	installed, capacityErr := fitRuleSet(sgLayer, rs, MaxSGEntriesPerDirection)

	writeRules := func(inner ruleArray) error {
		for _, window := range installed.windows(MaxSGEntriesPerDirection) {
			for i, r := range window.Rules {
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
				slot := window.Base + uint32(i)
				if err := inner.Update(slot, v, ebpf.UpdateAny); err != nil {
					return fmt.Errorf("write sg %d %s rule %d: %w", rs.GroupID, window.Direction, i, err)
				}
			}
		}
		return nil
	}

	writeMeta := func() error {
		// sg_meta_val carries no has_ingress_rules flag and needs
		// none: SecurityGroup ingress is deny-by-default, so an
		// ingress count of 0 already denies the direction, whether
		// the user wrote no ingress rules or the direction was
		// installed fail-closed. Egress defaults to allow-all, so
		// only egress needs a flag to say "enforce a rule list".
		meta := bpf.PodEgressSgMetaVal{
			IngressCount:   uint32(len(installed.Ingress)),
			EgressCount:    uint32(len(installed.Egress)),
			RulesetVersion: uint32(installed.RulesetVersion),
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
