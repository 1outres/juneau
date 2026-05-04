package policy

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// SGStore writes RuleSets into the SG-related BPF maps. It is the only
// thing in the daemon that pokes at sg_meta_map / sg_rule_table; every
// other reconciler treats the resolved RuleSet as opaque.
//
// Each SG owns one inner array map (the per-SG rules). On update we
// build a fresh inner, swap it into the outer HASH_OF_MAPS, then close
// the old one — same pattern Fib uses for FIB inner maps. This keeps
// updates atomic from the data plane's point of view (the outer map
// always points at a fully-formed inner) and obviates incremental
// edits, which simplifies failure handling.
type SGStore struct {
	meta      *ebpf.Map
	rules     *ebpf.Map
	innerSpec *ebpf.MapSpec

	mu        sync.Mutex
	snapshots map[uint32]*ebpf.Map
}

// NewSGStore wraps the BPF maps owned by pod_egress.
//
// innerSpec is the spec of the per-SG rule array that the HASH_OF_MAPS
// hands out as values. The Store copies the spec on each create so the
// shared spec object is never mutated.
func NewSGStore(meta, rules *ebpf.Map, innerSpec *ebpf.MapSpec) *SGStore {
	return &SGStore{
		meta:      meta,
		rules:     rules,
		innerSpec: innerSpec,
		snapshots: make(map[uint32]*ebpf.Map),
	}
}

// MaxRulesPerSG mirrors MAX_RULES_PER_SG in maps.h. Callers that
// pre-validate rule counts should compare against this.
const MaxRulesPerSG = 8

// Apply writes (or rewrites) the rules + meta for one SG. If
// len(rs.Rules) exceeds MaxRulesPerSG, Apply truncates and returns
// ErrRuleLimitExceeded; the caller is responsible for surfacing this on
// status — we still write what fits so traffic does not see a stale
// ruleset.
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

	inner, err := ebpf.NewMap(s.innerSpec.Copy())
	if err != nil {
		return fmt.Errorf("create inner map for sg %d: %w", rs.GroupID, err)
	}
	// On any error before the swap completes, close the throwaway inner.
	committed := false
	defer func() {
		if !committed {
			_ = inner.Close()
		}
	}()

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

	if err := s.rules.Update(rs.GroupID, uint32(inner.FD()), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("install inner map for sg %d: %w", rs.GroupID, err)
	}

	// Meta last so anyone observing meta sees a consistent ruleset.
	meta := bpf.PodEgressSgMetaVal{
		IngressCount:   uint32(rs.IngressCount),
		EgressCount:    uint32(rs.EgressCount),
		RulesetVersion: uint32(rs.RulesetVersion),
	}
	if rs.HasEgressRules {
		meta.HasEgressRules = 1
	}
	if err := s.meta.Update(rs.GroupID, meta, ebpf.UpdateAny); err != nil {
		// Outer was already swapped; rolling back is impractical and
		// would itself be racy. We just log and continue: the next
		// reconcile will reconverge meta.
		zap.S().Warnf("policy: write sg meta %d: %v", rs.GroupID, err)
	}

	committed = true
	s.mu.Lock()
	old := s.snapshots[rs.GroupID]
	s.snapshots[rs.GroupID] = inner
	s.mu.Unlock()
	if old != nil {
		if err := old.Close(); err != nil {
			zap.S().Warnf("policy: close old inner sg %d: %v", rs.GroupID, err)
		}
	}

	if limitExceeded {
		return ErrRuleLimitExceeded
	}
	return nil
}

// Delete removes both the rule inner map handle and the meta entry.
// Idempotent.
func (s *SGStore) Delete(groupID uint32) error {
	if groupID == 0 {
		return nil
	}
	if err := s.rules.Delete(groupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete sg %d rules: %w", groupID, err)
	}
	if err := s.meta.Delete(groupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete sg %d meta: %w", groupID, err)
	}

	s.mu.Lock()
	old, hadOld := s.snapshots[groupID]
	delete(s.snapshots, groupID)
	s.mu.Unlock()
	if hadOld && old != nil {
		if err := old.Close(); err != nil {
			zap.S().Warnf("policy: close inner sg %d on delete: %v", groupID, err)
		}
	}
	return nil
}

// CloseAll releases every retained inner-map handle. Used by Manager on
// shutdown so we do not leak FDs when the program is reloaded.
func (s *SGStore) CloseAll() error {
	s.mu.Lock()
	snaps := s.snapshots
	s.snapshots = make(map[uint32]*ebpf.Map)
	s.mu.Unlock()

	var errs []error
	for _, m := range snaps {
		if m == nil {
			continue
		}
		if err := m.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ErrRuleLimitExceeded indicates the ruleset overflowed MaxRulesPerSG.
// Apply still wrote the prefix that fit, so traffic should not stall;
// callers should set Status.RulesValid=False and surface a clear reason.
var ErrRuleLimitExceeded = errors.New("policy: rule count exceeds MaxRulesPerSG")
