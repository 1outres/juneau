package policy

import (
	"errors"
	"testing"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// ruleStore is the part of SGStore and ACLStore this file exercises.
// Both layers must place rules and invalidate flows on the same
// rules, so they run the same suite.
type ruleStore interface {
	Apply(rs RuleSet) error
	Delete(id uint32) error
}

// installedRule is a layer-agnostic view of one written slot, so the
// shared suite can assert slot placement for both layers.
type installedRule struct {
	Direction Direction
	PortLo    uint16
	PortHi    uint16
	Verdict   Verdict
}

// installedMeta is a layer-agnostic view of a published meta value.
type installedMeta struct {
	IngressCount    uint32
	EgressCount     uint32
	HasIngressRules bool
	HasEgressRules  bool
}

type ruleStoreCase struct {
	// name doubles as the layer label a CapacityError carries.
	name string
	// limit is the window size of ONE direction.
	limit int
	// hasIngressFlag says whether the layer's meta value carries a
	// has_ingress_rules field. SecurityGroup's does not and needs
	// none: SG ingress defaults to DENY, so an ingress window with
	// zero entries already denies.
	hasIngressFlag bool
	build          func(table ruleTable, meta metaTable, bumper Bumper) ruleStore
	decodeRule     func(value any) installedRule
	decodeMeta     func(value any) installedMeta
}

func ruleStoreCases() []ruleStoreCase {
	return []ruleStoreCase{
		{
			name:           sgLayer,
			limit:          MaxSGEntriesPerDirection,
			hasIngressFlag: false,
			build: func(table ruleTable, meta metaTable, bumper Bumper) ruleStore {
				return newSGStore(table, meta, bumper)
			},
			decodeRule: func(value any) installedRule {
				r := value.(bpf.PodEgressSgRule)
				return installedRule{
					Direction: Direction(r.Direction),
					PortLo:    r.PortLo,
					PortHi:    r.PortHi,
					Verdict:   Verdict(r.Verdict),
				}
			},
			decodeMeta: func(value any) installedMeta {
				m := value.(bpf.PodEgressSgMetaVal)
				return installedMeta{
					IngressCount:   m.IngressCount,
					EgressCount:    m.EgressCount,
					HasEgressRules: m.HasEgressRules != 0,
				}
			},
		},
		{
			name:           aclLayer,
			limit:          MaxACLEntriesPerDirection,
			hasIngressFlag: true,
			build: func(table ruleTable, meta metaTable, bumper Bumper) ruleStore {
				return newACLStore(table, meta, bumper)
			},
			decodeRule: func(value any) installedRule {
				r := value.(bpf.PodEgressAclRule)
				return installedRule{
					Direction: Direction(r.Direction),
					PortLo:    r.PortLo,
					PortHi:    r.PortHi,
					Verdict:   Verdict(r.Verdict),
				}
			},
			decodeMeta: func(value any) installedMeta {
				m := value.(bpf.PodEgressAclMetaVal)
				return installedMeta{
					IngressCount:    m.IngressCount,
					EgressCount:     m.EgressCount,
					HasIngressRules: m.HasIngressRules != 0,
					HasEgressRules:  m.HasEgressRules != 0,
				}
			},
		},
	}
}

const testGroupID uint32 = 7

func testRule(dir Direction, port uint16) Rule {
	return Rule{
		Direction: dir,
		Proto:     ProtoTCP,
		PortLo:    port,
		PortHi:    port,
		PeerKind:  PeerKindCIDR,
		Verdict:   VerdictAllow,
	}
}

// nRules builds n distinct rules for one direction. The port bases
// differ per direction so a misplaced rule is obvious in a failure
// message.
func nRules(dir Direction, n int) []Rule {
	base := uint16(1000)
	if dir == DirEgress {
		base = 2000
	}
	out := make([]Rule, 0, n)
	for i := range n {
		out = append(out, testRule(dir, base+uint16(i)))
	}
	return out
}

func testRuleSet(ingress, egress []Rule) RuleSet {
	return RuleSet{
		GroupID:         testGroupID,
		Ingress:         ingress,
		Egress:          egress,
		HasIngressRules: len(ingress) > 0,
		HasEgressRules:  len(egress) > 0,
	}
}

type ruleStoreHarness struct {
	c      ruleStoreCase
	store  ruleStore
	table  *fakeRuleTable
	meta   *fakeMetaTable
	bumper *fakeBumper
}

// slotRule returns the rule the latest Apply wrote at slot, or
// ok=false when that slot was left empty.
func (h *ruleStoreHarness) slotRule(slot uint32) (installedRule, bool) {
	if h.table.inner == nil {
		return installedRule{}, false
	}
	value, ok := h.table.inner.slots[slot]
	if !ok {
		return installedRule{}, false
	}
	return h.c.decodeRule(value), true
}

func (h *ruleStoreHarness) slotCount() int {
	if h.table.inner == nil {
		return 0
	}
	return len(h.table.inner.slots)
}

func (h *ruleStoreHarness) installedMeta(t *testing.T) installedMeta {
	t.Helper()
	value, ok := h.meta.values[testGroupID]
	if !ok {
		t.Fatalf("no meta published for id %d", testGroupID)
	}
	return h.c.decodeMeta(value)
}

func (h *ruleStoreHarness) wantSlot(t *testing.T, slot uint32, want Rule) {
	t.Helper()
	got, ok := h.slotRule(slot)
	if !ok {
		t.Fatalf("slot %d is empty, want %s port %d", slot, want.Direction, want.PortLo)
	}
	if got.Direction != want.Direction || got.PortLo != want.PortLo || got.PortHi != want.PortHi || got.Verdict != want.Verdict {
		t.Errorf("slot %d = %+v, want %s port %d verdict %d", slot, got, want.Direction, want.PortLo, want.Verdict)
	}
}

func (h *ruleStoreHarness) wantEmptyWindow(t *testing.T, dir Direction) {
	t.Helper()
	base := uint32(0)
	if dir == DirEgress {
		base = uint32(h.c.limit)
	}
	for i := range h.c.limit {
		if got, ok := h.slotRule(base + uint32(i)); ok {
			t.Errorf("%s slot %d holds %+v, want the window installed empty", dir, base+uint32(i), got)
		}
	}
}

func eachRuleStore(t *testing.T, run func(t *testing.T, h *ruleStoreHarness)) {
	t.Helper()
	for _, c := range ruleStoreCases() {
		t.Run(c.name, func(t *testing.T) {
			table := &fakeRuleTable{}
			meta := newFakeMetaTable()
			bumper := &fakeBumper{}
			run(t, &ruleStoreHarness{
				c:      c,
				store:  c.build(table, meta, bumper),
				table:  table,
				meta:   meta,
				bumper: bumper,
			})
		})
	}
}

func wantCapacityErrors(t *testing.T, err error, want ...CapacityError) {
	t.Helper()
	got := CapacityErrorsFrom(err)
	if len(got) != len(want) {
		t.Fatalf("Apply error = %v, want %d capacity errors, got %d", err, len(want), len(got))
	}
	for i := range want {
		if *got[i] != want[i] {
			t.Errorf("capacity error %d = %+v, want %+v", i, *got[i], want[i])
		}
	}
	// Callers outside this package reach the detail through errors.As,
	// so joining must not hide it.
	var first *CapacityError
	if !errors.As(err, &first) {
		t.Errorf("errors.As(%v, *CapacityError) = false", err)
	}
}

// Filling one direction to its limit must not cost the other
// direction a single entry. Before the windows existed, a full
// ingress list pushed every egress rule out of the shared array and
// the whole egress direction blackholed (issue #52).
func TestRuleStoreApplyInstallsBothDirectionsWhenBothAreAtTheLimit(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		limit := h.c.limit
		rs := testRuleSet(nRules(DirIngress, limit), nRules(DirEgress, limit))

		if err := h.store.Apply(rs); err != nil {
			t.Fatalf("Apply: %v", err)
		}

		for i := range limit {
			h.wantSlot(t, uint32(i), rs.Ingress[i])
			h.wantSlot(t, uint32(limit+i), rs.Egress[i])
		}
		if got := h.slotCount(); got != 2*limit {
			t.Errorf("installed slots = %d, want %d", got, 2*limit)
		}

		meta := h.installedMeta(t)
		if meta.IngressCount != uint32(limit) || meta.EgressCount != uint32(limit) {
			t.Errorf("meta counts = %d/%d, want %d/%d", meta.IngressCount, meta.EgressCount, limit, limit)
		}
	})
}

func TestRuleStoreApplyFailsClosedOnlyForTheOverflowingIngress(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		limit := h.c.limit
		rs := testRuleSet(nRules(DirIngress, limit+1), nRules(DirEgress, limit))

		err := h.store.Apply(rs)
		wantCapacityErrors(t, err, CapacityError{
			Layer:     h.c.name,
			ID:        testGroupID,
			Direction: DirIngress,
			Entries:   limit + 1,
			Limit:     limit,
		})

		h.wantEmptyWindow(t, DirIngress)
		for i := range limit {
			h.wantSlot(t, uint32(limit+i), rs.Egress[i])
		}

		meta := h.installedMeta(t)
		if meta.IngressCount != 0 {
			t.Errorf("meta ingress count = %d, want 0", meta.IngressCount)
		}
		if h.c.hasIngressFlag && !meta.HasIngressRules {
			t.Error("meta has_ingress_rules = 0; the evaluator would default-allow instead of denying")
		}
		if meta.EgressCount != uint32(limit) || !meta.HasEgressRules {
			t.Errorf("meta egress = %d rules (declared=%t), want %d declared", meta.EgressCount, meta.HasEgressRules, limit)
		}
	})
}

func TestRuleStoreApplyFailsClosedOnlyForTheOverflowingEgress(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		limit := h.c.limit
		rs := testRuleSet(nRules(DirIngress, limit), nRules(DirEgress, limit+1))

		err := h.store.Apply(rs)
		wantCapacityErrors(t, err, CapacityError{
			Layer:     h.c.name,
			ID:        testGroupID,
			Direction: DirEgress,
			Entries:   limit + 1,
			Limit:     limit,
		})

		h.wantEmptyWindow(t, DirEgress)
		for i := range limit {
			h.wantSlot(t, uint32(i), rs.Ingress[i])
		}

		meta := h.installedMeta(t)
		if meta.EgressCount != 0 {
			t.Errorf("meta egress count = %d, want 0", meta.EgressCount)
		}
		if !meta.HasEgressRules {
			t.Error("meta has_egress_rules = 0; the evaluator would default-allow egress instead of denying")
		}
		if meta.IngressCount != uint32(limit) {
			t.Errorf("meta ingress count = %d, want %d", meta.IngressCount, limit)
		}
	})
}

func TestRuleStoreApplyReportsEveryOverflowingDirection(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		limit := h.c.limit
		rs := testRuleSet(nRules(DirIngress, limit+1), nRules(DirEgress, limit+2))

		err := h.store.Apply(rs)
		wantCapacityErrors(t, err,
			CapacityError{Layer: h.c.name, ID: testGroupID, Direction: DirIngress, Entries: limit + 1, Limit: limit},
			CapacityError{Layer: h.c.name, ID: testGroupID, Direction: DirEgress, Entries: limit + 2, Limit: limit},
		)

		if got := h.slotCount(); got != 0 {
			t.Errorf("installed slots = %d, want 0", got)
		}
		meta := h.installedMeta(t)
		if meta.IngressCount != 0 || meta.EgressCount != 0 {
			t.Errorf("meta counts = %d/%d, want 0/0", meta.IngressCount, meta.EgressCount)
		}
		if !meta.HasEgressRules {
			t.Error("meta has_egress_rules = 0; a fail-closed egress must stay in rule-list mode")
		}
	})
}

// Falling back to fail-closed denies flows the previous rules
// admitted, so the conntrack table must not keep trusting them.
func TestRuleStoreApplyBumpsWhenADirectionFallsBackToFailClosed(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		limit := h.c.limit
		if err := h.store.Apply(testRuleSet(nRules(DirIngress, limit), nil)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := h.bumper.count(); got != 1 {
			t.Fatalf("bumps = %d, want 1", got)
		}

		err := h.store.Apply(testRuleSet(nRules(DirIngress, limit+1), nil))
		if len(CapacityErrorsFrom(err)) != 1 {
			t.Fatalf("Apply error = %v, want one capacity error", err)
		}
		if got := h.bumper.count(); got != 2 {
			t.Errorf("bumps = %d, want 2 (fail-closed denies what the old rules admitted)", got)
		}
	})
}

// While a direction stays over capacity the data plane holds the same
// empty window, so editing the part that does not fit changes nothing
// and must not re-evaluate every admitted flow.
func TestRuleStoreApplyBumpsOnceWhileADirectionStaysOverCapacity(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		limit := h.c.limit
		first := nRules(DirIngress, limit+1)
		second := append(nRules(DirIngress, limit+1), testRule(DirIngress, 9999))

		for i, rules := range [][]Rule{first, second} {
			err := h.store.Apply(testRuleSet(rules, nil))
			if len(CapacityErrorsFrom(err)) != 1 {
				t.Fatalf("Apply step %d error = %v, want one capacity error", i, err)
			}
		}

		if got := h.bumper.count(); got != 1 {
			t.Errorf("bumps = %d, want 1 (the installed window did not change)", got)
		}
	})
}

func TestRuleStoreApplyBumpsOnceForIdenticalRuleSets(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		rs := testRuleSet([]Rule{testRule(DirIngress, 80)}, nil)
		for range 3 {
			if err := h.store.Apply(rs); err != nil {
				t.Fatalf("Apply: %v", err)
			}
		}

		if got := h.bumper.count(); got != 1 {
			t.Errorf("bumps = %d, want 1", got)
		}
		if got := len(h.table.applies); got != 3 {
			t.Errorf("rotations = %d, want 3 (rotation must not be skipped)", got)
		}
	})
}

func TestRuleStoreApplyBumpsOnEveryContentChange(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		versioned := testRuleSet([]Rule{testRule(DirIngress, 443), testRule(DirIngress, 80)}, nil)
		versioned.RulesetVersion = 9

		steps := []RuleSet{
			testRuleSet([]Rule{testRule(DirIngress, 80)}, nil),
			testRuleSet([]Rule{testRule(DirIngress, 80), testRule(DirIngress, 443)}, nil),
			testRuleSet([]Rule{testRule(DirIngress, 443), testRule(DirIngress, 80)}, nil),
			versioned,
			testRuleSet([]Rule{testRule(DirIngress, 443), testRule(DirIngress, 80)}, []Rule{testRule(DirEgress, 53)}),
		}
		for i, rs := range steps {
			if err := h.store.Apply(rs); err != nil {
				t.Fatalf("Apply step %d: %v", i, err)
			}
		}

		if got := h.bumper.count(); got != len(steps) {
			t.Errorf("bumps = %d, want %d", got, len(steps))
		}
	})
}

func TestRuleStoreApplyRejectsIDZero(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		if err := h.store.Apply(RuleSet{}); err == nil {
			t.Fatal("Apply with id=0 must fail")
		}
		if len(h.table.applies) != 0 || h.bumper.count() != 0 {
			t.Errorf("rotations = %d, bumps = %d, want 0 and 0", len(h.table.applies), h.bumper.count())
		}
	})
}

func TestRuleStoreApplyRetriesTheBumpAfterFailure(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		rs := testRuleSet([]Rule{testRule(DirIngress, 80)}, nil)

		want := errors.New("boom")
		h.bumper.err = want
		if err := h.store.Apply(rs); !errors.Is(err, want) {
			t.Fatalf("Apply error = %v, want %v", err, want)
		}

		h.bumper.err = nil
		if err := h.store.Apply(rs); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := h.bumper.count(); got != 1 {
			t.Errorf("bumps = %d, want 1", got)
		}
	})
}

func TestRuleStoreApplyDoesNotBumpWhenTheRotationFails(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		want := errors.New("boom")
		h.table.applyErr = want

		if err := h.store.Apply(testRuleSet([]Rule{testRule(DirIngress, 80)}, nil)); !errors.Is(err, want) {
			t.Fatalf("Apply error = %v, want %v", err, want)
		}
		if got := h.bumper.count(); got != 0 {
			t.Errorf("bumps = %d, want 0", got)
		}
	})
}

func TestRuleStoreDeleteBumps(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		rs := testRuleSet([]Rule{testRule(DirIngress, 80)}, nil)
		if err := h.store.Apply(rs); err != nil {
			t.Fatalf("Apply: %v", err)
		}

		if err := h.store.Delete(rs.GroupID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if got := h.bumper.count(); got != 2 {
			t.Errorf("bumps = %d, want 2", got)
		}

		if err := h.store.Apply(rs); err != nil {
			t.Fatalf("Apply after Delete: %v", err)
		}
		if got := h.bumper.count(); got != 3 {
			t.Errorf("bumps = %d, want 3 (Delete must forget the installed rules)", got)
		}
	})
}

// A Delete for rules this process never applied still bumps: the maps
// are pinned, so they can hold rules an earlier daemon installed.
func TestRuleStoreDeleteBumpsForUnknownID(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		if err := h.store.Delete(testGroupID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if got := h.bumper.count(); got != 1 {
			t.Errorf("bumps = %d, want 1", got)
		}
	})
}

func TestRuleStoreDeleteDoesNotBumpWhenTheTableFails(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, h *ruleStoreHarness) {
		want := errors.New("boom")
		h.table.deleteErr = want

		if err := h.store.Delete(testGroupID); !errors.Is(err, want) {
			t.Fatalf("Delete error = %v, want %v", err, want)
		}
		if got := h.bumper.count(); got != 0 {
			t.Errorf("bumps = %d, want 0", got)
		}
	})
}
