package policy

import (
	"errors"
	"testing"
)

// ruleStore is the part of SGStore and ACLStore this file exercises.
// Both layers must invalidate flows on the same rules, so they run
// the same suite.
type ruleStore interface {
	Apply(rs RuleSet) error
	Delete(id uint32) error
}

type ruleStoreCase struct {
	name     string
	maxRules int
	limitErr error
	build    func(table ruleTable, bumper Bumper) ruleStore
}

func ruleStoreCases() []ruleStoreCase {
	return []ruleStoreCase{
		{
			name:     "securitygroup",
			maxRules: MaxRulesPerSG,
			limitErr: ErrRuleLimitExceeded,
			build: func(table ruleTable, bumper Bumper) ruleStore {
				return newSGStore(table, nil, bumper)
			},
		},
		{
			name:     "networkacl",
			maxRules: MaxRulesPerACL,
			limitErr: ErrACLRuleLimitExceeded,
			build: func(table ruleTable, bumper Bumper) ruleStore {
				return newACLStore(table, nil, bumper)
			},
		},
	}
}

const testGroupID uint32 = 7

func testRule(port uint16) Rule {
	return Rule{
		Direction: DirIngress,
		Proto:     ProtoTCP,
		PortLo:    port,
		PortHi:    port,
		PeerKind:  PeerKindCIDR,
		Verdict:   VerdictAllow,
	}
}

func testRuleSet(rules ...Rule) RuleSet {
	return RuleSet{
		GroupID:         testGroupID,
		Rules:           rules,
		IngressCount:    len(rules),
		HasIngressRules: len(rules) > 0,
	}
}

func eachRuleStore(t *testing.T, run func(t *testing.T, c ruleStoreCase, store ruleStore, table *fakeRuleTable, bumper *fakeBumper)) {
	t.Helper()
	for _, c := range ruleStoreCases() {
		t.Run(c.name, func(t *testing.T) {
			table := &fakeRuleTable{}
			bumper := &fakeBumper{}
			run(t, c, c.build(table, bumper), table, bumper)
		})
	}
}

func TestRuleStoreApplyBumpsOnceForIdenticalRuleSets(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, _ ruleStoreCase, store ruleStore, table *fakeRuleTable, bumper *fakeBumper) {
		rs := testRuleSet(testRule(80))
		for range 3 {
			if err := store.Apply(rs); err != nil {
				t.Fatalf("Apply: %v", err)
			}
		}

		if got := bumper.count(); got != 1 {
			t.Errorf("bumps = %d, want 1", got)
		}
		if got := len(table.applies); got != 3 {
			t.Errorf("rotations = %d, want 3 (rotation must not be skipped)", got)
		}
	})
}

func TestRuleStoreApplyBumpsOnEveryContentChange(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, _ ruleStoreCase, store ruleStore, _ *fakeRuleTable, bumper *fakeBumper) {
		versioned := testRuleSet(testRule(443), testRule(80))
		versioned.RulesetVersion = 9

		steps := []RuleSet{
			testRuleSet(testRule(80)),
			testRuleSet(testRule(80), testRule(443)),
			testRuleSet(testRule(443), testRule(80)),
			versioned,
		}
		for i, rs := range steps {
			if err := store.Apply(rs); err != nil {
				t.Fatalf("Apply step %d: %v", i, err)
			}
		}

		if got := bumper.count(); got != len(steps) {
			t.Errorf("bumps = %d, want %d", got, len(steps))
		}
	})
}

func TestRuleStoreApplyIgnoresRulesBeyondTheLimit(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, c ruleStoreCase, store ruleStore, _ *fakeRuleTable, bumper *fakeBumper) {
		first := make([]Rule, 0, c.maxRules+1)
		for i := range c.maxRules + 1 {
			first = append(first, testRule(uint16(1000+i)))
		}
		second := append(first[:c.maxRules:c.maxRules], testRule(9999))

		if err := store.Apply(testRuleSet(first...)); !errors.Is(err, c.limitErr) {
			t.Fatalf("Apply error = %v, want %v", err, c.limitErr)
		}
		if err := store.Apply(testRuleSet(second...)); !errors.Is(err, c.limitErr) {
			t.Fatalf("Apply error = %v, want %v", err, c.limitErr)
		}

		if got := bumper.count(); got != 1 {
			t.Errorf("bumps = %d, want 1 (the installed prefix did not change)", got)
		}
	})
}

func TestRuleStoreApplyRejectsIDZero(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, _ ruleStoreCase, store ruleStore, table *fakeRuleTable, bumper *fakeBumper) {
		if err := store.Apply(RuleSet{}); err == nil {
			t.Fatal("Apply with id=0 must fail")
		}
		if len(table.applies) != 0 || bumper.count() != 0 {
			t.Errorf("rotations = %d, bumps = %d, want 0 and 0", len(table.applies), bumper.count())
		}
	})
}

func TestRuleStoreApplyRetriesTheBumpAfterFailure(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, _ ruleStoreCase, store ruleStore, _ *fakeRuleTable, bumper *fakeBumper) {
		rs := testRuleSet(testRule(80))

		want := errors.New("boom")
		bumper.err = want
		if err := store.Apply(rs); !errors.Is(err, want) {
			t.Fatalf("Apply error = %v, want %v", err, want)
		}

		bumper.err = nil
		if err := store.Apply(rs); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := bumper.count(); got != 1 {
			t.Errorf("bumps = %d, want 1", got)
		}
	})
}

func TestRuleStoreApplyDoesNotBumpWhenTheRotationFails(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, _ ruleStoreCase, store ruleStore, table *fakeRuleTable, bumper *fakeBumper) {
		want := errors.New("boom")
		table.applyErr = want

		if err := store.Apply(testRuleSet(testRule(80))); !errors.Is(err, want) {
			t.Fatalf("Apply error = %v, want %v", err, want)
		}
		if got := bumper.count(); got != 0 {
			t.Errorf("bumps = %d, want 0", got)
		}
	})
}

func TestRuleStoreDeleteBumps(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, _ ruleStoreCase, store ruleStore, _ *fakeRuleTable, bumper *fakeBumper) {
		rs := testRuleSet(testRule(80))
		if err := store.Apply(rs); err != nil {
			t.Fatalf("Apply: %v", err)
		}

		if err := store.Delete(rs.GroupID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if got := bumper.count(); got != 2 {
			t.Errorf("bumps = %d, want 2", got)
		}

		if err := store.Apply(rs); err != nil {
			t.Fatalf("Apply after Delete: %v", err)
		}
		if got := bumper.count(); got != 3 {
			t.Errorf("bumps = %d, want 3 (Delete must forget the installed rules)", got)
		}
	})
}

// A Delete for rules this process never applied still bumps: the maps
// are pinned, so they can hold rules an earlier daemon installed.
func TestRuleStoreDeleteBumpsForUnknownID(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, _ ruleStoreCase, store ruleStore, _ *fakeRuleTable, bumper *fakeBumper) {
		if err := store.Delete(testGroupID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if got := bumper.count(); got != 1 {
			t.Errorf("bumps = %d, want 1", got)
		}
	})
}

func TestRuleStoreDeleteDoesNotBumpWhenTheTableFails(t *testing.T) {
	eachRuleStore(t, func(t *testing.T, _ ruleStoreCase, store ruleStore, table *fakeRuleTable, bumper *fakeBumper) {
		want := errors.New("boom")
		table.deleteErr = want

		if err := store.Delete(testGroupID); !errors.Is(err, want) {
			t.Fatalf("Delete error = %v, want %v", err, want)
		}
		if got := bumper.count(); got != 0 {
			t.Errorf("bumps = %d, want 0", got)
		}
	})
}
