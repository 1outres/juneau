package reconciler

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/ctstate"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/mapsweep"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/policyct"
)

// fixedEpoch is an EpochSource that never moves.
type fixedEpoch uint32

func (e fixedEpoch) Current() uint32 { return uint32(e) }

const testNow = uint64(24 * time.Hour)

func natEntry(i uint32, state uint8, lastSeenNs uint64) mapsweep.Entry[natCTKey, natCTVal] {
	return mapsweep.Entry[natCTKey, natCTVal]{
		Key:   natCTKey{Scope: 7, Saddr: i, Proto: ctstate.ProtoTCP},
		Value: natCTVal{State: state, LastSeenNs: lastSeenNs},
	}
}

func policyEntry(key policyCTKey, lastSeenNs uint64) mapsweep.Entry[policyCTKey, policyCTVal] {
	return mapsweep.Entry[policyCTKey, policyCTVal]{
		Key:   key,
		Value: policyCTVal{State: ctstate.StateEstablished, LastSeenNs: lastSeenNs},
	}
}

func present[K, V any](key K, value V) mapsweep.Current[K, V] {
	return mapsweep.Current[K, V]{Key: key, Value: value, Present: true}
}

func groupKeys(plan mapsweep.Plan[policyCTKey, policyCTVal]) [][]policyCTKey {
	out := make([][]policyCTKey, 0, len(plan.Groups))
	for _, g := range plan.Groups {
		out = append(out, g.Keys)
	}
	return out
}

// A minute ago is fresh for every protocol, and ten hours ago is idle
// for every protocol.
var (
	freshNs = testNow - uint64(time.Minute)
	idleNs  = testNow - uint64(10*time.Hour)
)

func TestNATCTPlanRemovesOnlyIdleEntries(t *testing.T) {
	fresh := natEntry(1, ctstate.StateEstablished, freshNs)
	idle := natEntry(2, ctstate.StateEstablished, testNow-uint64(2*ctstate.TTLEstablished))
	closed := natEntry(3, ctstate.StateClosed, testNow)

	plan := planNATCT([]mapsweep.Entry[natCTKey, natCTVal]{fresh, idle, closed}, testNow)

	var got []natCTKey
	for _, g := range plan.Groups {
		if g.Reason != reasonExpired {
			t.Errorf("group %v has reason %q, want %q", g.Keys, g.Reason, reasonExpired)
		}
		got = append(got, g.Keys...)
	}
	if want := []natCTKey{idle.Key, closed.Key}; !slices.Equal(got, want) {
		t.Errorf("planned %v, want %v", got, want)
	}

	// The data plane used the idle entry after the snapshot.
	refreshed := present(idle.Key, natCTVal{State: ctstate.StateEstablished, LastSeenNs: testNow})
	if plan.Confirm(plan.Groups[0], []mapsweep.Current[natCTKey, natCTVal]{refreshed}) {
		t.Error("the recheck removed an entry the data plane refreshed after the snapshot")
	}
}

func TestPolicyCTPlanRemovesOldEpochsWhateverTheirAge(t *testing.T) {
	const epoch = uint32(7)
	fresh := policyEntry(flowKey(epoch, 1), freshNs)
	freshOld := policyEntry(flowKey(epoch-1, 2), freshNs)
	freshOlder := policyEntry(flowKey(epoch-5, 3), freshNs)
	plan := planPolicyCT([]mapsweep.Entry[policyCTKey, policyCTVal]{
		fresh, policyEntry(policyct.Reverse(fresh.Key), freshNs), freshOld, freshOlder,
	}, epoch, testNow)

	want := [][]policyCTKey{{freshOld.Key}, {freshOlder.Key}}
	if got := groupKeys(plan); !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("planned %v, want %v", got, want)
	}
	for _, g := range plan.Groups {
		if g.Reason != reasonStaleEpoch {
			t.Errorf("group %v has reason %q, want %q", g.Keys, g.Reason, reasonStaleEpoch)
		}
		if !plan.Confirm(g, []mapsweep.Current[policyCTKey, policyCTVal]{present(g.Keys[0], policyCTVal{LastSeenNs: testNow})}) {
			t.Errorf("the recheck kept %v: no lookup can reach an entry of an old epoch, however fresh", g.Keys)
		}
	}
}

func TestPolicyCTPlanJudgesAPairAsOne(t *testing.T) {
	const epoch = uint32(7)
	pair := func(i int, forwardNs, reverseNs uint64) []mapsweep.Entry[policyCTKey, policyCTVal] {
		key := flowKey(epoch, i)
		return []mapsweep.Entry[policyCTKey, policyCTVal]{
			policyEntry(key, forwardNs),
			policyEntry(policyct.Reverse(key), reverseNs),
		}
	}
	oneWay := pair(1, freshNs, idleNs)
	quietSender := pair(2, idleNs, freshNs)
	dead := pair(3, idleNs, idleNs)
	orphan := policyEntry(flowKey(epoch, 4), idleNs)

	snapshot := slices.Concat(oneWay, quietSender, dead, []mapsweep.Entry[policyCTKey, policyCTVal]{orphan})
	plan := planPolicyCT(snapshot, epoch, testNow)

	want := [][]policyCTKey{
		{dead[0].Key, dead[1].Key},
		{orphan.Key, policyct.Reverse(orphan.Key)},
	}
	if got := groupKeys(plan); !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("planned %v, want %v: a pair goes only when no half of it is fresh, and once", got, want)
	}
	for _, g := range plan.Groups {
		if g.Reason != reasonExpired {
			t.Errorf("group %v has reason %q, want %q", g.Keys, g.Reason, reasonExpired)
		}
	}
}

// The recheck reads both halves again, and judges the pair again on
// what it finds.
func TestPolicyCTPlanRecheckJudgesThePairAgain(t *testing.T) {
	const epoch = uint32(7)
	key := flowKey(epoch, 1)
	partner := policyct.Reverse(key)
	plan := planPolicyCT([]mapsweep.Entry[policyCTKey, policyCTVal]{
		policyEntry(key, idleNs), policyEntry(partner, idleNs),
	}, epoch, testNow)
	if len(plan.Groups) != 1 {
		t.Fatalf("planned %v, want the one pair", groupKeys(plan))
	}
	group := plan.Groups[0]

	idle := policyCTVal{State: ctstate.StateEstablished, LastSeenNs: idleNs}
	fresh := policyCTVal{State: ctstate.StateEstablished, LastSeenNs: testNow}
	for _, tc := range []struct {
		name string
		now  []mapsweep.Current[policyCTKey, policyCTVal]
		want bool
	}{
		{"both halves still idle", []mapsweep.Current[policyCTKey, policyCTVal]{present(key, idle), present(partner, idle)}, true},
		{"one half used since the snapshot", []mapsweep.Current[policyCTKey, policyCTVal]{present(key, idle), present(partner, fresh)}, false},
		{"one half gone, the other idle", []mapsweep.Current[policyCTKey, policyCTVal]{present(key, idle), {Key: partner}}, true},
		{"one half gone, the other written again", []mapsweep.Current[policyCTKey, policyCTVal]{{Key: key}, present(partner, fresh)}, false},
	} {
		if got := plan.Confirm(group, tc.now); got != tc.want {
			t.Errorf("%s: remove=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestInstallFailuresSinceIsTheGrowth(t *testing.T) {
	earlier := installFailures{reverse: 3, forward: 1}
	later := installFailures{reverse: 5, forward: 1}

	grown := later.since(earlier)
	if want := (installFailures{reverse: 2}); grown != want {
		t.Errorf("growth = %+v, want %+v", grown, want)
	}
	if !grown.any() {
		t.Error("a growth of the reverse count reads as no failure")
	}
	if later.since(later).any() {
		t.Error("no growth reads as a failure")
	}
}

func reporting(name string, err error, calls *[]string) ctTable {
	return ctTable{
		name: name,
		sweep: func(uint64) mapsweep.Report {
			*calls = append(*calls, name)
			return mapsweep.Report{Map: name, Err: err}
		},
	}
}

func TestSweepVisitsEveryTableAndKeepsGoingAfterAFailure(t *testing.T) {
	var calls []string
	boom := errors.New("boom")
	c := newConntrack(0, reporting("ct_map", boom, &calls), reporting("policy_ct_map", nil, &calls))

	reports := c.sweep(testNow)

	if want := []string{"ct_map", "policy_ct_map"}; !slices.Equal(calls, want) {
		t.Errorf("swept %v, want %v", calls, want)
	}
	if len(reports) != 2 || !errors.Is(reports[0].Err, boom) || reports[1].Err != nil {
		t.Errorf("reports = %+v, want the failure of the first table and a clean second one", reports)
	}
}

func TestNewConntrackSweepsCTAndPolicyTables(t *testing.T) {
	// The maps are nil because the tables are never swept here; the
	// point is that both keyspaces are registered for GC.
	c := NewConntrack(ConntrackMaps{}, fixedEpoch(1), 0)

	got := make([]string, 0, len(c.tables))
	for _, tbl := range c.tables {
		got = append(got, tbl.name)
	}
	if want := []string{"ct_map", "policy_ct_map"}; !slices.Equal(got, want) {
		t.Errorf("tables=%v, want %v", got, want)
	}
}

func TestNewConntrackDefaultsInterval(t *testing.T) {
	if got := NewConntrack(ConntrackMaps{}, fixedEpoch(1), 0).interval; got != ConntrackGCInterval {
		t.Errorf("interval=%v, want %v", got, ConntrackGCInterval)
	}
	if got := NewConntrack(ConntrackMaps{}, fixedEpoch(1), time.Second).interval; got != time.Second {
		t.Errorf("interval=%v, want %v", got, time.Second)
	}
}
