package reconciler

import (
	"errors"
	"testing"
	"time"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/ctstate"
)

// recordingTable is a ctTable backed by an in-memory slice. It records
// which entries the GC asked to evict so tests can assert on the
// eviction decision without a live kernel map.
type recordingTable struct {
	name    string
	entries []ctFlow
	err     error

	walks   int
	evicted []ctFlow
}

func (r *recordingTable) table() ctTable {
	return ctTable{
		name: r.name,
		walk: func(evict func(ctFlow) bool) (int, error) {
			r.walks++
			for _, e := range r.entries {
				if evict(e) {
					r.evicted = append(r.evicted, e)
				}
			}
			return len(r.evicted), r.err
		},
	}
}

func establishedFlow(lastSeenNs uint64) ctFlow {
	return ctFlow{state: ctstate.StateEstablished, proto: ctstate.ProtoTCP, lastSeenNs: lastSeenNs}
}

// fixedEpoch is an EpochSource that never moves.
type fixedEpoch uint32

func (e fixedEpoch) Current() uint32 { return uint32(e) }

func TestSweepEvictsOnlyExpiredEntries(t *testing.T) {
	const now = uint64(4 * time.Hour)

	fresh := establishedFlow(now - uint64(time.Minute))
	idle := establishedFlow(now - uint64(2*ctstate.TTLEstablished))
	closed := ctFlow{state: ctstate.StateClosed, proto: ctstate.ProtoTCP, lastSeenNs: now}

	tbl := &recordingTable{name: "ct_map", entries: []ctFlow{fresh, idle, closed}}
	c := newConntrack(0, tbl.table())

	c.sweep(now)

	if tbl.walks != 1 {
		t.Fatalf("walks=%d, want 1", tbl.walks)
	}
	want := []ctFlow{idle, closed}
	if len(tbl.evicted) != len(want) {
		t.Fatalf("evicted=%v, want %v", tbl.evicted, want)
	}
	for i, w := range want {
		if tbl.evicted[i] != w {
			t.Errorf("evicted[%d]=%v, want %v", i, tbl.evicted[i], w)
		}
	}
}

func TestSweepVisitsEveryTable(t *testing.T) {
	const now = uint64(4 * time.Hour)
	stale := establishedFlow(0)

	ct := &recordingTable{name: "ct_map", entries: []ctFlow{stale}}
	policy := &recordingTable{name: "policy_ct_map", entries: []ctFlow{stale}}
	c := newConntrack(0, ct.table(), policy.table())

	c.sweep(now)

	for _, tbl := range []*recordingTable{ct, policy} {
		if tbl.walks != 1 {
			t.Errorf("%s: walks=%d, want 1", tbl.name, tbl.walks)
		}
		if len(tbl.evicted) != 1 {
			t.Errorf("%s: evicted=%v, want one entry", tbl.name, tbl.evicted)
		}
	}
}

func TestSweepContinuesAfterTableError(t *testing.T) {
	const now = uint64(4 * time.Hour)
	stale := establishedFlow(0)

	broken := &recordingTable{name: "ct_map", entries: []ctFlow{stale}, err: errors.New("iterate: boom")}
	healthy := &recordingTable{name: "policy_ct_map", entries: []ctFlow{stale}}
	c := newConntrack(0, broken.table(), healthy.table())

	c.sweep(now)

	if healthy.walks != 1 {
		t.Fatalf("healthy table not swept after the previous table failed")
	}
}

func TestPolicyEvictRuleDropsOtherEpochs(t *testing.T) {
	const now = uint64(4 * time.Hour)
	const current = uint32(7)

	fresh := establishedFlow(now - uint64(time.Minute))
	idle := establishedFlow(now - uint64(2*ctstate.TTLEstablished))
	expired := func(f ctFlow) bool {
		return ctstate.ShouldEvict(f.state, f.proto, f.lastSeenNs, now)
	}

	evict := policyEvictRule(current, expired)

	if evict(current, fresh) {
		t.Errorf("entry admitted under the current rules evicted while still fresh")
	}
	if !evict(current-1, fresh) {
		t.Errorf("entry from an older generation kept: no lookup can reach it again")
	}
	if !evict(current, idle) {
		t.Errorf("idle entry on the current generation kept: the TTL rule still applies")
	}
}

func TestNewConntrackSweepsCTAndPolicyTables(t *testing.T) {
	// The maps are nil because the tables are never walked here; the
	// point is that both keyspaces are registered for GC.
	c := NewConntrack(nil, nil, fixedEpoch(1), 0)

	got := make([]string, 0, len(c.tables))
	for _, tbl := range c.tables {
		got = append(got, tbl.name)
	}
	want := []string{"ct_map", "policy_ct_map"}
	if len(got) != len(want) {
		t.Fatalf("tables=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tables[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestNewConntrackDefaultsInterval(t *testing.T) {
	if got := NewConntrack(nil, nil, fixedEpoch(1), 0).interval; got != ConntrackGCInterval {
		t.Errorf("interval=%v, want %v", got, ConntrackGCInterval)
	}
	if got := NewConntrack(nil, nil, fixedEpoch(1), time.Second).interval; got != time.Second {
		t.Errorf("interval=%v, want %v", got, time.Second)
	}
}
