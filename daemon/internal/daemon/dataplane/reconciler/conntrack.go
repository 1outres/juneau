package reconciler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/ctstate"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/mapsweep"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/monotonic"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/policyct"
)

// ConntrackGCInterval is how often the GC scans the conntrack tables.
// eBPF deletes CLOSED entries inline, so the GC is mainly catching idle
// / half-open / FIN_WAIT-timed-out flows, plus the policy entries a
// rule change put out of reach. Both tables are plain HASH maps, so
// nothing but this GC frees their space; 30s keeps them from filling
// up under typical workloads, and bounds how long the orphaned policy
// entries take up space.
const ConntrackGCInterval = 30 * time.Second

// The reasons the GC removes conntrack entries for.
const (
	reasonExpired    mapsweep.Reason = "expired"
	reasonStaleEpoch mapsweep.Reason = "staleEpoch"
)

type (
	natCTKey    = bpf.PodEgressCtKey
	natCTVal    = bpf.PodEgressCtVal
	policyCTKey = policyct.Key
	policyCTVal = bpf.PodEgressPolicyCtVal
)

// ctTable is one conntrack table the GC sweeps. sweep runs one pass
// at the given time and reports what it did.
type ctTable struct {
	name  string
	sweep func(nowNs uint64) mapsweep.Report
}

// EpochSource reports the policy generation the data plane is
// enforcing. policy.Epoch implements it. The GC takes the interface so
// this package does not depend on the policy package.
type EpochSource interface {
	Current() uint32
}

// ConntrackMaps are the maps the conntrack GC works on.
type ConntrackMaps struct {
	// CT is ct_map, the table the Service / NAPT / LB paths own.
	CT *ebpf.Map
	// PolicyCT is policy_ct_map, the table the policy stage owns.
	PolicyCT *ebpf.Map
	// PolicyCTStats is policy_ct_stats, where the policy stage counts
	// the pairs it could not write in full.
	PolicyCTStats *ebpf.Map
}

// Conntrack drives periodic cleanup of every conntrack table. It is
// not informer-driven; the manager runs Conntrack.Run on a goroutine
// and cancels its context to stop it.
type Conntrack struct {
	tables   []ctTable
	interval time.Duration
}

func NewConntrack(maps ConntrackMaps, epoch EpochSource, interval time.Duration) *Conntrack {
	return newConntrack(interval,
		natTable(maps.CT),
		policyTable(maps.PolicyCT, maps.PolicyCTStats, epoch),
	)
}

func newConntrack(interval time.Duration, tables ...ctTable) *Conntrack {
	if interval <= 0 {
		interval = ConntrackGCInterval
	}
	return &Conntrack{tables: tables, interval: interval}
}

func (c *Conntrack) Run(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, report := range c.sweep(monotonic.Ns()) {
				report.Log("conntrack gc")
			}
		}
	}
}

// sweep runs one pass over every table. A table that fails does not
// stop the others.
func (c *Conntrack) sweep(nowNs uint64) []mapsweep.Report {
	reports := make([]mapsweep.Report, 0, len(c.tables))
	for _, table := range c.tables {
		reports = append(reports, table.sweep(nowNs))
	}
	return reports
}

// natTable sweeps ct_map, the table the Service / NAPT / LB paths own.
func natTable(m *ebpf.Map) ctTable {
	const name = "ct_map"
	return ctTable{
		name: name,
		sweep: func(nowNs uint64) mapsweep.Report {
			stats, err := mapsweep.Sweep(m, func(snapshot []mapsweep.Entry[natCTKey, natCTVal]) mapsweep.Plan[natCTKey, natCTVal] {
				return planNATCT(snapshot, nowNs)
			})
			return mapsweep.Report{Map: name, Stats: stats, Err: err}
		},
	}
}

func planNATCT(snapshot []mapsweep.Entry[natCTKey, natCTVal], nowNs uint64) mapsweep.Plan[natCTKey, natCTVal] {
	return mapsweep.ByEntry(snapshot, reasonExpired, func(k natCTKey, v natCTVal) bool {
		return ctstate.ShouldEvict(v.State, k.Proto, v.LastSeenNs, nowNs)
	})
}

// policyTable sweeps policy_ct_map, the per-enforcement-point table the
// policy stage owns, and reports how many pairs the policy stage could
// not write since the previous pass.
func policyTable(m, stats *ebpf.Map, epoch EpochSource) ctTable {
	s := &policySweeper{ct: m, stats: stats, epoch: epoch}
	return ctTable{name: policySweeperName, sweep: s.sweep}
}

const policySweeperName = "policy_ct_map"

// policySweeper keeps the install failures it saw on the previous
// pass, so each report can say how much they grew.
type policySweeper struct {
	ct    *ebpf.Map
	stats *ebpf.Map
	epoch EpochSource

	failures installFailures
}

func (s *policySweeper) sweep(nowNs uint64) mapsweep.Report {
	stats, err := mapsweep.Sweep(s.ct, func(snapshot []mapsweep.Entry[policyCTKey, policyCTVal]) mapsweep.Plan[policyCTKey, policyCTVal] {
		// The epoch is read after the snapshot. An entry written under
		// an epoch published while the snapshot was read then counts as
		// current, not as stale.
		return planPolicyCT(snapshot, s.epoch.Current(), nowNs)
	})
	report := mapsweep.Report{Map: policySweeperName, Stats: stats, Err: err}

	failures, err := readInstallFailures(s.stats)
	if err != nil {
		report.Err = errors.Join(report.Err, err)
		return report
	}
	grown := failures.since(s.failures)
	s.failures = failures
	report.Fields = []any{
		"reverseInstallFailures", grown.reverse,
		"forwardInstallFailures", grown.forward,
	}
	if grown.any() {
		report.Warnings = append(report.Warnings, "policy_ct_install could not write some pairs")
	}
	return report
}

// planPolicyCT decides what to remove from policy_ct_map.
//
// An entry of an epoch other than the current one goes whatever its
// age. The epoch is part of the key, so once it moves on no lookup can
// reach the entry again, and this sweep is the only thing that removes
// it.
//
// An entry of the current epoch is one half of a pair: a key K, and
// policyct.Reverse(K), which the same admission wrote. A pair goes only
// when every half of it still in the table has gone idle, and both
// halves go together. Judging each half on its own breaks one-way
// flows. The sender keeps the forward half fresh while the reply half
// idles out, and a forward half without its partner short-circuits
// every later packet of the flow, so the reply half is never written
// again and every reply is judged as a new flow (issue #77).
func planPolicyCT(snapshot []mapsweep.Entry[policyCTKey, policyCTVal], epoch uint32, nowNs uint64) mapsweep.Plan[policyCTKey, policyCTVal] {
	idle := func(k policyCTKey, v policyCTVal) bool {
		return ctstate.ShouldEvict(v.State, k.Proto, v.LastSeenNs, nowNs)
	}

	current := make(map[policyCTKey]policyCTVal)
	for _, e := range snapshot {
		if e.Key.Epoch == epoch {
			current[e.Key] = e.Value
		}
	}

	var groups []mapsweep.Group[policyCTKey]
	planned := make(map[policyCTKey]bool)
	for _, e := range snapshot {
		if e.Key.Epoch != epoch {
			groups = append(groups, mapsweep.Group[policyCTKey]{Keys: []policyCTKey{e.Key}, Reason: reasonStaleEpoch})
			continue
		}
		if planned[e.Key] || !idle(e.Key, e.Value) {
			continue
		}
		partner := policyct.Reverse(e.Key)
		if v, ok := current[partner]; ok && !idle(partner, v) {
			continue
		}
		planned[partner] = true
		groups = append(groups, mapsweep.Group[policyCTKey]{Keys: []policyCTKey{e.Key, partner}, Reason: reasonExpired})
	}

	return mapsweep.Plan[policyCTKey, policyCTVal]{
		Groups: groups,
		Confirm: func(group mapsweep.Group[policyCTKey], now []mapsweep.Current[policyCTKey, policyCTVal]) bool {
			if group.Reason == reasonStaleEpoch {
				return true
			}
			for _, c := range now {
				if c.Present && !idle(c.Key, c.Value) {
					return false
				}
			}
			return true
		},
	}
}

// installFailures is what policy_ct_stats has counted: the admissions
// that wrote neither half of their pair, and the ones that wrote only
// the reverse half.
type installFailures struct {
	reverse uint64
	forward uint64
}

func (f installFailures) since(earlier installFailures) installFailures {
	return installFailures{
		reverse: f.reverse - earlier.reverse,
		forward: f.forward - earlier.forward,
	}
}

func (f installFailures) any() bool { return f.reverse != 0 || f.forward != 0 }

func readInstallFailures(m *ebpf.Map) (installFailures, error) {
	reverse, err := sumPerCPU(m, policyct.StatReverseInstallFailed)
	if err != nil {
		return installFailures{}, err
	}
	forward, err := sumPerCPU(m, policyct.StatForwardInstallFailed)
	if err != nil {
		return installFailures{}, err
	}
	return installFailures{reverse: reverse, forward: forward}, nil
}

func sumPerCPU(m *ebpf.Map, slot uint32) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(slot, &perCPU); err != nil {
		return 0, fmt.Errorf("read slot %d of policy_ct_stats: %w", slot, err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}
