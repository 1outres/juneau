package reconciler

import (
	"context"
	"errors"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/ctstate"
)

// ConntrackGCInterval is how often the GC scans the conntrack tables.
// eBPF deletes CLOSED entries inline, so the GC is mainly catching idle
// / half-open / FIN_WAIT-timed-out flows, plus the policy entries a
// rule change put out of reach. 30s gives the LRU enough headroom
// under typical workloads, and bounds how long the orphaned policy
// entries take up space.
const ConntrackGCInterval = 30 * time.Second

// ctFlow is the part of a conntrack entry the TTL rules look at. Both
// ct_map and policy_ct_map carry it, which is what lets one GC sweep
// both tables even though the rest of their layouts differ.
type ctFlow struct {
	state      uint8
	proto      uint8
	lastSeenNs uint64
}

// ctTable is one conntrack table the GC sweeps. walk visits every
// entry, deletes the ones it decides to drop, and reports how many it
// removed. expired is the TTL rule both tables share; a table may drop
// entries for reasons of its own on top of it. The name is for logs.
type ctTable struct {
	name string
	walk func(expired func(ctFlow) bool) (int, error)
}

// EpochSource reports the policy generation the data plane is
// enforcing. policy.Epoch implements it. The GC takes the interface so
// this package does not depend on the policy package.
type EpochSource interface {
	Current() uint32
}

// Conntrack drives periodic cleanup of every conntrack table. It is
// not informer-driven; the manager runs Conntrack.Run on a goroutine
// and cancels its context to stop it.
type Conntrack struct {
	tables   []ctTable
	interval time.Duration
}

func NewConntrack(ctMap, policyCtMap *ebpf.Map, epoch EpochSource, interval time.Duration) *Conntrack {
	return newConntrack(interval, natTable(ctMap), policyTable(policyCtMap, epoch))
}

func newConntrack(interval time.Duration, tables ...ctTable) *Conntrack {
	if interval <= 0 {
		interval = ConntrackGCInterval
	}
	return &Conntrack{tables: tables, interval: interval}
}

// natTable sweeps ct_map, the table the Service / NAPT / LB paths own.
func natTable(m *ebpf.Map) ctTable {
	const name = "ct_map"
	return ctTable{
		name: name,
		walk: func(expired func(ctFlow) bool) (int, error) {
			var key bpf.PodEgressCtKey
			var val bpf.PodEgressCtVal
			return sweepMap(name, m, &key, &val, func() bool {
				return expired(ctFlow{state: val.State, proto: key.Proto, lastSeenNs: val.LastSeenNs})
			})
		},
	}
}

// policyTable sweeps policy_ct_map, the per-enforcement-point table the
// policy stage owns.
func policyTable(m *ebpf.Map, epoch EpochSource) ctTable {
	const name = "policy_ct_map"
	return ctTable{
		name: name,
		walk: func(expired func(ctFlow) bool) (int, error) {
			// One read per pass. A bump in the middle of a walk can
			// cost the entries written right after it an extra
			// evaluation, which is what the bump asked for anyway.
			evict := policyEvictRule(epoch.Current(), expired)
			var key bpf.PodEgressPolicyCtKey
			var val bpf.PodEgressPolicyCtVal
			return sweepMap(name, m, &key, &val, func() bool {
				return evict(key.Epoch, ctFlow{state: val.State, proto: key.Proto, lastSeenNs: val.LastSeenNs})
			})
		},
	}
}

// policyEvictRule extends the shared TTL rule with the generation
// check only policy_ct_map needs. The generation is part of the key,
// so once it moves on nothing can look the entry up again: it is dead
// weight however recently it was used, and this sweep is the only
// thing that removes it.
func policyEvictRule(current uint32, expired func(ctFlow) bool) func(uint32, ctFlow) bool {
	return func(entryEpoch uint32, f ctFlow) bool {
		return entryEpoch != current || expired(f)
	}
}

// sweepMap walks one live BPF map. key and val are the typed scratch
// the iterator fills; evict reads them back after each step and says
// whether the entry has to go.
func sweepMap(name string, m *ebpf.Map, key, val any, evict func() bool) (int, error) {
	deleted := 0
	iter := m.Iterate()
	for iter.Next(key, val) {
		if !evict() {
			continue
		}
		// Racing against eBPF inline deletes / LRU eviction is normal —
		// silently skip when the entry has already vanished.
		if err := m.Delete(key); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				zap.S().Warnf("conntrack gc: %s: delete: %v", name, err)
			}
			continue
		}
		deleted++
	}
	return deleted, iter.Err()
}

func (c *Conntrack) Run(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.sweep(monotonicNs())
		}
	}
}

func (c *Conntrack) sweep(nowNs uint64) {
	expired := func(f ctFlow) bool {
		return ctstate.ShouldEvict(f.state, f.proto, f.lastSeenNs, nowNs)
	}
	for _, table := range c.tables {
		deleted, err := table.walk(expired)
		if err != nil {
			zap.S().Warnf("conntrack gc: %s: iterate: %v", table.name, err)
		}
		if deleted > 0 {
			zap.S().Debugf("conntrack gc: %s: evicted %d entries", table.name, deleted)
		}
	}
}

// monotonicNs returns the same clock the eBPF side observes via
// bpf_ktime_get_ns: nanoseconds since boot on CLOCK_MONOTONIC. Using
// time.Now() (wall clock) here would silently break TTL comparisons.
func monotonicNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		zap.S().Warnf("conntrack gc: clock_gettime: %v", err)
		return 0
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec)
}
