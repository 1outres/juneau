package l2

import (
	"context"
	"errors"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/monotonic"
)

// FdbAging is how long a learned MAC survives without being seen
// again. It mirrors L2_FDB_AGING_NS in maps.h — the data plane stamps
// the entries and this is what reads the stamps, so the two numbers
// have to say the same thing.
const FdbAging = 300 * time.Second

// FdbGCInterval is how often the sweep runs. A tenth of the aging time
// keeps an entry from outliving it by much without making the sweep a
// busy loop.
const FdbGCInterval = 30 * time.Second

// FdbGC ages the learned addresses out of every L2Network's forwarding
// table. Nothing in Kubernetes says a MAC has gone away — a workload
// stops sending and that is all — so the sweep runs on a ticker rather
// than on informer events, the way service.AffinityGC does.
//
// The tables are LRU maps, so a table that fills up keeps working
// without this. What the sweep adds is that a MAC which has moved
// somewhere juneau cannot see stops being forwarded to its old place
// once the aging time has passed.
type FdbGC struct {
	table    *Table
	aging    uint64
	interval time.Duration
	now      func() uint64
}

// NewFdbGC builds the sweeper over the l2_fdb table. aging <= 0 and
// interval <= 0 take the constants above, so the Manager can leave
// both out.
func NewFdbGC(table *Table, aging, interval time.Duration) *FdbGC {
	if aging <= 0 {
		aging = FdbAging
	}
	if interval <= 0 {
		interval = FdbGCInterval
	}
	return &FdbGC{
		table:    table,
		aging:    uint64(aging.Nanoseconds()),
		interval: interval,
		now:      monotonic.Ns,
	}
}

// Run sweeps every table on a ticker until ctx is done.
func (g *FdbGC) Run(ctx context.Context) {
	t := time.NewTicker(g.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.Sweep()
		}
	}
}

// Sweep drops every entry that has not been seen for the aging time.
// Exported so a test can run one pass without a ticker.
func (g *FdbGC) Sweep() {
	if g.table == nil {
		return
	}
	nowNs := g.now()
	g.table.ForEachInner(func(vni uint32, inner *ebpf.Map) {
		g.sweepOne(vni, inner, nowNs)
	})
}

func (g *FdbGC) sweepOne(vni uint32, inner *ebpf.Map, nowNs uint64) {
	var (
		key bpf.PodEgressL2FdbKey
		val bpf.PodEgressL2FdbVal
	)
	iter := inner.Iterate()
	for iter.Next(&key, &val) {
		// A stamp from the future means the data plane refreshed the
		// entry between the read of the clock and the read of the
		// entry. It is fresh by definition, so leave it.
		if val.LastSeenNs > nowNs || nowNs-val.LastSeenNs < g.aging {
			continue
		}
		// Losing the race against a refresh or an LRU eviction is
		// normal: the entry is gone either way.
		if err := inner.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("l2 fdb gc: delete from vni %d: %v", vni, err)
		}
	}
	if err := iter.Err(); err != nil {
		zap.S().Warnf("l2 fdb gc: iterate vni %d: %v", vni, err)
	}
}
