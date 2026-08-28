package service

import (
	"context"
	"errors"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/monotonic"
)

// AffinityGCInterval bounds how stale an expired ClientIP-affinity
// entry may stay in service_affinity_map. The map is LRU_HASH so
// expired entries do not threaten correctness — gen + bound checks
// in the BPF fast path guard against use after a backend rebind —
// but a periodic sweep keeps map pressure bounded under steady load
// where the LRU hand never has to evict. 5 minutes mirrors typical
// kube-proxy IPVS sweep cadence.
const AffinityGCInterval = 5 * time.Minute

// AffinityGC drives periodic service_affinity_map cleanup. It runs
// outside the informer-driven Runner pattern because no Kubernetes
// event causes affinity entries to be created or removed: their
// lifecycle is purely time- and packet-driven inside the data plane.
type AffinityGC struct {
	affinityMap *ebpf.Map
	interval    time.Duration
	now         func() uint64 // CLOCK_MONOTONIC nanoseconds; injected for tests
}

// NewAffinityGC constructs the GC. interval <= 0 falls back to
// AffinityGCInterval so the manager can pass the constant directly.
func NewAffinityGC(affinityMap *ebpf.Map, interval time.Duration) *AffinityGC {
	if interval <= 0 {
		interval = AffinityGCInterval
	}
	return &AffinityGC{
		affinityMap: affinityMap,
		interval:    interval,
		now:         monotonic.Ns,
	}
}

// Run sweeps the affinity map on a ticker until ctx is done.
func (g *AffinityGC) Run(ctx context.Context) {
	t := time.NewTicker(g.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.gcOnce()
		}
	}
}

func (g *AffinityGC) gcOnce() {
	if g.affinityMap == nil {
		return
	}
	nowNs := g.now()

	var (
		key bpf.PodEgressServiceAffinityKey
		val bpf.PodEgressServiceAffinityVal
	)
	iter := g.affinityMap.Iterate()
	for iter.Next(&key, &val) {
		if val.ExpiresAtNs > nowNs {
			continue
		}
		// Racing against BPF inline updates / LRU eviction is normal —
		// silently skip when the entry has already vanished.
		if err := g.affinityMap.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("service affinity gc: delete: %v", err)
		}
	}
	if err := iter.Err(); err != nil {
		zap.S().Warnf("service affinity gc: iterate: %v", err)
	}
}
