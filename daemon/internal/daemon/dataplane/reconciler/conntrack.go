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

// ConntrackGCInterval is how often the GC scans ct_map. eBPF deletes
// CLOSED entries inline, so the GC is mainly catching idle / half-open /
// FIN_WAIT-timed-out flows. 30s gives the LRU enough headroom under
// typical workloads.
const ConntrackGCInterval = 30 * time.Second

// Conntrack drives periodic ct_map cleanup. It is not informer-driven;
// the manager runs Conntrack.Run on a goroutine and cancels its context
// to stop it.
type Conntrack struct {
	ctMap    *ebpf.Map
	interval time.Duration
}

func NewConntrack(ctMap *ebpf.Map, interval time.Duration) *Conntrack {
	if interval <= 0 {
		interval = ConntrackGCInterval
	}
	return &Conntrack{ctMap: ctMap, interval: interval}
}

func (c *Conntrack) Run(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.gcOnce()
		}
	}
}

func (c *Conntrack) gcOnce() {
	nowNs := monotonicNs()

	var (
		key bpf.PodEgressCtKey
		val bpf.PodEgressCtVal
	)
	iter := c.ctMap.Iterate()
	for iter.Next(&key, &val) {
		if !ctstate.ShouldEvict(val.State, key.Proto, val.LastSeenNs, nowNs) {
			continue
		}
		// Racing against eBPF inline deletes / LRU eviction is normal —
		// silently skip when the entry has already vanished.
		if err := c.ctMap.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			zap.S().Warnf("conntrack gc: delete: %v", err)
		}
	}
	if err := iter.Err(); err != nil {
		zap.S().Warnf("conntrack gc: iterate: %v", err)
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
