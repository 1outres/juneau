package service

import (
	"slices"
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/mapsweep"
)

// newAffinityMap allocates an in-process LRU_HASH that mirrors the
// real service_affinity_map ABI. Tests use it through the cilium/ebpf
// userspace fake so we can drive iteration / delete on a non-root
// host (CI) while exercising the actual GC code path.
func newAffinityMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    12,
		ValueSize:  16,
		MaxEntries: 32,
	})
	if err != nil {
		t.Skipf("ebpf.NewMap unavailable on this host: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestAffinityGC_DeletesExpired(t *testing.T) {
	m := newAffinityMap(t)
	if m == nil {
		return
	}

	const nowNs = uint64(10_000_000_000)
	keep := bpf.PodEgressServiceAffinityKey{ClusterIp: 0x0a000001, Port: 80, Proto: 6, ClientIp: 0xc0a80001}
	expire := bpf.PodEgressServiceAffinityKey{ClusterIp: 0x0a000001, Port: 80, Proto: 6, ClientIp: 0xc0a80002}
	keepVal := bpf.PodEgressServiceAffinityVal{BackendIndex: 0, BackendGen: 1, ExpiresAtNs: nowNs + 1_000_000_000}
	expireVal := bpf.PodEgressServiceAffinityVal{BackendIndex: 1, BackendGen: 1, ExpiresAtNs: nowNs - 1_000_000_000}

	if err := m.Update(&keep, &keepVal, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed keep: %v", err)
	}
	if err := m.Update(&expire, &expireVal, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed expire: %v", err)
	}

	gc := &AffinityGC{affinityMap: m, now: func() uint64 { return nowNs }}
	reports := gc.gcOnce()

	var v bpf.PodEgressServiceAffinityVal
	if err := m.Lookup(&keep, &v); err != nil {
		t.Errorf("expected keep entry to remain: %v", err)
	}
	if err := m.Lookup(&expire, &v); err == nil {
		t.Errorf("expected expire entry to be deleted, still present: %+v", v)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want one", len(reports))
	}
	if r := reports[0]; r.Err != nil || r.Stats.Read != 2 || r.Stats.Removed[reasonExpired] != 1 {
		t.Errorf("report = %+v, want 2 read and 1 removed as expired", r)
	}
}

func TestAffinityGC_NilMapNoOp(t *testing.T) {
	gc := &AffinityGC{affinityMap: nil, now: func() uint64 { return 0 }}
	if reports := gc.gcOnce(); len(reports) != 0 {
		t.Errorf("a GC with no map reported %+v", reports)
	}
}

func TestAffinityExpiryPlanRemovesWhatHasExpired(t *testing.T) {
	const nowNs = uint64(10_000_000_000)
	entry := func(client uint32, expiresAtNs uint64) mapsweep.Entry[affinityKey, affinityVal] {
		return mapsweep.Entry[affinityKey, affinityVal]{
			Key:   affinityKey{ClusterIp: 0x0a000001, Port: 80, Proto: 6, ClientIp: client},
			Value: affinityVal{ExpiresAtNs: expiresAtNs},
		}
	}
	live := entry(1, nowNs+1)
	expiresNow := entry(2, nowNs)
	expired := entry(3, nowNs-1)

	plan := planAffinityExpiry([]mapsweep.Entry[affinityKey, affinityVal]{live, expiresNow, expired}, nowNs)

	var got []affinityKey
	for _, g := range plan.Groups {
		got = append(got, g.Keys...)
	}
	if want := []affinityKey{expiresNow.Key, expired.Key}; !slices.Equal(got, want) {
		t.Errorf("planned %v, want %v", got, want)
	}
	renewed := mapsweep.Current[affinityKey, affinityVal]{Key: expired.Key, Value: affinityVal{ExpiresAtNs: nowNs + 1}, Present: true}
	if plan.Confirm(plan.Groups[0], []mapsweep.Current[affinityKey, affinityVal]{renewed}) {
		t.Error("the recheck removed an affinity the data plane renewed after the snapshot")
	}
}
