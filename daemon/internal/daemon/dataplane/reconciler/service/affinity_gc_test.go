package service

import (
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
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
	gc.gcOnce()

	var v bpf.PodEgressServiceAffinityVal
	if err := m.Lookup(&keep, &v); err != nil {
		t.Errorf("expected keep entry to remain: %v", err)
	}
	if err := m.Lookup(&expire, &v); err == nil {
		t.Errorf("expected expire entry to be deleted, still present: %+v", v)
	}
}

func TestAffinityGC_NilMapNoOp(t *testing.T) {
	gc := &AffinityGC{affinityMap: nil, now: func() uint64 { return 0 }}
	gc.gcOnce() // must not panic
}
