package policy

import (
	"sync"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

type fakeBumper struct {
	mu    sync.Mutex
	bumps int
	err   error
}

func (b *fakeBumper) Bump() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	b.bumps++
	return nil
}

func (b *fakeBumper) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bumps
}

// fakeRuleTable stands in for Rotator. It records the ids it was
// asked to rotate without touching a BPF map, so the callbacks the
// stores build are never run.
type fakeRuleTable struct {
	applies   []uint32
	deletes   []uint32
	applyErr  error
	deleteErr error
}

func (t *fakeRuleTable) Apply(id uint32, _ func(inner *ebpf.Map) error, _ func() error) error {
	if t.applyErr != nil {
		return t.applyErr
	}
	t.applies = append(t.applies, id)
	return nil
}

func (t *fakeRuleTable) Delete(id uint32) error {
	if t.deleteErr != nil {
		return t.deleteErr
	}
	t.deletes = append(t.deletes, id)
	return nil
}

func (t *fakeRuleTable) CloseAll() error { return nil }

// fakeMembershipTable stands in for sg_membership_map.
type fakeMembershipTable struct {
	entries   map[uint64]struct{}
	updates   int
	deletes   int
	updateErr error
	deleteErr error
}

func newFakeMembershipTable() *fakeMembershipTable {
	return &fakeMembershipTable{entries: make(map[uint64]struct{})}
}

func (t *fakeMembershipTable) Update(key, _ any, _ ebpf.MapUpdateFlags) error {
	if t.updateErr != nil {
		return t.updateErr
	}
	t.updates++
	t.entries[membershipFakeKey(key)] = struct{}{}
	return nil
}

func (t *fakeMembershipTable) Delete(key any) error {
	if t.deleteErr != nil {
		return t.deleteErr
	}
	t.deletes++
	k := membershipFakeKey(key)
	if _, ok := t.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(t.entries, k)
	return nil
}

func (t *fakeMembershipTable) has(vpcID, ipv4 uint32) bool {
	_, ok := t.entries[uint64(vpcID)<<32|uint64(ipv4)]
	return ok
}

func membershipFakeKey(key any) uint64 {
	k := key.(bpf.PodEgressSgMembershipKey)
	return uint64(k.VpcId)<<32 | uint64(k.Ipv4)
}
