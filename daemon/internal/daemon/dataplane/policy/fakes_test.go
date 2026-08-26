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

// fakeRuleArray stands in for one per-resource inner rule map. It
// keeps the slot each rule was written to, which is how the tests
// check that egress really lands in the high window.
type fakeRuleArray struct {
	slots map[uint32]any
}

func newFakeRuleArray() *fakeRuleArray {
	return &fakeRuleArray{slots: make(map[uint32]any)}
}

func (a *fakeRuleArray) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	a.slots[key.(uint32)] = value
	return nil
}

// fakeRuleTable stands in for Rotator. It records the ids it was
// asked to rotate and runs the write callbacks against in-memory
// tables, so tests can read back the exact slots and meta values a
// store publishes without needing CAP_BPF.
type fakeRuleTable struct {
	applies   []uint32
	deletes   []uint32
	applyErr  error
	deleteErr error

	// inner holds the rules written by the latest Apply. Rotator
	// mints a fresh inner map per rotation, so this is replaced
	// rather than added to.
	inner *fakeRuleArray
}

func (t *fakeRuleTable) Apply(id uint32, writeRules func(inner ruleArray) error, writeMeta func() error) error {
	if t.applyErr != nil {
		return t.applyErr
	}
	inner := newFakeRuleArray()
	if err := writeRules(inner); err != nil {
		return err
	}
	// Rotator only logs a meta write failure because the outer swap
	// already happened; mirror that so stores see the same contract.
	_ = writeMeta()
	t.applies = append(t.applies, id)
	t.inner = inner
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

// fakeMetaTable stands in for acl_meta_map / sg_meta_map.
type fakeMetaTable struct {
	values    map[uint32]any
	updateErr error
}

func newFakeMetaTable() *fakeMetaTable {
	return &fakeMetaTable{values: make(map[uint32]any)}
}

func (t *fakeMetaTable) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	if t.updateErr != nil {
		return t.updateErr
	}
	t.values[key.(uint32)] = value
	return nil
}

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
