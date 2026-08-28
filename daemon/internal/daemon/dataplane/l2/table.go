// Package l2 holds the state the L2Network data plane keeps outside
// the BPF programs: the per-VNI tables the programs read, and the
// aging of the addresses they learn into them.
package l2

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// Table owns the inner maps of one HASH_OF_MAPS keyed by VNI.
//
// It works the way policy.Rotator does — mint an inner map, install it
// on the outer with a single Update, keep the handle so it can be
// closed later — with one difference. A policy inner map is rewritten
// as a whole on every change, so Rotator swaps a fresh one in every
// time. An L2 inner map holds either what the data plane has learned
// or a membership list that changes one endpoint at a time, and
// swapping would throw all of it away. Table therefore mints an inner
// map once, on the first Ensure for a VNI, and lets it go only when
// the L2Network does.
//
// Every map operation runs under mu, including the syscalls. Two
// reconcilers and the aging sweep all reach a table, and a handle read
// out from under the lock could be closed by a delete before its
// syscall lands — on a descriptor number the next map has already
// taken.
type Table struct {
	name      string
	outer     *ebpf.Map
	innerSpec *ebpf.MapSpec

	mu     sync.Mutex
	inners map[uint32]*ebpf.Map
}

// NewTable wraps an outer HASH_OF_MAPS and the spec its inner maps are
// minted from. innerSpec is copied on every Ensure, so the caller may
// keep using the spec it passed.
func NewTable(name string, outer *ebpf.Map, innerSpec *ebpf.MapSpec) *Table {
	return &Table{
		name:      name,
		outer:     outer,
		innerSpec: innerSpec,
		inners:    make(map[uint32]*ebpf.Map),
	}
}

// Ensure builds the inner map of vni and installs it on the outer map.
// Calling it again for the same VNI does nothing, so a reconciler may
// call it on every pass and two reconcilers may both call it without
// agreeing on who goes first.
func (t *Table) Ensure(vni uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := t.ensureLocked(vni)
	return err
}

func (t *Table) ensureLocked(vni uint32) (*ebpf.Map, error) {
	if vni == 0 {
		return nil, fmt.Errorf("l2/%s: vni 0 is not a network", t.name)
	}
	if inner, ok := t.inners[vni]; ok {
		return inner, nil
	}

	inner, err := ebpf.NewMap(t.innerSpec.Copy())
	if err != nil {
		return nil, fmt.Errorf("l2/%s: create inner map for vni %d: %w", t.name, vni, err)
	}
	if err := t.outer.Update(vni, uint32(inner.FD()), ebpf.UpdateAny); err != nil {
		_ = inner.Close()
		return nil, fmt.Errorf("l2/%s: install inner map for vni %d: %w", t.name, vni, err)
	}
	t.inners[vni] = inner
	return inner, nil
}

// AddMember puts one member into the inner map of vni, building the
// table first if this is the first member. Members are a set: the
// value the data plane reads is always 1 and only the key matters.
func (t *Table) AddMember(vni, member uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	inner, err := t.ensureLocked(vni)
	if err != nil {
		return err
	}
	var present uint8 = 1
	if err := inner.Update(member, present, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("l2/%s: add member %d to vni %d: %w", t.name, member, vni, err)
	}
	return nil
}

// RemoveMember takes one member out of the inner map of vni. A VNI
// this node holds no table for, and a member that is already gone, are
// both fine: the caller is undoing what an earlier pass wrote, and the
// network itself may have been deleted in between.
func (t *Table) RemoveMember(vni, member uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	inner, ok := t.inners[vni]
	if !ok {
		return nil
	}
	if err := inner.Delete(member); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("l2/%s: remove member %d from vni %d: %w", t.name, member, vni, err)
	}
	return nil
}

// ForEachInner runs fn over every inner map this table holds, in VNI
// order. The lock is held for the whole walk, so a network deleted
// halfway through waits rather than closing a map fn is reading.
func (t *Table) ForEachInner(fn func(vni uint32, inner *ebpf.Map)) {
	t.mu.Lock()
	defer t.mu.Unlock()

	vnis := make([]uint32, 0, len(t.inners))
	for vni := range t.inners {
		vnis = append(vnis, vni)
	}
	sort.Slice(vnis, func(i, j int) bool { return vnis[i] < vnis[j] })

	for _, vni := range vnis {
		fn(vni, t.inners[vni])
	}
}

// Delete drops the inner map of vni from the outer map and closes it.
// A missing key is not an error: the outer map is pinned and outlives
// the process, so a delete may be the first thing this daemon does to
// a VNI an earlier one built.
func (t *Table) Delete(vni uint32) error {
	if vni == 0 {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	inner, hadInner := t.inners[vni]
	delete(t.inners, vni)

	if err := t.outer.Delete(vni); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("l2/%s: remove inner map for vni %d: %w", t.name, vni, err)
	}
	if hadInner {
		if err := inner.Close(); err != nil {
			zap.S().Warnf("l2/%s: close inner map for vni %d: %v", t.name, vni, err)
		}
	}
	return nil
}

// CloseAll releases every inner-map handle. The Manager calls it on
// shutdown so a daemon reload does not leak file descriptors.
func (t *Table) CloseAll() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var errs []error
	for _, inner := range t.inners {
		if err := inner.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	t.inners = make(map[uint32]*ebpf.Map)
	return errors.Join(errs...)
}
