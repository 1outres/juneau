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
	_, err := t.ensure(vni)
	return err
}

func (t *Table) ensure(vni uint32) (*ebpf.Map, error) {
	if vni == 0 {
		return nil, fmt.Errorf("l2/%s: vni 0 is not a network", t.name)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
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
	inner, err := t.ensure(vni)
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
	inner, ok := t.inners[vni]
	t.mu.Unlock()
	if !ok {
		return nil
	}
	if err := inner.Delete(member); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("l2/%s: remove member %d from vni %d: %w", t.name, member, vni, err)
	}
	return nil
}

// Inner returns the inner map of vni, or nil when this node holds no
// table for it. The aging sweep reads entries through it.
func (t *Table) Inner(vni uint32) *ebpf.Map {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inners[vni]
}

// VNIs lists the networks this table holds an inner map for, in a
// stable order.
func (t *Table) VNIs() []uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]uint32, 0, len(t.inners))
	for vni := range t.inners {
		out = append(out, vni)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
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
	inner, hadInner := t.inners[vni]
	delete(t.inners, vni)
	t.mu.Unlock()

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
	inners := t.inners
	t.inners = make(map[uint32]*ebpf.Map)
	t.mu.Unlock()

	var errs []error
	for _, inner := range inners {
		if err := inner.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
