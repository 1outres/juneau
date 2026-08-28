// Package l2 holds the state the L2Network data plane keeps outside
// the BPF programs: the per-VNI tables the programs read, and the
// aging of the addresses they learn into them.
package l2

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// The value of one entry of a flood list, mirroring L2_PORT_FLAG_* in
// daemon/bpf/maps.h. An ordinary local veth and a remote node carry
// PortFlagPresent; the gateway port of the segment carries the two
// together, which is what tells the data plane to hand it its copy of a
// flooded frame on ingress rather than on egress.
const (
	PortFlagPresent uint8 = 1
	PortFlagGateway uint8 = 2
)

// FdbFlagGateway mirrors L2_FDB_FLAG_GATEWAY in daemon/bpf/maps.h. It
// marks the one forwarding entry user space writes: the MAC of this
// node's gateway port. A frame that claims that address cannot take the
// entry over, and the aging sweep leaves it alone.
const FdbFlagGateway uint32 = 1

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

// Put writes one entry into the inner map of vni, building the table
// first when this is the first entry.
func (t *Table) Put(vni uint32, key, value any) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	inner, err := t.ensureLocked(vni)
	if err != nil {
		return err
	}
	if err := inner.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("l2/%s: write %v into vni %d: %w", t.name, key, vni, err)
	}
	return nil
}

// PutIfAbsent writes one entry into the inner map of vni only while
// nothing holds that key yet, building the table first when this is the
// first entry.
//
// It is how user space offers what the control plane knows without
// taking anything away from what the data plane has seen. An entry that
// is already there was either written by an earlier pass or learned
// from a frame, and a frame is the better source: it says what the
// segment is really doing, while the control plane only knows what it
// handed out.
func (t *Table) PutIfAbsent(vni uint32, key, value any) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	inner, err := t.ensureLocked(vni)
	if err != nil {
		return err
	}
	if err := inner.Update(key, value, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return nil
		}
		return fmt.Errorf("l2/%s: write %v into vni %d: %w", t.name, key, vni, err)
	}
	return nil
}

// RemoveIfEqual takes one entry out of the inner map of vni, but only
// while it still holds the value the caller wrote.
//
// The pair of this and PutIfAbsent is what keeps user space from
// undoing the data plane. An entry the data plane has since corrected
// no longer matches, so it stays; the caller is only ever taking back
// its own.
//
// The read and the delete run under the same lock, so nothing user
// space does lands between them. A frame arriving in that window can
// still overwrite the entry after the read, which costs one relearn and
// nothing else.
func (t *Table) RemoveIfEqual(vni uint32, key, value any) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	inner, ok := t.inners[vni]
	if !ok {
		return nil
	}

	current := reflect.New(reflect.TypeOf(value))
	if err := inner.Lookup(key, current.Interface()); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("l2/%s: read %v of vni %d: %w", t.name, key, vni, err)
	}
	if !reflect.DeepEqual(current.Elem().Interface(), value) {
		return nil
	}

	if err := inner.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("l2/%s: remove %v from vni %d: %w", t.name, key, vni, err)
	}
	return nil
}

// Remove takes one entry out of the inner map of vni. A VNI this node
// holds no table for, and an entry that is already gone, are both fine:
// the caller is undoing what an earlier pass wrote, and the network
// itself may have been deleted in between.
func (t *Table) Remove(vni uint32, key any) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	inner, ok := t.inners[vni]
	if !ok {
		return nil
	}
	if err := inner.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("l2/%s: remove %v from vni %d: %w", t.name, key, vni, err)
	}
	return nil
}

// AddMember puts one ordinary port on a flood list. The gateway port
// carries a flag of its own, so it is written with Put instead.
func (t *Table) AddMember(vni, member uint32) error {
	return t.Put(vni, member, PortFlagPresent)
}

// RemoveMember takes one port off a flood list.
func (t *Table) RemoveMember(vni, member uint32) error {
	return t.Remove(vni, member)
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
