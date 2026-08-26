package policy

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// ruleTable is the rotate-and-swap contract SGStore and ACLStore
// depend on. Rotator is the only implementation the daemon runs;
// tests bring their own because creating a BPF map needs CAP_BPF.
type ruleTable interface {
	Apply(id uint32, writeRules func(inner ruleArray) error, writeMeta func() error) error
	Delete(id uint32) error
	CloseAll() error
}

// ruleArray is the write side of one resource's inner rule map, and
// metaTable the write side of acl_meta_map / sg_meta_map. *ebpf.Map
// implements both; tests bring their own so they can read back which
// slot each rule landed in and what meta the store published.
type ruleArray interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

type metaTable interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

var (
	_ ruleTable = (*Rotator)(nil)
	_ ruleArray = (*ebpf.Map)(nil)
	_ metaTable = (*ebpf.Map)(nil)
)

// Rotator owns the inner-map lifecycle for a HASH_OF_MAPS-backed rule
// table that supports atomic rotate-and-swap updates. Both SGStore and
// ACLStore wrap a Rotator with a typed front-end that knows how to
// turn a RuleSet into the bpf2go-generated rule struct for that layer.
//
// Update flow (Apply):
//
//  1. NewMap(innerSpec) creates a fresh inner array map.
//  2. The caller-supplied writeRules callback fills slots [0, N).
//  3. outer.Update(id, inner.FD()) atomically swaps the new inner
//     into the HASH_OF_MAPS — observers always see a fully-formed
//     ruleset for a given id.
//  4. The caller-supplied writeMeta callback publishes per-id
//     metadata last (so meta-aware code paths read consistent state).
//  5. The previous inner for this id is closed under lock so no FDs
//     leak when the daemon rotates the same SG/ACL repeatedly.
//
// Failures before the swap close the throwaway inner; failures during
// the swap are returned without rolling back (rolling back would race
// with the data plane). Failures during writeMeta only log: outer is
// already authoritative, and a future reconcile will re-converge meta.
type Rotator struct {
	// name is a human label used in error / log messages
	// ("policy/securitygroup", "policy/networkacl").
	name      string
	outer     *ebpf.Map
	meta      *ebpf.Map
	innerSpec *ebpf.MapSpec

	mu        sync.Mutex
	snapshots map[uint32]*ebpf.Map
}

// NewRotator wraps an outer HASH_OF_MAPS plus its companion meta map
// and the inner array spec used to mint fresh inner maps on each
// rotation.
//
// innerSpec is copied on every Apply, so the shared spec object is
// never mutated.
func NewRotator(name string, outer, meta *ebpf.Map, innerSpec *ebpf.MapSpec) *Rotator {
	return &Rotator{
		name:      name,
		outer:     outer,
		meta:      meta,
		innerSpec: innerSpec,
		snapshots: make(map[uint32]*ebpf.Map),
	}
}

// Apply runs writeRules to populate a fresh inner map, swaps it onto
// the outer HASH_OF_MAPS, then runs writeMeta to publish metadata.
// id must be > 0; 0 is reserved as the "not-allocated" sentinel.
//
// writeRules is called exactly once with the throwaway inner map. The
// callback must not retain the inner reference; Rotator owns it from
// the moment it is created.
//
// writeMeta runs only after the outer swap succeeds. A meta write
// error is logged but not returned, mirroring the original SGStore
// behaviour: the outer was already swapped, so rolling back would be
// racier than letting the next reconcile reconverge.
func (r *Rotator) Apply(id uint32, writeRules func(inner ruleArray) error, writeMeta func() error) error {
	if id == 0 {
		return fmt.Errorf("policy/%s: cannot apply with id=0", r.name)
	}

	inner, err := ebpf.NewMap(r.innerSpec.Copy())
	if err != nil {
		return fmt.Errorf("policy/%s: create inner map for id %d: %w", r.name, id, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = inner.Close()
		}
	}()

	if err := writeRules(inner); err != nil {
		return fmt.Errorf("policy/%s: write rules for id %d: %w", r.name, id, err)
	}

	if err := r.outer.Update(id, uint32(inner.FD()), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("policy/%s: install inner map for id %d: %w", r.name, id, err)
	}

	if err := writeMeta(); err != nil {
		zap.S().Warnf("policy/%s: write meta %d: %v", r.name, id, err)
	}

	committed = true
	r.mu.Lock()
	old := r.snapshots[id]
	r.snapshots[id] = inner
	r.mu.Unlock()
	if old != nil {
		if err := old.Close(); err != nil {
			zap.S().Warnf("policy/%s: close old inner %d: %v", r.name, id, err)
		}
	}
	return nil
}

// Delete removes both the outer rule entry and the meta entry for id.
// Idempotent on missing keys.
func (r *Rotator) Delete(id uint32) error {
	if id == 0 {
		return nil
	}
	if err := r.outer.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("policy/%s: delete rules for id %d: %w", r.name, id, err)
	}
	if err := r.meta.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("policy/%s: delete meta for id %d: %w", r.name, id, err)
	}

	r.mu.Lock()
	old, hadOld := r.snapshots[id]
	delete(r.snapshots, id)
	r.mu.Unlock()
	if hadOld && old != nil {
		if err := old.Close(); err != nil {
			zap.S().Warnf("policy/%s: close inner %d on delete: %v", r.name, id, err)
		}
	}
	return nil
}

// CloseAll releases every retained inner-map handle. Used by Manager
// on shutdown so we do not leak FDs across daemon reloads.
func (r *Rotator) CloseAll() error {
	r.mu.Lock()
	snaps := r.snapshots
	r.snapshots = make(map[uint32]*ebpf.Map)
	r.mu.Unlock()

	var errs []error
	for _, m := range snaps {
		if m == nil {
			continue
		}
		if err := m.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
