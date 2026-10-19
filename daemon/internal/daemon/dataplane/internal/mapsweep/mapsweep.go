// Package mapsweep removes entries from a live BPF hash map that the
// data plane keeps reading and writing.
//
// The package does the map I/O and nothing else. Which entries go is
// decided by a Planner, which sees plain values and no map, so the
// decision can be tested without BPF.
//
// A pass has two steps.
//
// The read step takes a snapshot of the whole map with
// BPF_MAP_LOOKUP_BATCH. In a hash map the batch cursor is a bucket
// number, so a delete that runs at the same time does not send the
// read back to the start. ebpf.Map.Iterate does not have that
// property: it walks with BPF_MAP_GET_NEXT_KEY, which returns the first
// key of the map when the key it is given has been deleted. A walk that
// deletes as it goes therefore starts over again and again, cilium/ebpf
// gives up on it with ErrIterationAborted, and the end of the map is
// never reached (issue #77).
//
// The remove step reads every key of a planned group again right
// before it deletes it, and asks the plan once more with what it
// found, because the data plane may have used the entry since the
// snapshot. Keys are deleted one at a time. BPF_MAP_DELETE_BATCH stops
// at the first key that is not there, and the data plane deletes keys
// on its own, so a batch delete would stop part way for no reason.
package mapsweep

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// defaultChunk is how many entries one batch lookup asks for. It only
// bounds the size of one syscall: the read goes on until the map ends.
const defaultChunk = 4096

// Entry is one key of a map and the value under it.
type Entry[K, V any] struct {
	Key   K
	Value V
}

// Current is what the map holds under one key at the recheck. When
// Present is false the key is gone and Value is the zero value.
type Current[K, V any] struct {
	Key     K
	Value   V
	Present bool
}

// Reason says why a plan removes a group. Stats counts the removed
// keys by it.
type Reason string

// Group is a set of keys that are removed together or not at all.
type Group[K any] struct {
	Keys   []K
	Reason Reason
}

// Plan is what a Planner decided for one snapshot.
type Plan[K, V any] struct {
	// Groups are the keys to remove.
	Groups []Group[K]
	// Confirm judges a group again right before it is removed. current
	// holds one item for each key of the group, in the same order, and
	// is reused after the call returns. Confirm returns false to keep
	// every key of the group. A group with no key left in the map is
	// not asked about.
	Confirm func(group Group[K], current []Current[K, V]) bool
}

// Planner decides what to remove, from a snapshot of the whole map.
type Planner[K, V any] func(snapshot []Entry[K, V]) Plan[K, V]

// Stats is what one pass saw and did.
type Stats struct {
	// Capacity is the max_entries of the map.
	Capacity uint32
	// Read is the number of entries in the snapshot.
	Read int
	// Removed counts the keys the pass deleted, by the reason of their
	// group.
	Removed map[Reason]int
	// Kept counts the keys of planned groups that were still in the map
	// and that the recheck decided to keep.
	Kept int
}

// Occupancy is the share of the capacity the snapshot found in use.
func (s Stats) Occupancy() float64 {
	if s.Capacity == 0 {
		return 0
	}
	return float64(s.Read) / float64(s.Capacity)
}

// ByEntry plans to remove each entry on its own when stale says so.
// The recheck asks stale again about the value the map holds then.
func ByEntry[K, V any](snapshot []Entry[K, V], reason Reason, stale func(K, V) bool) Plan[K, V] {
	var groups []Group[K]
	for _, e := range snapshot {
		if stale(e.Key, e.Value) {
			groups = append(groups, Group[K]{Keys: []K{e.Key}, Reason: reason})
		}
	}
	return Plan[K, V]{
		Groups: groups,
		Confirm: func(_ Group[K], current []Current[K, V]) bool {
			return stale(current[0].Key, current[0].Value)
		},
	}
}

// Sweep runs one pass over m, which has to be a HASH or an LRU_HASH
// map. The returned Stats cover what the pass got through, also when
// it fails part way.
func Sweep[K, V any](m *ebpf.Map, plan Planner[K, V]) (Stats, error) {
	stats := Stats{Capacity: m.MaxEntries(), Removed: make(map[Reason]int)}

	entries, err := Snapshot[K, V](m)
	if err != nil {
		return stats, err
	}
	stats.Read = len(entries)

	p := plan(entries)
	current := make([]Current[K, V], 0, 2)
	for _, group := range p.Groups {
		current, err = recheck(m, group.Keys, current[:0])
		if err != nil {
			return stats, err
		}
		present := 0
		for _, c := range current {
			if c.Present {
				present++
			}
		}
		if present == 0 {
			continue
		}
		if !p.Confirm(group, current) {
			stats.Kept += present
			continue
		}
		for _, c := range current {
			if !c.Present {
				continue
			}
			removed, err := remove(m, c.Key)
			if err != nil {
				return stats, err
			}
			if removed {
				stats.Removed[group.Reason]++
			}
		}
	}
	return stats, nil
}

// Snapshot reads every entry of m, which has to be a HASH or an
// LRU_HASH map. An entry written or deleted while the read runs may or
// may not be in the result, and no entry is in it twice.
func Snapshot[K, V any](m *ebpf.Map) ([]Entry[K, V], error) {
	return snapshot[K, V](m, defaultChunk)
}

func snapshot[K, V any](m *ebpf.Map, chunk int) ([]Entry[K, V], error) {
	switch m.Type() {
	case ebpf.Hash, ebpf.LRUHash:
	default:
		return nil, fmt.Errorf("mapsweep: cannot read a %s map: the batch cursor is only known to be safe for HASH and LRU_HASH", m.Type())
	}

	chunk = min(chunk, int(m.MaxEntries()))
	var (
		out    []Entry[K, V]
		cursor ebpf.MapBatchCursor
		keys   = make([]K, chunk)
		values = make([]V, chunk)
	)
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		for i := range n {
			out = append(out, Entry[K, V]{Key: keys[i], Value: values[i]})
		}
		switch {
		case errors.Is(err, ebpf.ErrKeyNotExist):
			return out, nil
		case errors.Is(err, unix.ENOSPC):
			// One bucket holds more entries than the buffer. The kernel
			// returns none of them and leaves the cursor on that bucket,
			// so the same call with a larger buffer goes on from there.
			if len(keys) >= int(m.MaxEntries()) {
				return nil, fmt.Errorf("mapsweep: batch lookup: a buffer of max_entries (%d) does not fit one bucket: %w", len(keys), err)
			}
			size := min(2*len(keys), int(m.MaxEntries()))
			keys = make([]K, size)
			values = make([]V, size)
		case err != nil:
			return nil, fmt.Errorf("mapsweep: batch lookup: %w", err)
		}
	}
}

func recheck[K, V any](m *ebpf.Map, keys []K, current []Current[K, V]) ([]Current[K, V], error) {
	for _, key := range keys {
		c := Current[K, V]{Key: key}
		err := m.Lookup(&c.Key, &c.Value)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return current, fmt.Errorf("mapsweep: look up %+v: %w", key, err)
		}
		c.Present = err == nil
		current = append(current, c)
	}
	return current, nil
}

// remove deletes one key and reports whether it was there to delete.
func remove[K any](m *ebpf.Map, key K) (bool, error) {
	err := m.Delete(&key)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ebpf.ErrKeyNotExist):
		return false, nil
	}
	return false, fmt.Errorf("mapsweep: delete %+v: %w", key, err)
}
