package mapsweep

import (
	"errors"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const reasonOld Reason = "old"

// newMap builds a real map. The package exists for what the kernel
// does with a map while it is read and written, so a fake would only
// show what the fake does.
func newMap(t *testing.T, typ ebpf.MapType, maxEntries uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       typ,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: maxEntries,
	})
	if err != nil {
		t.Skipf("ebpf.NewMap unavailable on this host: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func put(t *testing.T, m *ebpf.Map, key uint32, value uint64) {
	t.Helper()
	if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
		t.Fatalf("write %d: %v", key, err)
	}
}

func has(t *testing.T, m *ebpf.Map, key uint32) bool {
	t.Helper()
	var value uint64
	err := m.Lookup(key, &value)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ebpf.ErrKeyNotExist):
		return false
	}
	t.Fatalf("look up %d: %v", key, err)
	return false
}

// below plans to remove every entry whose value is under limit.
func below(limit uint64) Planner[uint32, uint64] {
	return func(snapshot []Entry[uint32, uint64]) Plan[uint32, uint64] {
		return ByEntry(snapshot, reasonOld, func(_ uint32, v uint64) bool { return v < limit })
	}
}

// The read step leans on two things the kernel does in a hash map
// batch lookup. A bucket that does not fit in the buffer fails the
// call with ENOSPC and leaves the cursor where it was, and the cursor
// counts buckets, so the read can go on from it with a larger buffer.
// This test pins both down: if a kernel or cilium/ebpf stops doing
// them, it fails here and not as a sweep that silently misses entries.
func TestBatchLookupFailsWithENOSPCAndKeepsTheCursor(t *testing.T) {
	// 64 keys in 64 buckets: some bucket holds two or more of them
	// unless every key lands in a bucket of its own, which is about as
	// likely as 1 in 10^26.
	const size = 64
	m := newMap(t, ebpf.Hash, size)
	for key := range uint32(size) {
		put(t, m, key, uint64(key))
	}

	var (
		cursor ebpf.MapBatchCursor
		seen   []uint32
		hitENO bool
	)
	keys := make([]uint32, 1)
	values := make([]uint64, 1)
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		seen = append(seen, keys[:n]...)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if errors.Is(err, unix.ENOSPC) {
			if n != 0 {
				t.Fatalf("ENOSPC came with %d entries, want none", n)
			}
			hitENO = true
			keys = make([]uint32, 2*len(keys))
			values = make([]uint64, 2*len(values))
			continue
		}
		if err != nil {
			t.Fatalf("batch lookup: %v", err)
		}
	}

	if !hitENO {
		t.Fatal("no bucket held more than one key, so ENOSPC was never tested")
	}
	slices.Sort(seen)
	if len(seen) != size || len(slices.Compact(slices.Clone(seen))) != size {
		t.Fatalf("read %d keys (%v), want each of the %d keys once", len(seen), seen, size)
	}
}

func TestSnapshotReadsEveryEntryOnce(t *testing.T) {
	const size = 64
	m := newMap(t, ebpf.Hash, size)
	for key := range uint32(size) {
		put(t, m, key, uint64(key)*10)
	}

	// A one-entry buffer forces the read through ENOSPC and the growth
	// of the buffer.
	got, err := snapshot[uint32, uint64](m, 1)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(got) != size {
		t.Fatalf("snapshot has %d entries, want %d", len(got), size)
	}
	seen := make(map[uint32]bool, size)
	for _, e := range got {
		if seen[e.Key] {
			t.Errorf("key %d read twice", e.Key)
		}
		seen[e.Key] = true
		if e.Value != uint64(e.Key)*10 {
			t.Errorf("key %d read with value %d, want %d", e.Key, e.Value, uint64(e.Key)*10)
		}
	}
}

func TestSnapshotOfAnEmptyMapIsEmpty(t *testing.T) {
	m := newMap(t, ebpf.Hash, 16)
	got, err := Snapshot[uint32, uint64](m)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("snapshot of an empty map has %d entries", len(got))
	}
}

// The batch cursor of an array is a key, not a bucket, and nothing
// here has been checked against it. The sweep refuses rather than
// guess.
func TestSnapshotRefusesAMapThatIsNotAHash(t *testing.T) {
	m := newMap(t, ebpf.Array, 16)
	if _, err := Snapshot[uint32, uint64](m); err == nil {
		t.Error("snapshot of an ARRAY map succeeded, want an error")
	}
}

func TestSweepRemovesWhatThePlanSelects(t *testing.T) {
	for _, typ := range []ebpf.MapType{ebpf.Hash, ebpf.LRUHash} {
		t.Run(typ.String(), func(t *testing.T) {
			m := newMap(t, typ, 64)
			for key := range uint32(10) {
				put(t, m, key, uint64(key))
			}

			stats, err := Sweep(m, below(4))
			if err != nil {
				t.Fatalf("sweep: %v", err)
			}

			for key := range uint32(10) {
				if got, want := has(t, m, key), key >= 4; got != want {
					t.Errorf("key %d: present=%v, want %v", key, got, want)
				}
			}
			want := Stats{Capacity: 64, Read: 10, Removed: map[Reason]int{reasonOld: 4}}
			if !stats.equal(want) {
				t.Errorf("stats = %+v, want %+v", stats, want)
			}
		})
	}
}

// The data plane may use an entry between the read and the remove.
// The recheck has to see that and keep the entry.
func TestSweepKeepsAnEntryThatChangedAfterTheRead(t *testing.T) {
	m := newMap(t, ebpf.Hash, 16)
	put(t, m, 1, 0)
	put(t, m, 2, 0)

	refreshFirst := func(snapshot []Entry[uint32, uint64]) Plan[uint32, uint64] {
		plan := below(5)(snapshot)
		put(t, m, 1, 100)
		return plan
	}
	stats, err := Sweep(m, refreshFirst)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if !has(t, m, 1) {
		t.Error("the sweep removed an entry that was refreshed after the read")
	}
	if has(t, m, 2) {
		t.Error("the sweep kept an entry that stayed stale")
	}
	want := Stats{Capacity: 16, Read: 2, Removed: map[Reason]int{reasonOld: 1}, Kept: 1}
	if !stats.equal(want) {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
}

// The data plane deletes entries on its own. A key that is gone by the
// time the sweep comes to it is not an error and not a removal.
func TestSweepPassesOverAKeyThatIsAlreadyGone(t *testing.T) {
	m := newMap(t, ebpf.Hash, 16)
	put(t, m, 1, 0)
	put(t, m, 2, 0)

	deleteFirst := func(snapshot []Entry[uint32, uint64]) Plan[uint32, uint64] {
		plan := below(5)(snapshot)
		if err := m.Delete(uint32(1)); err != nil {
			t.Fatalf("delete: %v", err)
		}
		return plan
	}
	stats, err := Sweep(m, deleteFirst)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if has(t, m, 2) {
		t.Error("the sweep kept an entry that stayed stale")
	}
	want := Stats{Capacity: 16, Read: 2, Removed: map[Reason]int{reasonOld: 1}}
	if !stats.equal(want) {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
}

// A group is removed as a whole or not at all, and Confirm sees every
// key of it, the ones that are gone included.
func TestSweepRemovesAGroupTogether(t *testing.T) {
	m := newMap(t, ebpf.Hash, 16)
	put(t, m, 1, 0)
	put(t, m, 2, 0)
	put(t, m, 3, 0)
	put(t, m, 4, 50)

	var asked [][]Current[uint32, uint64]
	pairs := func([]Entry[uint32, uint64]) Plan[uint32, uint64] {
		return Plan[uint32, uint64]{
			Groups: []Group[uint32]{
				{Keys: []uint32{1, 2}, Reason: reasonOld},
				{Keys: []uint32{3, 4}, Reason: reasonOld},
				{Keys: []uint32{5, 6}, Reason: reasonOld},
			},
			Confirm: func(_ Group[uint32], current []Current[uint32, uint64]) bool {
				asked = append(asked, slices.Clone(current))
				for _, c := range current {
					if c.Present && c.Value >= 5 {
						return false
					}
				}
				return true
			},
		}
	}
	stats, err := Sweep(m, pairs)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	for key, want := range map[uint32]bool{1: false, 2: false, 3: true, 4: true} {
		if got := has(t, m, key); got != want {
			t.Errorf("key %d: present=%v, want %v", key, got, want)
		}
	}
	want := Stats{Capacity: 16, Read: 4, Removed: map[Reason]int{reasonOld: 2}, Kept: 2}
	if !stats.equal(want) {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	wantAsked := [][]Current[uint32, uint64]{
		{{Key: 1, Present: true}, {Key: 2, Present: true}},
		{{Key: 3, Present: true}, {Key: 4, Value: 50, Present: true}},
	}
	if !slices.EqualFunc(asked, wantAsked, slices.Equal) {
		t.Errorf("Confirm was asked %v, want %v: a group with no key left is not asked", asked, wantAsked)
	}
}

func TestOccupancyIsTheShareOfTheCapacityRead(t *testing.T) {
	if got := (Stats{Capacity: 200, Read: 50}).Occupancy(); got != 0.25 {
		t.Errorf("occupancy = %v, want 0.25", got)
	}
	if got := (Stats{}).Occupancy(); got != 0 {
		t.Errorf("occupancy of a map with no capacity = %v, want 0", got)
	}
}

// equal compares two Stats. The zero Removed and an empty one mean the
// same.
func (s Stats) equal(o Stats) bool {
	if s.Capacity != o.Capacity || s.Read != o.Read || s.Kept != o.Kept || len(s.Removed) != len(o.Removed) {
		return false
	}
	for reason, n := range s.Removed {
		if o.Removed[reason] != n {
			return false
		}
	}
	return true
}
