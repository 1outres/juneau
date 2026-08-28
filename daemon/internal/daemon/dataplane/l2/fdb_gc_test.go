package l2

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

const gcTestVNI = 4242

// newGCTable builds a real l2_fdb out of the generated layout. The
// sweep reads entries back out of a map, so a fake would only prove
// that the fake works; a real map needs CAP_BPF.
func newGCTable(t *testing.T) *Table {
	t.Helper()
	bpftest.Require(t)

	spec, err := bpf.LoadL2Egress()
	if err != nil {
		t.Fatalf("read the l2_egress object: %v", err)
	}

	innerSpec := spec.Maps["l2_fdb_inner"].Copy()
	innerSpec.Pinning = ebpf.PinNone
	outerSpec := spec.Maps["l2_fdb"].Copy()
	outerSpec.Pinning = ebpf.PinNone
	outerSpec.InnerMap = innerSpec.Copy()

	outer, err := ebpf.NewMap(outerSpec)
	if err != nil {
		t.Fatalf("build l2_fdb: %v", err)
	}
	t.Cleanup(func() { _ = outer.Close() })

	table := NewTable("fdb", outer, innerSpec)
	t.Cleanup(func() {
		if err := table.CloseAll(); err != nil {
			t.Errorf("close the tables: %v", err)
		}
	})
	if err := table.Ensure(gcTestVNI); err != nil {
		t.Fatalf("build the table of VNI %d: %v", gcTestVNI, err)
	}
	return table
}

// withInner runs fn against the inner map of gcTestVNI. Table hands
// its inner maps out only while it holds its own lock.
func withInner(t *testing.T, table *Table, fn func(inner *ebpf.Map)) {
	t.Helper()
	found := false
	table.ForEachInner(func(vni uint32, inner *ebpf.Map) {
		if vni != gcTestVNI {
			return
		}
		found = true
		fn(inner)
	})
	if !found {
		t.Fatalf("the table has no inner map for VNI %d", gcTestVNI)
	}
}

func writeEntry(t *testing.T, table *Table, last byte, lastSeenNs uint64) bpf.PodEgressL2FdbKey {
	t.Helper()
	key := bpf.PodEgressL2FdbKey{Mac: [6]uint8{0x02, 0, 0, 0, 0, last}}
	withInner(t, table, func(inner *ebpf.Map) {
		err := inner.Update(
			&key,
			&bpf.PodEgressL2FdbVal{Ifindex: uint32(last), LastSeenNs: lastSeenNs},
			ebpf.UpdateAny,
		)
		if err != nil {
			t.Fatalf("write a forwarding entry: %v", err)
		}
	})
	return key
}

func has(t *testing.T, table *Table, key bpf.PodEgressL2FdbKey) bool {
	t.Helper()
	found := false
	withInner(t, table, func(inner *ebpf.Map) {
		var val bpf.PodEgressL2FdbVal
		found = inner.Lookup(&key, &val) == nil
	})
	return found
}

func TestFdbGCDropsWhatHasNotBeenSeenForTheAgingTime(t *testing.T) {
	table := newGCTable(t)

	const now = uint64(10 * time.Hour)
	fresh := writeEntry(t, table, 1, now-uint64(10*time.Second))
	stale := writeEntry(t, table, 2, now-uint64(FdbAging)-1)
	exactlyAtTheLimit := writeEntry(t, table, 3, now-uint64(FdbAging))

	gc := NewFdbGC(table, FdbAging, FdbGCInterval)
	gc.now = func() uint64 { return now }
	gc.Sweep()

	if !has(t, table, fresh) {
		t.Error("the sweep dropped an entry that was seen ten seconds ago")
	}
	if has(t, table, stale) {
		t.Error("the sweep kept an entry older than the aging time")
	}
	if has(t, table, exactlyAtTheLimit) {
		t.Error("the sweep kept an entry that reached the aging time exactly")
	}
}

// The data plane refreshes an entry while the sweep walks the table,
// so a stamp can be newer than the clock the sweep read. That entry is
// in use by definition.
func TestFdbGCKeepsAnEntryStampedAfterItReadTheClock(t *testing.T) {
	table := newGCTable(t)

	const now = uint64(10 * time.Hour)
	refreshed := writeEntry(t, table, 1, now+uint64(time.Second))

	gc := NewFdbGC(table, FdbAging, FdbGCInterval)
	gc.now = func() uint64 { return now }
	gc.Sweep()

	if !has(t, table, refreshed) {
		t.Error("the sweep dropped an entry the data plane had just refreshed")
	}
}

func TestFdbGCLeavesANetworkItHoldsNoTableFor(t *testing.T) {
	table := newGCTable(t)

	gc := NewFdbGC(table, FdbAging, FdbGCInterval)
	gc.now = func() uint64 { return uint64(10 * time.Hour) }
	if err := table.Delete(gcTestVNI); err != nil {
		t.Fatalf("drop the table: %v", err)
	}

	// The sweep walks the tables it holds, so a network that is gone is
	// simply not walked. This asserts it does not reach for one.
	gc.Sweep()
}
