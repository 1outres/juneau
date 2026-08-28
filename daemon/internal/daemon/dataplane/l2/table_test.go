package l2

import (
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

const arpTestVNI = 4242

// newArpTable builds a real l2_arp out of the generated layout. The
// guarantees under test are about what the kernel does with
// BPF_NOEXIST and about comparing a value read back out of a map, so a
// fake would only prove that the fake agrees with itself.
func newArpTable(t *testing.T) *Table {
	t.Helper()
	bpftest.Require(t)

	spec, err := bpf.LoadL2Egress()
	if err != nil {
		t.Fatalf("read the l2_egress object: %v", err)
	}

	innerSpec := spec.Maps["l2_arp_inner"].Copy()
	innerSpec.Pinning = ebpf.PinNone
	outerSpec := spec.Maps["l2_arp"].Copy()
	outerSpec.Pinning = ebpf.PinNone
	outerSpec.InnerMap = innerSpec.Copy()

	outer, err := ebpf.NewMap(outerSpec)
	if err != nil {
		t.Fatalf("build l2_arp: %v", err)
	}
	t.Cleanup(func() { _ = outer.Close() })

	table := NewTable("arp", outer, innerSpec)
	t.Cleanup(func() {
		if err := table.CloseAll(); err != nil {
			t.Errorf("close the tables: %v", err)
		}
	})
	if err := table.Ensure(arpTestVNI); err != nil {
		t.Fatalf("build the table of VNI %d: %v", arpTestVNI, err)
	}
	return table
}

func arpKey(address uint32) bpf.PodEgressL2ArpKey { return bpf.PodEgressL2ArpKey{Ipv4: address} }

func arpVal(last uint8) bpf.PodEgressL2ArpVal {
	return bpf.PodEgressL2ArpVal{Mac: [6]uint8{0x02, 0, 0, 0, 0, last}}
}

func arpLookup(t *testing.T, table *Table, key bpf.PodEgressL2ArpKey) (bpf.PodEgressL2ArpVal, bool) {
	t.Helper()
	var (
		val   bpf.PodEgressL2ArpVal
		found bool
	)
	table.ForEachInner(func(vni uint32, inner *ebpf.Map) {
		if vni != arpTestVNI {
			return
		}
		found = inner.Lookup(&key, &val) == nil
	})
	return val, found
}

func TestPutIfAbsentWritesWhereNothingIsHeld(t *testing.T) {
	table := newArpTable(t)

	if err := table.PutIfAbsent(arpTestVNI, arpKey(1), arpVal(1)); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}

	got, ok := arpLookup(t, table, arpKey(1))
	if !ok {
		t.Fatal("nothing was written")
	}
	if got != arpVal(1) {
		t.Errorf("wrote %v, want %v", got, arpVal(1))
	}
}

// The whole point of the pair: an offer from user space never wins over
// what the data plane recorded.
func TestPutIfAbsentLeavesWhatIsAlreadyHeld(t *testing.T) {
	table := newArpTable(t)

	if err := table.Put(arpTestVNI, arpKey(1), arpVal(9)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := table.PutIfAbsent(arpTestVNI, arpKey(1), arpVal(1)); err != nil {
		t.Fatalf("PutIfAbsent over a held key reported an error: %v", err)
	}

	got, _ := arpLookup(t, table, arpKey(1))
	if got != arpVal(9) {
		t.Errorf("the key holds %v, want the %v that was there", got, arpVal(9))
	}
}

func TestRemoveIfEqualTakesBackWhatItWrote(t *testing.T) {
	table := newArpTable(t)

	if err := table.PutIfAbsent(arpTestVNI, arpKey(1), arpVal(1)); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}
	if err := table.RemoveIfEqual(arpTestVNI, arpKey(1), arpVal(1)); err != nil {
		t.Fatalf("RemoveIfEqual: %v", err)
	}

	if _, ok := arpLookup(t, table, arpKey(1)); ok {
		t.Error("the entry is still there")
	}
}

func TestRemoveIfEqualLeavesWhatSomebodyElseWrote(t *testing.T) {
	table := newArpTable(t)

	if err := table.Put(arpTestVNI, arpKey(1), arpVal(9)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := table.RemoveIfEqual(arpTestVNI, arpKey(1), arpVal(1)); err != nil {
		t.Fatalf("RemoveIfEqual: %v", err)
	}

	got, ok := arpLookup(t, table, arpKey(1))
	if !ok {
		t.Fatal("an entry nobody claimed was removed")
	}
	if got != arpVal(9) {
		t.Errorf("the key holds %v, want %v", got, arpVal(9))
	}
}

func TestRemoveIfEqualIsFineWithAKeyThatIsGone(t *testing.T) {
	table := newArpTable(t)

	if err := table.RemoveIfEqual(arpTestVNI, arpKey(1), arpVal(1)); err != nil {
		t.Errorf("RemoveIfEqual on a missing key: %v", err)
	}
	if err := table.RemoveIfEqual(9999, arpKey(1), arpVal(1)); err != nil {
		t.Errorf("RemoveIfEqual on a VNI with no table: %v", err)
	}
}
