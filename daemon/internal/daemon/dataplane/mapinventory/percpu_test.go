package mapinventory

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

func newPerCPUArray(t *testing.T, valueSize uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  valueSize,
		MaxEntries: 2,
	})
	if err != nil {
		t.Skipf("ebpf.NewMap unavailable on this host: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func counterDescriptor(m *ebpf.Map) *Descriptor {
	return &Descriptor{
		Name:  "counters",
		Map:   m,
		Key:   Schema{Fields: []Field{FieldU32Named("slot")}},
		Value: Schema{Fields: []Field{FieldU64Named("count")}},
	}
}

// A per-CPU map holds one value for each CPU, and a dump shows their
// sum: that is the count a reader is after.
func TestDumpAddsUpTheValuesOfEveryCPU(t *testing.T) {
	m := newPerCPUArray(t, 8)
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("count the CPUs: %v", err)
	}
	perCPU := make([]uint64, cpus)
	for i := range perCPU {
		perCPU[i] = uint64(i + 1)
	}
	if err := m.Update(uint32(1), perCPU, ebpf.UpdateAny); err != nil {
		t.Fatalf("write slot 1: %v", err)
	}
	want := uint64(cpus * (cpus + 1) / 2)

	d := counterDescriptor(m)
	if err := NewInventory().Register(d); err != nil {
		t.Fatalf("register: %v", err)
	}

	counts := make(map[uint64]uint64)
	err = DumpMap(context.Background(), d, DumpOptions{}, func(e *debugpb.BPFMapEntry) error {
		counts[e.Key[0].GetU64()] = e.Value[0].GetU64()
		return nil
	})
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if got := counts[1]; got != want {
		t.Errorf("slot 1 dumps as %d, want the sum %d", got, want)
	}
	if got, ok := counts[0]; !ok || got != 0 {
		t.Errorf("slot 0 dumps as %d (present=%v), want 0", got, ok)
	}

	var looked uint64
	err = DumpMap(context.Background(), d, DumpOptions{
		KeyFilter: []*debugpb.BPFMapField{{Name: "slot", Value: &debugpb.BPFMapField_U64{U64: 1}}},
	}, func(e *debugpb.BPFMapEntry) error {
		looked = e.Value[0].GetU64()
		return nil
	})
	if err != nil {
		t.Fatalf("dump one slot: %v", err)
	}
	if looked != want {
		t.Errorf("looking slot 1 up dumps %d, want the sum %d", looked, want)
	}
}

// A sum only means something for a counter, so a per-CPU map whose
// value is anything else is refused at startup.
func TestRegisterRefusesAPerCPUValueThatIsNotCounters(t *testing.T) {
	m := newPerCPUArray(t, 8)
	d := counterDescriptor(m)
	d.Value = Schema{Fields: []Field{FieldU32Named("a"), FieldU32Named("b")}}

	if err := NewInventory().Register(d); !errors.Is(err, ErrPerCPUValue) {
		t.Errorf("register = %v, want %v", err, ErrPerCPUValue)
	}
}
