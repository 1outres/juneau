package program_test

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/l2"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// pinPathForTest is where this test pins the maps of the objects it
// loads. It has to sit on bpffs, and it must not be the path a daemon
// on this host is using.
const pinPathForTest = "/sys/fs/bpf/juneau-program-test"

// TestEveryProgramSeesTheSameL2Maps walks the sequence Manager.Start
// runs: load all four objects under one pin path, then build the
// per-VNI tables from the l2_egress specs.
//
// The L2 maps are declared in the header every program includes, so
// each object carries a definition of them. Only LIBBPF_PIN_BY_NAME
// makes those one kernel object, and getting it wrong would show up as
// a data plane where l2_egress learns into a table vxlan_ingress never
// reads.
func TestEveryProgramSeesTheSameL2Maps(t *testing.T) {
	bpftest.Require(t)

	if err := os.RemoveAll(pinPathForTest); err != nil {
		t.Fatalf("clear the pin path: %v", err)
	}
	if err := os.Mkdir(pinPathForTest, 0o700); err != nil {
		t.Skipf("cannot pin under bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinPathForTest) })

	podEgress, err := program.NewPodEgress(pinPathForTest, 0)
	if err != nil {
		t.Fatalf("load pod_egress: %+v", err)
	}
	t.Cleanup(func() { _ = podEgress.Close() })

	podIngress, err := program.NewPodIngress(pinPathForTest)
	if err != nil {
		t.Fatalf("load pod_ingress: %+v", err)
	}
	t.Cleanup(func() { _ = podIngress.Close() })

	l2Egress, err := program.NewL2Egress(pinPathForTest)
	if err != nil {
		t.Fatalf("load l2_egress: %+v", err)
	}
	t.Cleanup(func() { _ = l2Egress.Close() })

	l2Ingress, err := program.NewL2Ingress(pinPathForTest)
	if err != nil {
		t.Fatalf("load l2_ingress: %+v", err)
	}
	t.Cleanup(func() { _ = l2Ingress.Close() })

	for _, tt := range []struct {
		name    string
		handles []*ebpf.Map
	}{
		{"l2_network_map", []*ebpf.Map{podEgress.Objs.L2NetworkMap, l2Egress.Objs.L2NetworkMap, l2Ingress.Objs.L2NetworkMap}},
		{"l2_ifindex", []*ebpf.Map{podEgress.Objs.L2Ifindex, l2Egress.Objs.L2Ifindex, l2Ingress.Objs.L2Ifindex}},
		{"l2_fdb", []*ebpf.Map{podEgress.Objs.L2Fdb, l2Egress.Objs.L2Fdb}},
		{"l2_bum_local", []*ebpf.Map{podEgress.Objs.L2BumLocal, l2Egress.Objs.L2BumLocal}},
		{"l2_bum_remote", []*ebpf.Map{podEgress.Objs.L2BumRemote, l2Egress.Objs.L2BumRemote}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			want := mapID(t, tt.handles[0])
			for _, handle := range tt.handles[1:] {
				if got := mapID(t, handle); got != want {
					t.Errorf("%s is a different kernel map in each program: %d and %d", tt.name, want, got)
				}
			}
		})
	}

	fdb := l2.NewTable("fdb", l2Egress.Objs.L2Fdb, l2Egress.MapSpecs.L2FdbInner)
	local := l2.NewTable("bum-local", l2Egress.Objs.L2BumLocal, l2Egress.MapSpecs.L2BumLocalInner)
	remote := l2.NewTable("bum-remote", l2Egress.Objs.L2BumRemote, l2Egress.MapSpecs.L2BumRemoteInner)
	tables := []*l2.Table{fdb, local, remote}
	t.Cleanup(func() {
		for _, table := range tables {
			if err := table.CloseAll(); err != nil {
				t.Errorf("close the tables: %v", err)
			}
		}
	})

	for _, table := range tables {
		if err := table.Ensure(testVNI); err != nil {
			t.Fatalf("build a per-VNI table: %v", err)
		}
	}
	for _, table := range []*l2.Table{local, remote} {
		if err := table.AddMember(testVNI, 7); err != nil {
			t.Fatalf("add a member: %v", err)
		}
		if err := table.RemoveMember(testVNI, 7); err != nil {
			t.Fatalf("remove a member: %v", err)
		}
	}
	for _, table := range tables {
		if err := table.Delete(testVNI); err != nil {
			t.Fatalf("drop a per-VNI table: %v", err)
		}
	}
}

func mapID(t *testing.T, m *ebpf.Map) ebpf.MapID {
	t.Helper()
	info, err := m.Info()
	if err != nil {
		t.Fatalf("read the map info: %v", err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("the kernel reported no id for the map")
	}
	return id
}
