package mapinventory

import (
	"os"
	"testing"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// registerPinPath is where this test pins the maps of the object it
// loads. It has to sit on bpffs, and it must not be the path a daemon
// on this host is using.
const registerPinPath = "/sys/fs/bpf/juneau-mapinventory-test"

// Register checks every descriptor against the live map, and the
// daemon refuses to start when one does not match. This runs that
// check against the maps the daemon really loads.
func TestRegisterPodEgressAcceptsTheLoadedMaps(t *testing.T) {
	bpftest.Require(t)

	if err := os.RemoveAll(registerPinPath); err != nil {
		t.Fatalf("clear the pin path: %v", err)
	}
	if err := os.Mkdir(registerPinPath, 0o700); err != nil {
		t.Skipf("cannot pin under bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(registerPinPath) })

	podEgress, err := program.NewPodEgress(registerPinPath, 0)
	if err != nil {
		t.Fatalf("load pod_egress: %+v", err)
	}
	t.Cleanup(func() { _ = podEgress.Close() })

	inv := NewInventory()
	if err := RegisterPodEgress(inv, podEgress); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := inv.Lookup("policy_ct_stats"); err != nil {
		t.Errorf("policy_ct_stats is not in the inventory: %v", err)
	}
}
