package grpc

import (
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// enterTestNetns moves the test into a network namespace of its own and
// puts it back when the test ends, so the links and routes a test builds
// never reach the host. It skips where this process may not build a
// namespace; `unshare -rn go test` gives an unprivileged user one.
//
// Netlink talks to the namespace of the calling thread, so the goroutine
// stays on its thread for the rest of the test.
func enterTestNetns(t *testing.T) {
	t.Helper()

	runtime.LockOSThread()

	previous, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("read the current network namespace: %v", err)
	}

	fresh, err := netns.New()
	if err != nil {
		_ = previous.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot build a network namespace: %v", err)
	}

	t.Cleanup(func() {
		if err := netns.Set(previous); err != nil {
			t.Errorf("return to the original network namespace: %v", err)
		}
		_ = fresh.Close()
		_ = previous.Close()
		runtime.UnlockOSThread()
	})
}

// addTestLink adds a dummy link and brings it up.
func addTestLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		t.Fatalf("add link %s: %v", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("look up link %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bring link %s up: %v", name, err)
	}
	return link
}
