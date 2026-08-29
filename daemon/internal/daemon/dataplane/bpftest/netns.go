package bpftest

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Netns moves the test into a network namespace of its own and puts it
// back when the test ends.
//
// The devices a packet test builds have to be real, because
// bpf_clone_redirect looks them up by index in the namespace the
// program runs in. Building them on the host would leave interfaces
// behind on a developer's machine and would collide with a juneau
// daemon running there.
//
// BPF_PROG_TEST_RUN reads the namespace of the calling thread, so the
// goroutine is pinned to its thread for the rest of the test. Every
// netlink call and every program run below has to happen on that same
// goroutine.
func Netns(t *testing.T) {
	t.Helper()

	runtime.LockOSThread()

	previous, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("bpftest: read the current network namespace: %v", err)
	}

	fresh, err := netns.New()
	if err != nil {
		_ = previous.Close()
		runtime.UnlockOSThread()
		t.Skipf("bpftest: cannot build a network namespace: %v", err)
	}

	t.Cleanup(func() {
		if err := netns.Set(previous); err != nil {
			t.Errorf("bpftest: return to the original network namespace: %v", err)
		}
		_ = fresh.Close()
		_ = previous.Close()
		runtime.UnlockOSThread()
	})

	silenceIPv6(t)
}

// silenceIPv6 turns IPv6 off for the namespace the test just entered.
//
// A device that comes up with IPv6 on sends router solicitation and
// multicast listener reports of its own, on a timer the test does not
// control. Those land in the same send counters the flood assertions
// read, so a port nothing fed can look like a port that was fed.
//
// /proc/sys/net is per-namespace, so this reaches no device outside
// the test.
func silenceIPv6(t *testing.T) {
	t.Helper()
	for _, path := range []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
	} {
		err := os.WriteFile(path, []byte("1"), 0o644)
		if errors.Is(err, fs.ErrNotExist) {
			// A kernel built without IPv6 has nothing to silence.
			continue
		}
		if err != nil {
			t.Fatalf("bpftest: turn IPv6 off in the test namespace: %v", err)
		}
	}
}

// Device is a network device a test built.
type Device struct {
	Name  string
	Index int
}

// Dummy adds a dummy device and brings it up. A dummy counts every
// frame handed to it and then drops it, which makes it the simplest
// possible stand-in for a port: after a run, TxPackets says how many
// copies of the frame the program sent there.
func Dummy(t *testing.T, name string) Device {
	t.Helper()

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatalf("bpftest: add device %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bpftest: bring device %s up: %v", name, err)
	}

	built, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("bpftest: look up device %s: %v", name, err)
	}
	return Device{Name: name, Index: built.Attrs().Index}
}

// txCounters is how many frames the device has been handed so far and
// how many bytes they came to.
//
// The counts come over netlink and not from /sys/class/net, because
// sysfs still shows the namespace it was mounted in and the devices
// here live in a namespace made after that.
func (d Device) txCounters(t *testing.T) (packets, bytes uint64) {
	t.Helper()
	link, err := netlink.LinkByIndex(d.Index)
	if err != nil {
		t.Fatalf("bpftest: read the counters of %s: %v", d.Name, err)
	}
	stats := link.Attrs().Statistics
	if stats == nil {
		t.Fatalf("bpftest: the kernel reported no counters for %s", d.Name)
	}
	return stats.TxPackets, stats.TxBytes
}

// Ports counts the copies of a frame that reach each device.
//
// The counts are differences and never totals: a device that has just
// come up sends IPv6 discovery of its own, so a total would say a port
// was fed when nothing fed it. Take a Ports before the run and ask it
// afterwards.
type Ports struct {
	before map[int]portCounters
}

type portCounters struct {
	packets uint64
	bytes   uint64
}

// WatchPorts records where the given devices stand right now.
func WatchPorts(t *testing.T, devices ...Device) *Ports {
	t.Helper()
	p := &Ports{before: make(map[int]portCounters, len(devices))}
	for _, device := range devices {
		packets, bytes := device.txCounters(t)
		p.before[device.Index] = portCounters{packets: packets, bytes: bytes}
	}
	return p
}

// Delivered is how many frames the device has been handed since
// WatchPorts. A device that was not watched is a mistake in the test
// rather than a device with nothing delivered, so it fails.
func (p *Ports) Delivered(t *testing.T, device Device) uint64 {
	t.Helper()
	packets, _ := device.txCounters(t)
	return packets - p.watched(t, device).packets
}

// DeliveredBytes is how many bytes those frames came to. It is how a
// test reads the length of a frame a program resized: what the kernel
// copies back to the caller keeps the room the caller offered, and the
// port that took the copy is the only place the real length shows.
func (p *Ports) DeliveredBytes(t *testing.T, device Device) uint64 {
	t.Helper()
	_, bytes := device.txCounters(t)
	return bytes - p.watched(t, device).bytes
}

func (p *Ports) watched(t *testing.T, device Device) portCounters {
	t.Helper()
	before, watched := p.before[device.Index]
	if !watched {
		t.Fatalf("bpftest: %s was not watched, so nothing can be said about it", device.Name)
	}
	return before
}
