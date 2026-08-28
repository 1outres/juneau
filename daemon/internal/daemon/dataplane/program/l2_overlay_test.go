package program_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

// vxlanPort is the port the overlay listens on, and loopbackVTEP is
// the address a frame in these tests appears to come from: the test
// sends the encapsulated frame to itself, so the node that holds the
// source MAC is this one.
const (
	vxlanPort    = 4789
	loopbackVTEP = "127.0.0.1"
)

// overlaySegment is one L2Network reached over a real VXLAN device.
//
// The from-overlay path cannot be driven with BPF_PROG_TEST_RUN: the
// program reads the tunnel key off the frame, and a frame the test
// hands straight to the program carries none. So the test builds the
// tunnel the kernel would build, attaches the program where the daemon
// attaches it, and sends a real encapsulated frame to itself. What
// comes out is the same skb the data plane sees in production, tunnel
// metadata and all — and because this is a real attach and not a test
// run, bpf_redirect really carries the frame to the port it names.
type overlaySegment struct {
	segment *l2Segment
	vxlan   bpftest.Device
	pod2    bpftest.Device
	pod3    bpftest.Device
}

func newOverlaySegment(t *testing.T) *overlaySegment {
	t.Helper()
	bpftest.Require(t)
	bpftest.Netns(t)

	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("look up the loopback device: %v", err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		t.Fatalf("bring the loopback device up: %v", err)
	}

	device := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{Name: "vxlan0"},
		VxlanId:   0,
		Port:      vxlanPort,
		FlowBased: true,
	}
	if err := netlink.LinkAdd(device); err != nil {
		t.Skipf("cannot build a VXLAN device here: %v", err)
	}
	if err := netlink.LinkSetUp(device); err != nil {
		t.Fatalf("bring the VXLAN device up: %v", err)
	}
	built, err := netlink.LinkByName("vxlan0")
	if err != nil {
		t.Fatalf("look up the VXLAN device: %v", err)
	}

	segment := newL2Segment(t, bpf.LoadVxlanIngress)
	overlay := &overlaySegment{
		segment: segment,
		vxlan:   bpftest.Device{Name: "vxlan0", Index: built.Attrs().Index},
		pod2:    bpftest.Dummy(t, "pod2"),
		pod3:    bpftest.Dummy(t, "pod3"),
	}
	segment.addLocalPort(t, overlay.pod2)
	segment.addLocalPort(t, overlay.pod3)
	segment.useTunnelDevice(t, overlay.vxlan)

	attached, err := ebpflink.AttachTCX(ebpflink.TCXOptions{
		Program:   segment.objs.Program(t, "tc_vxlan_ingress_entry"),
		Interface: overlay.vxlan.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		t.Fatalf("attach the program to the VXLAN device: %v", err)
	}
	t.Cleanup(func() { _ = attached.Close() })

	return overlay
}

// deliver sends one frame over the overlay as another node would. The
// datagram goes to this host, so the program sees loopbackVTEP as the
// node that holds the source MAC.
func (o *overlaySegment) deliver(t *testing.T, vni uint32, frame []byte) {
	t.Helper()

	conn, err := net.Dial("udp", net.JoinHostPort(loopbackVTEP, "4789"))
	if err != nil {
		t.Fatalf("open the overlay socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// VXLAN header: the I flag says the VNI field is valid, and the VNI
	// sits in the top 24 bits of the second word.
	header := make([]byte, 8)
	header[0] = 0x08
	binary.BigEndian.PutUint32(header[4:8], vni<<8)

	if _, err := conn.Write(append(header, frame...)); err != nil {
		t.Fatalf("send the encapsulated frame: %v", err)
	}
}

// awaitLearned waits for the segment to learn a MAC. Delivery happens
// in a softirq after the write returns, so the test cannot read the
// table right away.
func (o *overlaySegment) awaitLearned(t *testing.T, mac net.HardwareAddr) bpf.PodEgressL2FdbVal {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if entry, ok := o.segment.lookup(t, mac); ok {
			return entry
		}
		if time.Now().After(deadline) {
			t.Fatalf("the segment never learned %s from the overlay", mac)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestVxlanIngressLearnsWhichNodeHoldsAMac(t *testing.T) {
	overlay := newOverlaySegment(t)
	sender := bpftest.MAC(1)

	frame := bpftest.Frame(t, bpftest.Broadcast, sender, bpftest.EtherTypeARP, nil)
	overlay.deliver(t, testVNI, frame)

	entry := overlay.awaitLearned(t, sender)
	if entry.Ifindex != 0 {
		t.Errorf("learned %s on ifindex %d, want a remote node", sender, entry.Ifindex)
	}
	if want := hostOrderIPv4(t, loopbackVTEP); entry.VtepIp != want {
		t.Errorf("learned %s behind vtep %d, want %d", sender, entry.VtepIp, want)
	}
}

// A frame that came in over the overlay is copied to the local ports
// and to nothing else. The node that sent it has already given every
// other node a copy, so sending it back out would multiply it without
// end. This is split horizon, and it is the one rule that keeps a
// broadcast on an L2Network from taking the segment down.
func TestVxlanIngressFloodsLocallyAndNeverBackOverTheOverlay(t *testing.T) {
	overlay := newOverlaySegment(t)
	overlay.segment.addRemoteNode(t, "10.0.0.2")
	overlay.segment.addRemoteNode(t, "10.0.0.3")

	sender := bpftest.MAC(1)
	frame := bpftest.Frame(t, bpftest.Broadcast, sender, bpftest.EtherTypeARP, nil)
	watched := bpftest.WatchPorts(t, overlay.pod2, overlay.pod3, overlay.vxlan)
	overlay.deliver(t, testVNI, frame)
	overlay.awaitLearned(t, sender)

	for _, device := range []bpftest.Device{overlay.pod2, overlay.pod3} {
		if got := watched.Delivered(t, device); got != 1 {
			t.Errorf("%s received %d copies of the broadcast, want 1", device.Name, got)
		}
	}
	if got := watched.Delivered(t, overlay.vxlan); got != 0 {
		t.Errorf("the overlay carried the frame back out %d times, want 0", got)
	}
}

func TestVxlanIngressSendsAKnownUnicastToItsLocalPort(t *testing.T) {
	overlay := newOverlaySegment(t)
	sender, peer := bpftest.MAC(1), bpftest.MAC(2)
	overlay.segment.learn(t, peer, uint32(overlay.pod2.Index), "")

	frame := bpftest.Frame(t, peer, sender, bpftest.EtherTypeIPv4, nil)
	watched := bpftest.WatchPorts(t, overlay.pod2, overlay.pod3, overlay.vxlan)
	overlay.deliver(t, testVNI, frame)
	overlay.awaitLearned(t, sender)

	if got := watched.Delivered(t, overlay.pod2); got != 1 {
		t.Errorf("pod2 holds the destination MAC but received %d frames, want 1", got)
	}
	if got := watched.Delivered(t, overlay.pod3); got != 0 {
		t.Errorf("pod3 received %d copies of a frame it does not hold the MAC for", got)
	}
}

// A frame the overlay delivered is never put back on it, not even when
// this node knows the destination MAC lives on a third node. The node
// that sent it reaches that node directly, so relaying would send the
// frame over the overlay twice and teach the far node that the source
// MAC lives behind this one.
func TestVxlanIngressNeverRelaysToAnotherNode(t *testing.T) {
	overlay := newOverlaySegment(t)
	sender, peer := bpftest.MAC(1), bpftest.MAC(2)
	overlay.segment.learn(t, peer, 0, "10.0.0.3")

	frame := bpftest.Frame(t, peer, sender, bpftest.EtherTypeIPv4, nil)
	watched := bpftest.WatchPorts(t, overlay.pod2, overlay.pod3, overlay.vxlan)
	overlay.deliver(t, testVNI, frame)
	overlay.awaitLearned(t, sender)

	if got := watched.Delivered(t, overlay.vxlan); got != 0 {
		t.Errorf("the overlay carried the frame on to a third node %d times, want 0", got)
	}
	// With nowhere local to place it, the frame takes the same path as
	// any unicast the segment cannot resolve.
	for _, device := range []bpftest.Device{overlay.pod2, overlay.pod3} {
		if got := watched.Delivered(t, device); got != 1 {
			t.Errorf("%s received %d copies, want the local flood to reach it once", device.Name, got)
		}
	}
}

// Every node that holds a port on a segment runs a gateway of its own,
// on the same address and the same MAC, so a broadcast the overlay
// delivered has already been offered to a gateway on the node it
// started from. Offering it to this one as well would answer a single
// ARP once per node in the cluster.
func TestVxlanIngressSkipsTheGatewayForAFrameFromTheOverlay(t *testing.T) {
	overlay := newOverlaySegment(t)
	overlay.segment.addGatewayPort(t, overlay.pod3, bpftest.MAC(0xfe))

	sender := bpftest.MAC(1)
	frame := bpftest.Frame(t, bpftest.Broadcast, sender, bpftest.EtherTypeARP, nil)
	watched := bpftest.WatchPorts(t, overlay.pod2, overlay.pod3)
	overlay.deliver(t, testVNI, frame)
	overlay.awaitLearned(t, sender)

	if got := watched.Delivered(t, overlay.pod2); got != 1 {
		t.Errorf("pod2 received %d copies of the broadcast, want 1", got)
	}
	if got := watched.Delivered(t, overlay.pod3); got != 0 {
		t.Errorf("the gateway received %d copies of a broadcast another node already offered it one of", got)
	}
}

// The gateway does read the ARP the overlay brings in. A host on
// another node announces itself to the whole segment, and that is the
// only way this node ever learns which MAC owns its address.
func TestVxlanIngressRecordsTheSenderOfAnArpFromAnotherNode(t *testing.T) {
	overlay := newOverlaySegment(t)
	sender := bpftest.MAC(1)

	frame := bpftest.Frame(t, bpftest.Broadcast, sender, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, sender, "10.60.0.7",
			net.HardwareAddr{0, 0, 0, 0, 0, 0}, "10.60.0.1"))
	overlay.deliver(t, testVNI, frame)
	overlay.awaitLearned(t, sender)

	got, ok := overlay.segment.resolved(t, "10.60.0.7")
	if !ok {
		t.Fatal("the segment did not record the sender of the request")
	}
	if !bytes.Equal(got, sender) {
		t.Errorf("recorded 10.60.0.7 as %s, want %s", got, sender)
	}
}
