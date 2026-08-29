package program_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

// l2EgressPorts is one segment with three local ports and a stand-in
// for the tunnel device, which is what most of the tests below need.
type l2EgressPorts struct {
	segment *l2Segment
	program *ebpf.Program
	pod1    bpftest.Device
	pod2    bpftest.Device
	pod3    bpftest.Device
	tunnel  bpftest.Device
}

func newL2EgressPorts(t *testing.T) *l2EgressPorts {
	t.Helper()
	bpftest.Require(t)
	bpftest.Netns(t)

	segment := newL2Segment(t, bpf.LoadL2Egress)
	ports := &l2EgressPorts{
		segment: segment,
		program: segment.objs.Program(t, "tc_l2_egress"),
		pod1:    bpftest.Dummy(t, "pod1"),
		pod2:    bpftest.Dummy(t, "pod2"),
		pod3:    bpftest.Dummy(t, "pod3"),
		tunnel:  bpftest.Dummy(t, "overlay0"),
	}
	for _, device := range []bpftest.Device{ports.pod1, ports.pod2, ports.pod3} {
		segment.addLocalPort(t, device)
	}
	segment.useTunnelDevice(t, ports.tunnel)
	return ports
}

// watch records where every device of the segment stands, so the
// assertions afterwards read the copies of this one frame.
func (p *l2EgressPorts) watch(t *testing.T) *bpftest.Ports {
	t.Helper()
	return bpftest.WatchPorts(t, p.pod1, p.pod2, p.pod3, p.tunnel)
}

func TestL2EgressLearnsWhoeverSendsAFrame(t *testing.T) {
	ports := newL2EgressPorts(t)
	sender := bpftest.MAC(1)

	frame := bpftest.Frame(t, bpftest.Broadcast, sender, bpftest.EtherTypeARP, nil)
	bpftest.Run(t, ports.program, frame, ports.pod1)

	entry, ok := ports.segment.lookup(t, sender)
	if !ok {
		t.Fatalf("the segment did not learn %s", sender)
	}
	if entry.Ifindex != uint32(ports.pod1.Index) {
		t.Errorf("learned %s on ifindex %d, want %d", sender, entry.Ifindex, ports.pod1.Index)
	}
	if entry.VtepIp != 0 {
		t.Errorf("learned %s with vtep %d, want a local port", sender, entry.VtepIp)
	}
	if entry.LastSeenNs == 0 {
		t.Error("learned an entry with no timestamp, so it can never age out")
	}
}

// A workload may put any MAC in a frame: an L2Network is a segment the
// user builds, and a bridge or a nested VM behind the NIC has to be
// able to speak for itself. The data plane learns whatever it sees.
func TestL2EgressLearnsAMacTheNicDoesNotOwn(t *testing.T) {
	ports := newL2EgressPorts(t)
	behindABridge := net.HardwareAddr{0x0a, 0xbc, 0xde, 0xf0, 0x12, 0x34}

	frame := bpftest.Frame(t, bpftest.Broadcast, behindABridge, bpftest.EtherTypeARP, nil)
	bpftest.Run(t, ports.program, frame, ports.pod1)

	if _, ok := ports.segment.lookup(t, behindABridge); !ok {
		t.Fatalf("the segment refused to learn %s", behindABridge)
	}
}

func TestL2EgressFollowsAMacThatMovesToAnotherPort(t *testing.T) {
	ports := newL2EgressPorts(t)
	mover := bpftest.MAC(1)

	frame := bpftest.Frame(t, bpftest.Broadcast, mover, bpftest.EtherTypeARP, nil)
	bpftest.Run(t, ports.program, frame, ports.pod1)
	bpftest.Run(t, ports.program, frame, ports.pod2)

	entry, ok := ports.segment.lookup(t, mover)
	if !ok {
		t.Fatalf("the segment lost %s after it moved", mover)
	}
	if entry.Ifindex != uint32(ports.pod2.Index) {
		t.Errorf("after the move %s is on ifindex %d, want %d", mover, entry.Ifindex, ports.pod2.Index)
	}
}

func TestL2EgressSendsAKnownUnicastToItsPortAlone(t *testing.T) {
	ports := newL2EgressPorts(t)
	sender, peer := bpftest.MAC(1), bpftest.MAC(2)
	ports.segment.learn(t, peer, uint32(ports.pod2.Index), "")

	frame := bpftest.Frame(t, peer, sender, bpftest.EtherTypeIPv4, nil)
	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, frame, ports.pod1)

	if verdict != bpftest.ActRedirect {
		t.Errorf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	// A redirect is not carried out under BPF_PROG_TEST_RUN, so the
	// proof that the frame was not flooded is that no port was fed.
	for _, device := range []bpftest.Device{ports.pod2, ports.pod3, ports.tunnel} {
		if got := watched.Delivered(t, device); got != 0 {
			t.Errorf("%s received %d copies of a known unicast, want none", device.Name, got)
		}
	}
}

func TestL2EgressSendsAKnownUnicastForAnotherNodeToTheTunnel(t *testing.T) {
	ports := newL2EgressPorts(t)
	sender, peer := bpftest.MAC(1), bpftest.MAC(2)
	ports.segment.learn(t, peer, 0, "10.0.0.9")

	frame := bpftest.Frame(t, peer, sender, bpftest.EtherTypeIPv4, nil)
	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, frame, ports.pod1)

	if verdict != bpftest.ActRedirect {
		t.Errorf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
		if got := watched.Delivered(t, device); got != 0 {
			t.Errorf("%s received %d copies of a frame bound for another node", device.Name, got)
		}
	}
}

func TestL2EgressCopiesABumFrameToEveryOtherLocalPort(t *testing.T) {
	sender := bpftest.MAC(1)
	unknownPeer := bpftest.MAC(9)

	for _, tt := range []struct {
		name string
		dst  net.HardwareAddr
	}{
		{name: "broadcast", dst: bpftest.Broadcast},
		{name: "unknown unicast", dst: unknownPeer},
		{name: "ipv4 multicast", dst: bpftest.MulticastIPv4},
		{name: "ipv6 multicast", dst: bpftest.MulticastIPv6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ports := newL2EgressPorts(t)

			frame := bpftest.Frame(t, tt.dst, sender, bpftest.EtherTypeIPv4, nil)
			watched := ports.watch(t)
			verdict := bpftest.Run(t, ports.program, frame, ports.pod1)

			// Every port that had to see the frame got a copy of its
			// own, so the frame the copies were made from is done.
			if verdict != bpftest.ActShot {
				t.Errorf("verdict %d, want the original to be dropped (%d)", verdict, bpftest.ActShot)
			}
			for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
				if got := watched.Delivered(t, device); got != 1 {
					t.Errorf("%s received %d copies, want 1", device.Name, got)
				}
			}
			if got := watched.Delivered(t, ports.pod1); got != 0 {
				t.Errorf("the frame came back out of the port it came in on %d times", got)
			}
		})
	}
}

func TestL2EgressCopiesABumFrameToEveryRemoteNode(t *testing.T) {
	ports := newL2EgressPorts(t)
	ports.segment.addRemoteNode(t, "10.0.0.2")
	ports.segment.addRemoteNode(t, "10.0.0.3")

	frame := bpftest.Frame(t, bpftest.Broadcast, bpftest.MAC(1), bpftest.EtherTypeARP, nil)
	watched := ports.watch(t)
	bpftest.Run(t, ports.program, frame, ports.pod1)

	if got := watched.Delivered(t, ports.tunnel); got != 2 {
		t.Errorf("the tunnel carried %d copies, want one per remote node (2)", got)
	}
}

func TestL2EgressKeepsABumFrameLocalWhenNoNodeHoldsAPort(t *testing.T) {
	ports := newL2EgressPorts(t)

	frame := bpftest.Frame(t, bpftest.Broadcast, bpftest.MAC(1), bpftest.EtherTypeARP, nil)
	watched := ports.watch(t)
	bpftest.Run(t, ports.program, frame, ports.pod1)

	if got := watched.Delivered(t, ports.tunnel); got != 0 {
		t.Errorf("the tunnel carried %d copies with no remote node on the segment", got)
	}
	if got := watched.Delivered(t, ports.pod2); got != 1 {
		t.Errorf("pod2 received %d copies, want 1", got)
	}
}

// An L2Network carries whatever the workload puts on it. Nothing in
// the forwarding path reads past the Ethernet header, so a frame that
// is not IPv4 travels exactly like one that is.
func TestL2EgressCarriesAnyEtherType(t *testing.T) {
	for _, tt := range []struct {
		name      string
		etherType uint16
	}{
		{name: "arp", etherType: bpftest.EtherTypeARP},
		{name: "ipv6", etherType: bpftest.EtherTypeIPv6},
		{name: "an ethertype juneau has never heard of", etherType: 0x88b5},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ports := newL2EgressPorts(t)

			frame := bpftest.Frame(t, bpftest.Broadcast, bpftest.MAC(1), tt.etherType, nil)
			watched := ports.watch(t)
			bpftest.Run(t, ports.program, frame, ports.pod1)

			if got := watched.Delivered(t, ports.pod2); got != 1 {
				t.Errorf("pod2 received %d copies of an ethertype %#04x frame, want 1", got, tt.etherType)
			}
		})
	}
}

// A veth that carries the program but that no L2Network claims yet is
// a segment that is not ready. Passing the frame on would put workload
// traffic on the host stack.
func TestL2EgressDropsAFrameFromAPortNoNetworkClaims(t *testing.T) {
	bpftest.Require(t)
	bpftest.Netns(t)

	segment := newL2Segment(t, bpf.LoadL2Egress)
	program := segment.objs.Program(t, "tc_l2_egress")
	stranger := bpftest.Dummy(t, "stranger")
	peer := bpftest.Dummy(t, "pod2")
	segment.addLocalPort(t, peer)

	frame := bpftest.Frame(t, bpftest.Broadcast, bpftest.MAC(1), bpftest.EtherTypeARP, nil)
	watched := bpftest.WatchPorts(t, peer)
	verdict := bpftest.Run(t, program, frame, stranger)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want the frame dropped (%d)", verdict, bpftest.ActShot)
	}
	if got := watched.Delivered(t, peer); got != 0 {
		t.Errorf("pod2 received %d copies from a port that is on no segment", got)
	}
}

func TestL2EgressDropsAFrameOfANetworkThatIsGone(t *testing.T) {
	bpftest.Require(t)
	bpftest.Netns(t)

	segment := newL2Segment(t, bpf.LoadL2Egress)
	program := segment.objs.Program(t, "tc_l2_egress")
	pod := bpftest.Dummy(t, "pod1")
	segment.addLocalPort(t, pod)

	if err := segment.objs.Map(t, "l2_network_map").Delete(
		&bpf.PodEgressL2NetworkKey{Vni: testVNI},
	); err != nil {
		t.Fatalf("delete the L2Network: %v", err)
	}

	frame := bpftest.Frame(t, bpftest.Broadcast, bpftest.MAC(1), bpftest.EtherTypeARP, nil)
	if verdict := bpftest.Run(t, program, frame, pod); verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want the frame dropped (%d)", verdict, bpftest.ActShot)
	}
}

// A switch never sends a frame back out of the port it came in on. A
// workload running its own bridge behind the NIC would hand it right
// back, and the two would trade the frame until one of them gave up.
func TestL2EgressDropsAFrameAimedAtItsOwnPort(t *testing.T) {
	ports := newL2EgressPorts(t)
	sender, peerBehindTheSameNIC := bpftest.MAC(1), bpftest.MAC(2)
	ports.segment.learn(t, peerBehindTheSameNIC, uint32(ports.pod1.Index), "")

	frame := bpftest.Frame(t, peerBehindTheSameNIC, sender, bpftest.EtherTypeIPv4, nil)
	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, frame, ports.pod1)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want the frame dropped (%d)", verdict, bpftest.ActShot)
	}
	for _, device := range []bpftest.Device{ports.pod1, ports.pod2, ports.pod3, ports.tunnel} {
		if got := watched.Delivered(t, device); got != 0 {
			t.Errorf("%s received %d copies of a frame aimed back at its source port", device.Name, got)
		}
	}
}

// The gateway hop count juneau keeps in skb->mark. Mirrors
// L2_MARK_GW_HOP_* and L2_GW_MAX_HOPS in daemon/bpf/maps.h.
const (
	gatewayHopShift = 24
	gatewayHopMask  = 0x0f000000
	maxGatewayHops  = 4
)

func gatewayHops(mark uint32) uint32 { return (mark & gatewayHopMask) >> gatewayHopShift }

func markWithHops(hops uint32) uint32 { return hops << gatewayHopShift }

// The gateway has no way of its own to learn which MAC owns which
// address: it never sends an ARP request, because answering one on
// behalf of a host would break the DHCP server, the router and the
// duplicate-address probes a segment is built to carry. So it reads the
// ARP that crosses the segment anyway.
func TestL2EgressRecordsTheSenderOfAnArpRequest(t *testing.T) {
	ports := newL2EgressPorts(t)
	sender := bpftest.MAC(1)

	frame := bpftest.Frame(t, bpftest.Broadcast, sender, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, sender, "10.60.0.7", net.HardwareAddr{0, 0, 0, 0, 0, 0}, "10.60.0.1"))
	bpftest.Run(t, ports.program, frame, ports.pod1)

	got, ok := ports.segment.resolved(t, "10.60.0.7")
	if !ok {
		t.Fatal("the segment did not record the sender of the request")
	}
	if !bytes.Equal(got, sender) {
		t.Errorf("recorded 10.60.0.7 as %s, want %s", got, sender)
	}
}

// A reply and a gratuitous announcement carry the sender pair too, and
// a host that moves announces itself before it sends anything else.
func TestL2EgressRecordsTheSenderOfAnArpReply(t *testing.T) {
	ports := newL2EgressPorts(t)
	sender := bpftest.MAC(1)

	frame := bpftest.Frame(t, bpftest.MAC(2), sender, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPReply, sender, "10.60.0.7", bpftest.MAC(2), "10.60.0.8"))
	bpftest.Run(t, ports.program, frame, ports.pod1)

	if _, ok := ports.segment.resolved(t, "10.60.0.7"); !ok {
		t.Fatal("the segment did not record the sender of the reply")
	}
	if _, ok := ports.segment.resolved(t, "10.60.0.8"); ok {
		t.Error("the segment recorded the target of the reply, which the frame says nothing about")
	}
}

// Reading the ARP must not turn into answering it. The request still
// has to reach every port, or the host that owns the address never gets
// to answer for itself.
func TestL2EgressStillFloodsTheArpItReads(t *testing.T) {
	ports := newL2EgressPorts(t)
	sender := bpftest.MAC(1)

	frame := bpftest.Frame(t, bpftest.Broadcast, sender, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, sender, "10.60.0.7", net.HardwareAddr{0, 0, 0, 0, 0, 0}, "10.60.0.1"))
	watched := ports.watch(t)
	bpftest.Run(t, ports.program, frame, ports.pod1)

	for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
		if delivered := watched.Delivered(t, device); delivered != 1 {
			t.Errorf("%s was fed %d copies of the request, want 1", device.Name, delivered)
		}
	}
}

// The gateway MAC is the one forwarding entry the data plane does not
// own. A workload that sends from it is claiming the way out of the
// segment for itself.
func TestL2EgressWillNotMoveTheGatewayToAWorkload(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)

	frame := bpftest.Frame(t, bpftest.MAC(2), gatewayMAC, bpftest.EtherTypeIPv4, nil)
	bpftest.Run(t, ports.program, frame, ports.pod1)

	entry, ok := ports.segment.lookup(t, gatewayMAC)
	if !ok {
		t.Fatal("the gateway entry is gone")
	}
	if entry.Ifindex != uint32(ports.pod3.Index) {
		t.Errorf("the gateway moved to ifindex %d, want it to stay on %d", entry.Ifindex, ports.pod3.Index)
	}
}

// Nothing counts the hand-offs to a gateway port for us: redirecting to
// an ingress has no recursion limit in the kernel, and bpf_redirect
// leaves the IP TTL alone. The count in skb->mark is what ends a loop
// between the gateway and something on the segment that keeps sending
// the frame back.
func TestL2EgressCountsEveryHandOffToTheGateway(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)

	frame := bpftest.Frame(t, gatewayMAC, bpftest.MAC(1), bpftest.EtherTypeIPv4, nil)
	verdict, mark := bpftest.RunMarked(t, ports.program, frame, ports.pod1, 0)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	if got := gatewayHops(mark); got != 1 {
		t.Errorf("the frame left with %d hops counted, want 1", got)
	}
}

func TestL2EgressStopsAFrameThatKeepsComingBackToTheGateway(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)

	frame := bpftest.Frame(t, gatewayMAC, bpftest.MAC(1), bpftest.EtherTypeIPv4, nil)
	verdict, _ := bpftest.RunMarked(t, ports.program, frame, ports.pod1, markWithHops(maxGatewayHops))

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
}

// Only the hop bits are juneau's. A frame the gateway hands back to the
// host stack carries its mark into netfilter, where kube-proxy reads
// marks of its own.
func TestL2EgressLeavesTheRestOfTheMarkAlone(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)

	frame := bpftest.Frame(t, gatewayMAC, bpftest.MAC(1), bpftest.EtherTypeIPv4, nil)
	_, mark := bpftest.RunMarked(t, ports.program, frame, ports.pod1, 0x4000)

	if mark&^gatewayHopMask != 0x4000 {
		t.Errorf("the frame left with mark %#x, want everything but the hop bits kept at %#x", mark, 0x4000)
	}
}

// The gateway takes its copy of a broadcast on the port's ingress, not
// its egress: it is a port juneau reads from rather than a workload
// that receives what is put in front of it.
func TestL2EgressDoesNotPutABroadcastOnTheGatewaysEgress(t *testing.T) {
	ports := newL2EgressPorts(t)
	ports.segment.addGatewayPort(t, ports.pod3, bpftest.MAC(0xfe))

	frame := bpftest.Frame(t, bpftest.Broadcast, bpftest.MAC(1), bpftest.EtherTypeARP, nil)
	watched := ports.watch(t)
	bpftest.Run(t, ports.program, frame, ports.pod1)

	if delivered := watched.Delivered(t, ports.pod2); delivered != 1 {
		t.Errorf("pod2 was fed %d copies, want 1", delivered)
	}
	if delivered := watched.Delivered(t, ports.pod3); delivered != 0 {
		t.Errorf("the gateway was fed %d copies on its egress, want them on its ingress", delivered)
	}
}
