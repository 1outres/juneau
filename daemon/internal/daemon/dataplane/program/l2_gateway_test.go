package program_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

// The addresses the gateway tests speak about. The segment is
// 10.60.0.0/24, the router port answers on its first address, and two
// hosts sit behind it.
const (
	gatewayAddress = "10.60.0.1"
	host2Address   = "10.60.0.2"
	host3Address   = "10.60.0.3"
	outsideAddress = "10.70.0.9"
)

// l2GatewayPorts is one segment with a gateway port and two hosts on
// it, driving the program that sits at the egress of the gateway veth.
type l2GatewayPorts struct {
	segment    *l2Segment
	program    *ebpf.Program
	gateway    bpftest.Device
	gatewayMAC net.HardwareAddr
	pod2       bpftest.Device
	pod3       bpftest.Device
	tunnel     bpftest.Device
}

func newL2GatewayPorts(t *testing.T) *l2GatewayPorts {
	t.Helper()
	bpftest.Require(t)
	bpftest.Netns(t)

	segment := newL2Segment(t, bpf.LoadL2Gateway)
	ports := &l2GatewayPorts{
		segment:    segment,
		program:    segment.objs.Program(t, "tc_l2_gateway"),
		gateway:    bpftest.Dummy(t, "l2gw"),
		gatewayMAC: bpftest.MAC(0xfe),
		pod2:       bpftest.Dummy(t, "pod2"),
		pod3:       bpftest.Dummy(t, "pod3"),
		tunnel:     bpftest.Dummy(t, "overlay0"),
	}
	for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
		segment.addLocalPort(t, device)
	}
	segment.addGatewayPort(t, ports.gateway, ports.gatewayMAC)
	segment.useTunnelDevice(t, ports.tunnel)
	return ports
}

func (p *l2GatewayPorts) watch(t *testing.T) *bpftest.Ports {
	t.Helper()
	return bpftest.WatchPorts(t, p.gateway, p.pod2, p.pod3, p.tunnel)
}

// routed builds the frame pod_egress hands to the gateway veth: an IPv4
// packet still carrying the addresses of the hop that received it.
func routed(t *testing.T, destination string) []byte {
	t.Helper()
	return bpftest.Frame(t, bpftest.MAC(0xf0), bpftest.MAC(0xf1), bpftest.EtherTypeIPv4,
		bpftest.IPv4(t, outsideAddress, destination))
}

func TestL2GatewayAddressesAPacketToTheHostThatOwnsIt(t *testing.T) {
	ports := newL2GatewayPorts(t)
	host2 := bpftest.MAC(2)
	ports.segment.resolve(t, host2Address, host2)
	ports.segment.learn(t, host2, uint32(ports.pod2.Index), "")

	verdict, out := bpftest.RunFrame(t, ports.program, routed(t, host2Address), ports.gateway)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	if got := net.HardwareAddr(out[0:6]); !bytes.Equal(got, host2) {
		t.Errorf("frame addressed to %s, want the host that owns the address (%s)", got, host2)
	}
	if got := net.HardwareAddr(out[6:12]); !bytes.Equal(got, ports.gatewayMAC) {
		t.Errorf("frame sent from %s, want the gateway (%s)", got, ports.gatewayMAC)
	}
}

// The address resolved but the MAC behind it has gone quiet. The frame
// already carries the destination's own MAC, so copying it to every
// port reaches that host and no one else takes it — the same answer a
// switch gives an unknown unicast.
func TestL2GatewayFloodsAResolvedMacItCannotPlace(t *testing.T) {
	ports := newL2GatewayPorts(t)
	ports.segment.resolve(t, host2Address, bpftest.MAC(2))

	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want the original frame dropped after the copies (%d)", verdict, bpftest.ActShot)
	}
	for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
		if delivered := watched.Delivered(t, device); delivered != 1 {
			t.Errorf("%s was fed %d copies, want 1", device.Name, delivered)
		}
	}
	if delivered := watched.Delivered(t, ports.gateway); delivered != 0 {
		t.Errorf("the gateway was fed %d copies of the frame it sent itself", delivered)
	}
}

// The reply pod_egress built for the gateway's own address arrives on
// this hook already addressed to the host that asked. Rewriting it
// would send the answer to the wrong place.
func TestL2GatewayLeavesAnArpReplyAsItIs(t *testing.T) {
	ports := newL2GatewayPorts(t)
	host2 := bpftest.MAC(2)
	ports.segment.learn(t, host2, uint32(ports.pod2.Index), "")

	frame := bpftest.Frame(t, host2, ports.gatewayMAC, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPReply, ports.gatewayMAC, gatewayAddress, host2, host2Address))
	verdict, out := bpftest.RunFrame(t, ports.program, frame, ports.gateway)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	if !bytes.Equal(out[0:12], frame[0:12]) {
		t.Errorf("the reply left with addresses %x, want the ones it arrived with %x", out[0:12], frame[0:12])
	}
}

// A router port carries what a router carries. Anything else on this
// hook came from the host stack behind the veth, and putting it on a
// tenant's segment is not the gateway's business.
func TestL2GatewayDropsAnEtherTypeARouterDoesNotSpeak(t *testing.T) {
	ports := newL2GatewayPorts(t)

	frame := bpftest.Frame(t, bpftest.Broadcast, ports.gatewayMAC, bpftest.EtherTypeIPv6, nil)
	if verdict := bpftest.Run(t, ports.program, frame, ports.gateway); verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
}

// The veth of a gateway that has gone away can come back as another
// port. Signing a frame with the MAC of a gateway that no longer lives
// here would put a second owner of that address on the segment.
func TestL2GatewayDropsAFrameOnAPortItNoLongerOwns(t *testing.T) {
	ports := newL2GatewayPorts(t)
	ports.segment.resolve(t, host2Address, bpftest.MAC(2))

	if err := ports.segment.objs.Map(t, "l2_gateway").Update(
		&bpf.PodEgressL2GatewayKey{Vni: testVNI},
		&bpf.PodEgressL2GatewayVal{Ifindex: uint32(ports.pod3.Index)},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("move the gateway to another port: %v", err)
	}

	if verdict := bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway); verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
}

// A workload that answers ARP for an address with the gateway's own MAC
// would have the gateway send the packet straight back to itself.
func TestL2GatewayDropsAPacketThatResolvesToItself(t *testing.T) {
	ports := newL2GatewayPorts(t)
	ports.segment.resolve(t, host2Address, ports.gatewayMAC)

	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
	if delivered := watched.Delivered(t, ports.gateway); delivered != 0 {
		t.Errorf("the gateway was fed %d copies of its own frame", delivered)
	}
}

// The gateway resolves and re-addresses; it does not read the flow.
// Undoing a NAT or judging a policy needs the conntrack of that flow,
// and this program runs wherever the packet was routed rather than on
// the node that holds it. Putting either back here breaks every
// cross-node reply, which is how it was found.
func TestL2GatewayLeavesTheAddressesOfAPacketAlone(t *testing.T) {
	ports := newL2GatewayPorts(t)
	host := bpftest.MAC(2)
	ports.segment.resolve(t, host2Address, host)
	ports.segment.learn(t, host, uint32(ports.pod2.Index), "")
	installServiceReverseInto(t, ports.segment.objs.Map(t, "ct_map"), host2Address)

	frame := bpftest.Frame(t, bpftest.MAC(0xf0), bpftest.MAC(0xf1), bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, backendAddress, host2Address, backendPort, clientPort))
	verdict, out := bpftest.RunFrame(t, ports.program, frame, ports.gateway)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	if got := bpftest.SourceAddress(t, out); got != backendAddress {
		t.Errorf("the gateway rewrote the source to %s; that belongs to l2_ingress", got)
	}
}

// The same ACL says nothing about traffic that stays on the segment.
// The L2 programs read no policy, and a rule that started dropping
// frames between two NICs would be a surprise nobody asked for.
func TestL2EgressIgnoresTheGatewayACL(t *testing.T) {
	ports := newL2EgressPorts(t)
	peer := bpftest.MAC(2)
	ports.segment.learn(t, peer, uint32(ports.pod2.Index), "")
	if err := ports.segment.objs.Map(t, "acl_meta_map").Update(
		uint32(testACLID),
		&bpf.PodEgressAclMetaVal{HasIngressRules: 1, HasEgressRules: 1},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("declare the ACL: %v", err)
	}
	ports.segment.standUpGateway(t, ports.pod3, bpftest.MAC(0xfe), 0, testACLID)

	frame := bpftest.Frame(t, peer, bpftest.MAC(1), bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, host2Address, host3Address, clientPort, servicePort))
	if verdict := bpftest.Run(t, ports.program, frame, ports.pod1); verdict != bpftest.ActRedirect {
		t.Errorf("verdict %d, want the frame forwarded (%d)", verdict, bpftest.ActRedirect)
	}
}

// A gateway on a node that holds no port of the segment can still put a
// packet on it: with the address resolved and no local port holding the
// MAC, the frame leaves as an unknown unicast over the overlay and the
// node that does hold it delivers.
//
// This is what makes a port on every node worth having, and it is also
// what narrows the remaining gap to one table. Such a node receives no
// frame from the segment — nothing lists it as a place to flood to — so
// nothing ever fills its l2_arp, and the resolution above is the step
// that fails.
func TestL2GatewayReachesTheSegmentOverTheOverlay(t *testing.T) {
	ports := newL2GatewayPorts(t)
	ports.segment.addRemoteNode(t, "10.0.0.2")
	ports.segment.resolve(t, host2Address, bpftest.MAC(2))

	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want the original frame dropped after the copies (%d)", verdict, bpftest.ActShot)
	}
	if delivered := watched.Delivered(t, ports.tunnel); delivered != 1 {
		t.Errorf("the overlay carried %d copies, want the frame to reach the node that holds the MAC", delivered)
	}
}

// A node that holds no port on the segment sees none of its ARP, so
// nothing ever fills its l2_arp by snooping. The controller knows the
// addresses it handed out, and reconciler.L2Arp offers them; with that
// in place the gateway on such a node can address the segment and the
// frame goes out over the overlay to the node that does hold the MAC.
//
// This is the whole of what a node with no endpoint was missing. The
// port, the flood list and the route were already there.
func TestGatewayOnANodeWithNoPortReachesTheSegment(t *testing.T) {
	bpftest.Require(t)
	bpftest.Netns(t)

	segment := newL2Segment(t, bpf.LoadL2Gateway)
	gateway := bpftest.Dummy(t, "l2gw")
	gatewayMAC := bpftest.MAC(0xfe)
	tunnel := bpftest.Dummy(t, "overlay0")
	segment.addGatewayPort(t, gateway, gatewayMAC)
	segment.useTunnelDevice(t, tunnel)

	// Nothing of the segment lives here. The endpoints, and every MAC
	// this node could have learned, are on another node.
	segment.addRemoteNode(t, "10.0.0.2")
	segment.seedAddress(t, host2Address, bpftest.MAC(2))

	watched := bpftest.WatchPorts(t, tunnel, gateway)
	bpftest.Run(t, segment.objs.Program(t, "tc_l2_gateway"), routed(t, host2Address), gateway)

	if delivered := watched.Delivered(t, tunnel); delivered != 1 {
		t.Errorf("the overlay carried %d copies, want the frame to reach the node that holds the MAC", delivered)
	}
	if delivered := watched.Delivered(t, gateway); delivered != 0 {
		t.Errorf("the gateway was fed %d copies of its own frame", delivered)
	}
}
