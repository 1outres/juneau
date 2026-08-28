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

// A host juneau has never seen speak cannot be addressed: the gateway
// snoops the segment's ARP and sends none of its own, so there is
// nothing to resolve the address with. Flooding instead would put a
// packet for one host on every port.
func TestL2GatewayDropsAPacketForAnAddressNobodyHasClaimed(t *testing.T) {
	ports := newL2GatewayPorts(t)

	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
	for _, device := range []bpftest.Device{ports.pod2, ports.pod3, ports.tunnel} {
		if delivered := watched.Delivered(t, device); delivered != 0 {
			t.Errorf("%s was fed %d copies of a packet nobody claimed", device.Name, delivered)
		}
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

// The addresses a ClusterIP flow out of the segment involves.
const (
	serviceAddress = "10.96.0.10"
	backendAddress = "10.61.0.7"
	servicePort    = 80
	backendPort    = 8080
	clientPort     = 40000
)

// installServiceReverse records what pod_egress installs on the gateway
// veth when it DNATs a ClusterIP: the reverse entry that turns the
// backend's address back into the Service's on the way home.
func (p *l2GatewayPorts) installServiceReverse(t *testing.T, client string) {
	t.Helper()
	err := p.segment.objs.Map(t, "ct_map").Update(
		&bpf.PodEgressCtKey{
			Scope: testVpcID,
			Saddr: networkOrderIPv4(t, backendAddress),
			Daddr: networkOrderIPv4(t, client),
			Sport: bigEndianPort(backendPort),
			Dport: bigEndianPort(clientPort),
			Proto: 6,
		},
		&bpf.PodEgressCtVal{
			NewSaddr: networkOrderIPv4(t, serviceAddress),
			NewDaddr: networkOrderIPv4(t, client),
			NewSport: bigEndianPort(servicePort),
			NewDport: bigEndianPort(clientPort),
			Action:   2, // CT_ACTION_SNAT
		},
		ebpf.UpdateAny,
	)
	if err != nil {
		t.Fatalf("record the reverse entry of the Service flow: %v", err)
	}
}

// bigEndianPort is a port as the data plane stores it: a __be16 read
// back through a Go uint16.
func bigEndianPort(port uint16) uint16 { return port<<8 | port>>8 }

// A ClusterIP reply has to leave the gateway carrying the Service's
// address, not the backend's. Nothing else on the way into the segment
// can put it back: the reverse rewrite normally happens in pod_ingress,
// and an L2 NIC has no pod_ingress on it.
func TestL2GatewayPutsTheServiceAddressBackOnAReply(t *testing.T) {
	ports := newL2GatewayPorts(t)
	client := bpftest.MAC(2)
	ports.segment.resolve(t, host2Address, client)
	ports.segment.learn(t, client, uint32(ports.pod2.Index), "")
	ports.installServiceReverse(t, host2Address)

	frame := bpftest.Frame(t, bpftest.MAC(0xf0), bpftest.MAC(0xf1), bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, backendAddress, host2Address, backendPort, clientPort))
	verdict, out := bpftest.RunFrame(t, ports.program, frame, ports.gateway)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	if got := bpftest.SourceAddress(t, out); got != serviceAddress {
		t.Errorf("the reply left with source %s, want the Service address %s", got, serviceAddress)
	}
	if got := bpftest.SourcePort(t, out); got != servicePort {
		t.Errorf("the reply left with source port %d, want %d", got, servicePort)
	}
	if got := net.HardwareAddr(out[0:6]); !bytes.Equal(got, client) {
		t.Errorf("the reply is addressed to %s, want the client that asked (%s)", got, client)
	}
}

// A packet with no reverse entry behind it is not a Service reply. It
// has to reach the segment exactly as it arrived.
func TestL2GatewayLeavesAPacketWithNoConntrackEntryAlone(t *testing.T) {
	ports := newL2GatewayPorts(t)
	client := bpftest.MAC(2)
	ports.segment.resolve(t, host2Address, client)
	ports.segment.learn(t, client, uint32(ports.pod2.Index), "")

	frame := bpftest.Frame(t, bpftest.MAC(0xf0), bpftest.MAC(0xf1), bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, backendAddress, host2Address, backendPort, clientPort))
	verdict, out := bpftest.RunFrame(t, ports.program, frame, ports.gateway)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	if got := bpftest.SourceAddress(t, out); got != backendAddress {
		t.Errorf("the packet left with source %s, want the %s it arrived with", got, backendAddress)
	}
}
