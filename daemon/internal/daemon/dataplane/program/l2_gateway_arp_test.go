package program_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/l2"
)

// arpFrameLen is the length of an Ethernet/IPv4 ARP frame: the header,
// the fixed part and the four addresses. Mirrors L2_ARP_FRAME_LEN in
// daemon/bpf/l2.h.
const arpFrameLen = 42

// arpRequest is one ARP frame read back off the wire, so a test can say
// what the gateway asked for instead of counting bytes.
type arpRequest struct {
	destination net.HardwareAddr
	source      net.HardwareAddr
	opcode      uint16
	senderMAC   net.HardwareAddr
	senderIP    net.IP
	targetMAC   net.HardwareAddr
	targetIP    net.IP
}

func readARP(t *testing.T, frame []byte) arpRequest {
	t.Helper()
	if len(frame) < arpFrameLen {
		t.Fatalf("the buffer holds %d bytes, too few for an ARP frame of %d", len(frame), arpFrameLen)
	}
	if got := binary.BigEndian.Uint16(frame[12:14]); got != bpftest.EtherTypeARP {
		t.Fatalf("the frame carries EtherType 0x%04x, want ARP (0x%04x)", got, bpftest.EtherTypeARP)
	}
	if got := binary.BigEndian.Uint16(frame[14:16]); got != 1 {
		t.Errorf("hardware type %d, want Ethernet (1)", got)
	}
	if got := binary.BigEndian.Uint16(frame[16:18]); got != bpftest.EtherTypeIPv4 {
		t.Errorf("protocol type 0x%04x, want IPv4 (0x%04x)", got, bpftest.EtherTypeIPv4)
	}
	if frame[18] != 6 || frame[19] != 4 {
		t.Errorf("address lengths %d and %d, want 6 and 4", frame[18], frame[19])
	}
	return arpRequest{
		destination: net.HardwareAddr(frame[0:6]),
		source:      net.HardwareAddr(frame[6:12]),
		opcode:      binary.BigEndian.Uint16(frame[20:22]),
		senderMAC:   net.HardwareAddr(frame[22:28]),
		senderIP:    net.IP(frame[28:32]),
		targetMAC:   net.HardwareAddr(frame[32:38]),
		targetIP:    net.IP(frame[38:42]),
	}
}

// A packet for an address nobody on the segment has spoken from is what
// an L2Network is built for: a workload that gave itself an address of
// its own, or a host behind a bridge on the far side of a NIC. The
// gateway asks the segment who owns it, exactly as a router does, and
// drops the packet that needed the answer. BPF has nowhere to park an
// skb until the reply comes back, so the first packet is always lost
// and a retransmit is what gets through.
func TestL2GatewayAsksTheSegmentForAnAddressItCannotResolve(t *testing.T) {
	ports := newL2GatewayPorts(t)

	watched := ports.watch(t)
	verdict, out := bpftest.RunRewritten(t, ports.program, routed(t, host2Address), ports.gateway)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want the packet dropped after the request went out (%d)", verdict, bpftest.ActShot)
	}
	for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
		if delivered := watched.Delivered(t, device); delivered != 1 {
			t.Errorf("%s was fed %d copies of the request, want 1", device.Name, delivered)
		}
	}
	if got := watched.DeliveredBytes(t, ports.pod2); got != arpFrameLen {
		t.Errorf("the frame that reached pod2 is %d bytes, want a request of %d", got, arpFrameLen)
	}

	request := readARP(t, out)
	if !bytes.Equal(request.destination, bpftest.Broadcast) {
		t.Errorf("the request went to %s, want the broadcast address", request.destination)
	}
	if !bytes.Equal(request.source, ports.gatewayMAC) {
		t.Errorf("the request came from %s, want the gateway (%s)", request.source, ports.gatewayMAC)
	}
	if request.opcode != bpftest.ARPRequest {
		t.Errorf("opcode %d, want a request (%d)", request.opcode, bpftest.ARPRequest)
	}
	if !bytes.Equal(request.senderMAC, ports.gatewayMAC) {
		t.Errorf("sender MAC %s, want the gateway (%s)", request.senderMAC, ports.gatewayMAC)
	}
	if got := request.senderIP.String(); got != gatewayAddress {
		t.Errorf("sender address %s, want the gateway (%s)", got, gatewayAddress)
	}
	if !bytes.Equal(request.targetMAC, net.HardwareAddr{0, 0, 0, 0, 0, 0}) {
		t.Errorf("target MAC %s, want it left empty", request.targetMAC)
	}
	if got := request.targetIP.String(); got != host2Address {
		t.Errorf("the request asks for %s, want the address the packet was for (%s)", got, host2Address)
	}
}

// The gateway port is a port of the segment, and the frame it sends
// must not come back to it. l2_egress on that port snoops every ARP it
// sees, so a copy handed back would have the segment record the gateway
// as the owner of the address it is still looking for.
func TestL2GatewayDoesNotAskItself(t *testing.T) {
	ports := newL2GatewayPorts(t)

	watched := ports.watch(t)
	bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	if delivered := watched.Delivered(t, ports.gateway); delivered != 0 {
		t.Errorf("the gateway was fed %d copies of the request it sent itself", delivered)
	}
}

// The request reaches the nodes that hold a port on the segment too.
// The host that owns the address may be on any of them.
func TestL2GatewayAsksTheOtherNodesAsWell(t *testing.T) {
	ports := newL2GatewayPorts(t)
	ports.segment.addRemoteNode(t, "10.0.0.2")

	watched := ports.watch(t)
	bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	if delivered := watched.Delivered(t, ports.tunnel); delivered != 1 {
		t.Errorf("the overlay carried %d copies of the request, want 1", delivered)
	}
}

// Without this the gateway is a broadcast amplifier: every packet for
// an address nobody has claimed would put an ARP request on every port
// of the segment, and a host sending thousands of packets a second at
// one unreachable address would drown the segment.
func TestL2GatewayAsksForOneAddressOnlyOnceAnInterval(t *testing.T) {
	ports := newL2GatewayPorts(t)

	bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want the packet dropped (%d)", verdict, bpftest.ActShot)
	}
	for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
		if delivered := watched.Delivered(t, device); delivered != 0 {
			t.Errorf("%s was fed %d more copies, want the second ask held back", device.Name, delivered)
		}
	}
}

// Holding one address back must not hold the segment back. Two
// workloads reaching two hosts that have not spoken yet are two
// separate questions.
func TestL2GatewayAsksForEachAddressOnItsOwn(t *testing.T) {
	ports := newL2GatewayPorts(t)

	bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	watched := ports.watch(t)
	bpftest.Run(t, ports.program, routed(t, host3Address), ports.gateway)

	for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
		if delivered := watched.Delivered(t, device); delivered != 1 {
			t.Errorf("%s was fed %d copies of the second request, want 1", device.Name, delivered)
		}
	}
}

// A host that comes up late has to be found. The interval spaces the
// asks out; it does not give up on the address.
func TestL2GatewayAsksAgainOnceTheIntervalHasPassed(t *testing.T) {
	ports := newL2GatewayPorts(t)

	bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)
	ports.segment.rewindAsk(t, host2Address, l2.ArpProbeInterval)

	watched := ports.watch(t)
	bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
		if delivered := watched.Delivered(t, device); delivered != 1 {
			t.Errorf("%s was fed %d copies of the second request, want 1", device.Name, delivered)
		}
	}
}

// A resolved address needs no question asked about it. The packet goes
// to the host that owns it and the segment stays quiet.
func TestL2GatewayAsksNothingForAnAddressItCanResolve(t *testing.T) {
	ports := newL2GatewayPorts(t)
	host2 := bpftest.MAC(2)
	ports.segment.resolve(t, host2Address, host2)
	ports.segment.learn(t, host2, uint32(ports.pod2.Index), "")

	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, routed(t, host2Address), ports.gateway)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	for _, device := range []bpftest.Device{ports.pod2, ports.pod3} {
		if delivered := watched.Delivered(t, device); delivered != 0 {
			t.Errorf("%s was fed %d copies, want the packet forwarded and nothing asked", device.Name, delivered)
		}
	}
	if _, asked := ports.segment.askedAt(t, host2Address); asked {
		t.Error("the gateway wrote down an ask for an address it already knew")
	}
}

// The addresses the controller handed out are already in the table, so
// the gateway addresses those packets rather than asking for them. The
// question is only for what juneau never handed out.
func TestL2GatewayAsksNothingForAnAddressTheControllerSeeded(t *testing.T) {
	ports := newL2GatewayPorts(t)
	ports.segment.seedAddress(t, host2Address, bpftest.MAC(2))

	_, out := bpftest.RunFrame(t, ports.program, routed(t, host2Address), ports.gateway)

	if got := binary.BigEndian.Uint16(out[12:14]); got != bpftest.EtherTypeIPv4 {
		t.Errorf("the frame left as EtherType 0x%04x, want the packet itself (0x%04x)", got, bpftest.EtherTypeIPv4)
	}
	if _, asked := ports.segment.askedAt(t, host2Address); asked {
		t.Error("the gateway wrote down an ask for an address the controller had already given it")
	}
}

// A router resolves the neighbours of the link it is on and nothing
// else. An address from outside the segment cannot be answered by
// anyone here, so asking for it would put a request on every port for
// every packet of a route that was aimed wrong.
func TestL2GatewayAsksNothingForAnAddressOutsideTheSegment(t *testing.T) {
	ports := newL2GatewayPorts(t)

	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, routed(t, outsideAddress), ports.gateway)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
	for _, device := range []bpftest.Device{ports.pod2, ports.pod3, ports.tunnel} {
		if delivered := watched.Delivered(t, device); delivered != 0 {
			t.Errorf("%s was fed %d copies of a request for an address off the segment", device.Name, delivered)
		}
	}
	if _, asked := ports.segment.askedAt(t, outsideAddress); asked {
		t.Error("the gateway wrote down an ask for an address that cannot be on the segment")
	}
}

// A frame the kernel handed over without padding is shorter than an ARP
// frame, so the rewrite has to grow it. Both directions run through
// bpf_skb_change_tail, which invalidates every pointer into the frame.
func TestL2GatewayAsksFromAFrameShorterThanTheRequest(t *testing.T) {
	ports := newL2GatewayPorts(t)

	packet := bpftest.IPv4(t, outsideAddress, host2Address)
	frame := make([]byte, 0, 14+len(packet))
	frame = append(frame, bpftest.MAC(0xf0)...)
	frame = append(frame, bpftest.MAC(0xf1)...)
	frame = append(frame, 0x08, 0x00)
	frame = append(frame, packet...)
	if len(frame) >= arpFrameLen {
		t.Fatalf("the frame is %d bytes, want one shorter than a request (%d)", len(frame), arpFrameLen)
	}

	watched := ports.watch(t)
	_, out := bpftest.RunRewritten(t, ports.program, frame, ports.gateway)

	if delivered := watched.Delivered(t, ports.pod2); delivered != 1 {
		t.Errorf("pod2 was fed %d copies of the request, want 1", delivered)
	}
	if got := watched.DeliveredBytes(t, ports.pod2); got != arpFrameLen {
		t.Errorf("the frame that reached pod2 is %d bytes, want a request of %d", got, arpFrameLen)
	}
	if got := readARP(t, out).targetIP.String(); got != host2Address {
		t.Errorf("the request asks for %s, want %s", got, host2Address)
	}
}

// The answer to the question the gateway asked comes back as a unicast
// reply addressed to it, and l2_egress reads the sender of every ARP
// frame that crosses the segment. Nothing had to be added for the
// answer; this says so out loud, because the ask is worth nothing
// without it.
func TestL2EgressRecordsTheAnswerToTheGatewaysQuestion(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)
	host := bpftest.MAC(1)

	frame := bpftest.Frame(t, gatewayMAC, host, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPReply, host, host2Address, gatewayMAC, gatewayAddress))
	bpftest.Run(t, ports.program, frame, ports.pod1)

	got, ok := ports.segment.resolved(t, host2Address)
	if !ok {
		t.Fatal("the segment did not record the host that answered")
	}
	if !bytes.Equal(got, host) {
		t.Errorf("recorded %s as %s, want %s", host2Address, got, host)
	}
}

// The answer to the gateway's question has to reach every node, not
// only the one it came back on.
//
// Every node runs a gateway on the same MAC, so the host addresses its
// reply to whichever gateway is local to it, and only that node would
// learn the address. The node that asked is the node the Vpc packet was
// routed on, which is a different one whenever the client and the host
// sit apart. So a reply addressed to the gateway is copied to the other
// nodes as well.
func TestL2EgressSharesTheAnswerToTheGatewayWithTheOtherNodes(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)
	ports.segment.addRemoteNode(t, "10.0.0.2")
	host := bpftest.MAC(1)

	frame := bpftest.Frame(t, gatewayMAC, host, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPReply, host, host2Address, gatewayMAC, gatewayAddress))
	watched := ports.watch(t)
	verdict, mark := bpftest.RunMarked(t, ports.program, frame, ports.pod1, 0)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want the frame dropped after the copies (%d)", verdict, bpftest.ActShot)
	}
	// The gateway takes its copy on the port's ingress, which a dummy
	// device counts nowhere. The hop it charges for the hand-off is left
	// in the mark, and that is what says it was offered one.
	if hops := gatewayHops(mark); hops != 1 {
		t.Errorf("the frame was handed to a gateway %d times, want the one on this node to take it", hops)
	}
	if delivered := watched.Delivered(t, ports.tunnel); delivered != 1 {
		t.Errorf("the overlay carried %d copies of the answer, want the other nodes to read it", delivered)
	}
	if delivered := watched.Delivered(t, ports.pod2); delivered != 0 {
		t.Errorf("a workload was fed %d copies of an answer addressed to the gateway", delivered)
	}
	if got, ok := ports.segment.resolved(t, host2Address); !ok || !bytes.Equal(got, host) {
		t.Errorf("this node recorded %s as %s, want %s", host2Address, got, host)
	}
}

// Only the answer travels. An ARP frame between two workloads is the
// segment's own business and goes to the one port that holds the MAC,
// the way any unicast does.
func TestL2EgressKeepsAnAnswerForAWorkloadOffTheOverlay(t *testing.T) {
	ports := newL2EgressPorts(t)
	ports.segment.addGatewayPort(t, ports.pod3, bpftest.MAC(0xfe))
	ports.segment.addRemoteNode(t, "10.0.0.2")
	peer := bpftest.MAC(2)
	ports.segment.learn(t, peer, uint32(ports.pod2.Index), "")
	host := bpftest.MAC(1)

	frame := bpftest.Frame(t, peer, host, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPReply, host, host2Address, peer, host3Address))
	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, frame, ports.pod1)

	if verdict != bpftest.ActRedirect {
		t.Errorf("verdict %d, want the frame sent to the port that holds the MAC (%d)", verdict, bpftest.ActRedirect)
	}
	if delivered := watched.Delivered(t, ports.tunnel); delivered != 0 {
		t.Errorf("the overlay carried %d copies of an answer no gateway asked for", delivered)
	}
}

// A question addressed to the gateway is not shared. Only the reply
// carries an address the other nodes could not have learned for
// themselves; a request is answered by the gateway that received it.
func TestL2EgressSharesAnAnswerAndNotAQuestion(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)
	ports.segment.addRemoteNode(t, "10.0.0.2")
	host := bpftest.MAC(1)

	frame := bpftest.Frame(t, gatewayMAC, host, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, host, host2Address,
			net.HardwareAddr{0, 0, 0, 0, 0, 0}, gatewayAddress))
	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, frame, ports.pod1)

	if verdict != bpftest.ActRedirect {
		t.Errorf("verdict %d, want the question handed to the gateway alone (%d)", verdict, bpftest.ActRedirect)
	}
	if delivered := watched.Delivered(t, ports.tunnel); delivered != 0 {
		t.Errorf("the overlay carried %d copies of a question the local gateway answers", delivered)
	}
}
