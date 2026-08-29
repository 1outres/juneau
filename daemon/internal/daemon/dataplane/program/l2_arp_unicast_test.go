package program_test

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/l2"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler"
)

// askingNode is a node that asked the segment for an address but holds
// no port on it, so no flood list names it. sharingNode does hold one.
const (
	askingNode  = "10.0.0.7"
	sharingNode = "10.0.0.2"
)

// noMAC is the target hardware address of an ARP request: the sender
// does not know it yet, which is the whole point of asking.
var noMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

// gatewayQuestion builds the frame a gateway puts on the segment when
// it cannot resolve an address.
func gatewayQuestion(t *testing.T, gatewayMAC net.HardwareAddr, target string) []byte {
	t.Helper()
	return bpftest.Frame(t, bpftest.Broadcast, gatewayMAC, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, gatewayMAC, gatewayAddress, noMAC, target))
}

// answerTo builds the reply a host sends back to the gateway: a
// unicast addressed to the MAC the question came from.
func answerTo(t *testing.T, gatewayMAC, host net.HardwareAddr, address string) []byte {
	t.Helper()
	return bpftest.Frame(t, gatewayMAC, host, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPReply, host, address, gatewayMAC, gatewayAddress))
}

// awaitAsker waits for the segment to write down which node asked for
// an address. The overlay delivers in a softirq after the write
// returns, so the table cannot be read right away.
func awaitAsker(t *testing.T, table *l2.Table, address string) bpf.PodEgressL2ArpAskerVal {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if record, ok := lookupAsker(t, table, address); ok {
			return record
		}
		if time.Now().After(deadline) {
			t.Fatalf("the segment never wrote down who asked for %s", address)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The gateway of a node that holds no port on the segment is the one
// this record exists for. Its question crosses the overlay, and the
// node that ends up carrying the answer is the only place that knows
// who is waiting for it.
func TestVxlanIngressWritesDownWhichNodeAskedForAnAddress(t *testing.T) {
	overlay := newOverlaySegment(t)
	gatewayMAC := bpftest.MAC(0xfe)
	overlay.segment.addGatewayPort(t, overlay.pod3, gatewayMAC)

	overlay.deliver(t, testVNI, gatewayQuestion(t, gatewayMAC, host2Address))

	record := awaitAsker(t, overlay.segment.arpAsker, host2Address)
	if want := hostOrderIPv4(t, loopbackVTEP); record.VtepIp != want {
		t.Errorf("recorded %d as the node that asked for %s, want %d", record.VtepIp, host2Address, want)
	}
	if record.AskedNs == 0 {
		t.Error("recorded the question with no timestamp, so it can never expire")
	}
}

// Only the gateway's own question is written down. A workload asking
// its neighbours is answered by them directly, and recording it would
// send the segment's own ARP replies to a node nobody asked.
func TestVxlanIngressWritesDownNothingForAQuestionAWorkloadAsked(t *testing.T) {
	overlay := newOverlaySegment(t)
	overlay.segment.addGatewayPort(t, overlay.pod3, bpftest.MAC(0xfe))
	host := bpftest.MAC(1)

	frame := bpftest.Frame(t, bpftest.Broadcast, host, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, host, host3Address, noMAC, host2Address))
	overlay.deliver(t, testVNI, frame)
	overlay.awaitLearned(t, host)

	if _, ok := overlay.segment.asker(t, host2Address); ok {
		t.Errorf("the segment wrote down a node as asking for %s over a workload's question", host2Address)
	}
}

// The answer goes to the node that asked, even though no flood list
// names it. That node holds no port on the segment — a node with only
// a gateway on it never appears in anyone's l2_bum_remote — which is
// why the shared copy alone leaves it asking forever.
func TestL2EgressSendsTheAnswerToTheNodeThatAsked(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)
	ports.segment.recordAsk(t, host2Address, askingNode, 0)
	host := bpftest.MAC(1)

	watched := ports.watch(t)
	verdict := bpftest.Run(t, ports.program, answerTo(t, gatewayMAC, host, host2Address), ports.pod1)

	if verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want the frame dropped after the copies (%d)", verdict, bpftest.ActShot)
	}
	if delivered := watched.Delivered(t, ports.tunnel); delivered != 1 {
		t.Errorf("the overlay carried %d copies of the answer, want the node that asked to get one", delivered)
	}
}

// Nothing is sent when nobody asked. Without a record the answer takes
// the shared path alone, and an empty flood list means it goes
// nowhere.
func TestL2EgressSendsNothingOverTheOverlayWhenNobodyAsked(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)
	host := bpftest.MAC(1)

	watched := ports.watch(t)
	bpftest.Run(t, ports.program, answerTo(t, gatewayMAC, host, host2Address), ports.pod1)

	if delivered := watched.Delivered(t, ports.tunnel); delivered != 0 {
		t.Errorf("the overlay carried %d copies of an answer no node asked for", delivered)
	}
}

// A record older than its lifetime names a node that has stopped
// asking. Sending the answer there would leave whoever is asking now
// waiting another round, so the record is not used.
func TestL2EgressIgnoresAnAskOlderThanItsLifetime(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)
	ports.segment.recordAsk(t, host2Address, askingNode, l2.ArpAskerTTL)
	host := bpftest.MAC(1)

	watched := ports.watch(t)
	bpftest.Run(t, ports.program, answerTo(t, gatewayMAC, host, host2Address), ports.pod1)

	if delivered := watched.Delivered(t, ports.tunnel); delivered != 0 {
		t.Errorf("the overlay carried %d copies of an answer to a node that stopped asking", delivered)
	}
}

// The shared copy and the answer are two separate things and both go
// out. The nodes that hold a port read the address out of the shared
// copy and have it before they ever need it; the node that asked has
// no port and gets the answer addressed to it.
func TestL2EgressSharesTheAnswerAndStillAnswersTheNodeThatAsked(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)
	ports.segment.addRemoteNode(t, sharingNode)
	ports.segment.recordAsk(t, host2Address, askingNode, 0)
	host := bpftest.MAC(1)

	watched := ports.watch(t)
	bpftest.Run(t, ports.program, answerTo(t, gatewayMAC, host, host2Address), ports.pod1)

	if delivered := watched.Delivered(t, ports.tunnel); delivered != 2 {
		t.Errorf("the overlay carried %d copies, want one shared and one for the node that asked", delivered)
	}
}

// A node the shared copy already reaches is not sent a second one. The
// answer would be read twice and nothing would come of it, but the
// segment would carry one more frame than it has to.
func TestL2EgressSendsOneCopyToANodeTheSharedAnswerReaches(t *testing.T) {
	ports := newL2EgressPorts(t)
	gatewayMAC := bpftest.MAC(0xfe)
	ports.segment.addGatewayPort(t, ports.pod3, gatewayMAC)
	ports.segment.addRemoteNode(t, sharingNode)
	ports.segment.recordAsk(t, host2Address, sharingNode, 0)
	host := bpftest.MAC(1)

	watched := ports.watch(t)
	bpftest.Run(t, ports.program, answerTo(t, gatewayMAC, host, host2Address), ports.pod1)

	if delivered := watched.Delivered(t, ports.tunnel); delivered != 1 {
		t.Errorf("the overlay carried %d copies to one node, want 1", delivered)
	}
}

// The record is read for answers to the gateway and for nothing else.
// An ARP reply between two workloads is the segment's own business and
// goes to the one port that holds the MAC, whoever else happens to be
// waiting for that address.
func TestL2EgressLeavesAnAnswerBetweenWorkloadsAlone(t *testing.T) {
	ports := newL2EgressPorts(t)
	ports.segment.addGatewayPort(t, ports.pod3, bpftest.MAC(0xfe))
	ports.segment.recordAsk(t, host2Address, askingNode, 0)
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

// arpUnicastPinPath is where the round-trip test below pins the maps
// of the objects it loads. It has to sit on bpffs and must not be the
// path a daemon on this host is using.
const arpUnicastPinPath = "/sys/fs/bpf/juneau-l2-arp-unicast"

// answerPath is one L2Network with both halves of the answer path on
// it: the program that reads a question off the overlay and the one
// that sends the answer back over it, loaded under a single pin path
// so their maps are one kernel object the way they are on a node.
//
// The overlay device is real and points at this host, so a frame this
// node sends to loopbackVTEP comes back in through the same device.
// That is what makes the destination of a unicast readable: a dummy
// device counts frames but says nothing about the tunnel key stamped
// on them.
type answerPath struct {
	l2Egress   *program.L2Egress
	fdb        *l2.Table
	arpAsker   *l2.Table
	bumLocal   *l2.Table
	vxlan      bpftest.Device
	host       bpftest.Device
	hostMAC    net.HardwareAddr
	gateway    bpftest.Device
	gatewayMAC net.HardwareAddr
}

func newAnswerPath(t *testing.T) *answerPath {
	t.Helper()
	bpftest.Require(t)
	bpftest.Netns(t)

	vxlan := buildOverlayDevice(t)

	if err := os.RemoveAll(arpUnicastPinPath); err != nil {
		t.Fatalf("clear the pin path: %v", err)
	}
	if err := os.Mkdir(arpUnicastPinPath, 0o700); err != nil {
		t.Skipf("cannot pin under bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(arpUnicastPinPath) })

	l2Egress, err := program.NewL2Egress(arpUnicastPinPath)
	if err != nil {
		t.Fatalf("load l2_egress: %+v", err)
	}
	t.Cleanup(func() { _ = l2Egress.Close() })

	// NewVxlanIngress names the tunnel device for the whole data plane
	// and attaches itself where the daemon attaches it, so nothing here
	// has to repeat either.
	vxlanIngress, err := program.NewVxlanIngress(arpUnicastPinPath, vxlan.Index)
	if err != nil {
		t.Fatalf("load vxlan_ingress: %+v", err)
	}
	t.Cleanup(func() { _ = vxlanIngress.Close() })

	path := &answerPath{
		l2Egress:   l2Egress,
		fdb:        l2.NewTable("fdb", l2Egress.Objs.L2Fdb, l2Egress.MapSpecs.L2FdbInner),
		arpAsker:   l2.NewTable("arp-asker", l2Egress.Objs.L2ArpAsker, l2Egress.MapSpecs.L2ArpAskerInner),
		bumLocal:   l2.NewTable("bum-local", l2Egress.Objs.L2BumLocal, l2Egress.MapSpecs.L2BumLocalInner),
		vxlan:      vxlan,
		host:       bpftest.Dummy(t, "pod1"),
		hostMAC:    bpftest.MAC(1),
		gateway:    bpftest.Dummy(t, "l2gw"),
		gatewayMAC: bpftest.MAC(0xfe),
	}
	tables := reconciler.L2NetworkTables{
		Fdb:       path.fdb,
		BumLocal:  path.bumLocal,
		BumRemote: l2.NewTable("bum-remote", l2Egress.Objs.L2BumRemote, l2Egress.MapSpecs.L2BumRemoteInner),
		Arp:       l2.NewTable("arp", l2Egress.Objs.L2Arp, l2Egress.MapSpecs.L2ArpInner),
		ArpProbe:  l2.NewTable("arp-probe", l2Egress.Objs.L2ArpProbe, l2Egress.MapSpecs.L2ArpProbeInner),
		ArpAsker:  path.arpAsker,
	}
	t.Cleanup(func() {
		for _, table := range []*l2.Table{path.fdb, path.bumLocal, path.arpAsker} {
			if err := table.CloseAll(); err != nil {
				t.Errorf("close the per-VNI tables: %v", err)
			}
		}
	})
	BringUpSegment(t, l2Egress.Objs.L2NetworkMap, tables)

	if err := l2Egress.Objs.L2Ifindex.Update(
		&bpf.PodEgressL2IfindexKey{Ifindex: uint32(path.host.Index)},
		&bpf.PodEgressL2IfindexVal{Vni: testVNI},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the segment behind %s: %v", path.host.Name, err)
	}
	if err := path.bumLocal.AddMember(testVNI, uint32(path.host.Index)); err != nil {
		t.Fatalf("add the host to the local flood list: %v", err)
	}
	StandUpGatewayPort(t, reconciler.L2GatewayMaps{
		Gateway:       l2Egress.Objs.L2Gateway,
		Subnet:        l2Egress.Objs.SubnetMap,
		IfindexSubnet: l2Egress.Objs.IfindexSubnet,
		Ifindex:       l2Egress.Objs.L2Ifindex,
		Fdb:           path.fdb,
		BumLocal:      path.bumLocal,
	}, path.gateway, path.gatewayMAC, 0, 0)

	return path
}

// awaitHeldBy waits for the segment to place a MAC on a node rather
// than on a local port. The frame travels through the kernel after the
// program returns, so the table cannot be read right away.
func (p *answerPath) awaitHeldBy(t *testing.T, mac net.HardwareAddr) bpf.PodEgressL2FdbVal {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if entry, ok := lookupFdb(t, p.fdb, mac); ok && entry.VtepIp != 0 {
			return entry
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never reached the segment as a MAC held by another node", mac)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTheAnswerCrossesTheOverlayToTheNodeThatAsked drives both halves
// in one run, over a real overlay device.
//
// A gateway on another node asks the segment for an address. The
// question arrives here, the host answers it, and the answer has to go
// back to the node that asked — which holds no port on this segment,
// so no flood list names it and nothing else would carry it there.
//
// The proof is what the segment learns afterwards. Nothing but the
// answer leaves this node, and the only address it can be sent to is
// the one the question came from, so the answer coming back in through
// the overlay device and moving the host's MAC off its local port says
// the tunnel key named that node and that VNI.
func TestTheAnswerCrossesTheOverlayToTheNodeThatAsked(t *testing.T) {
	path := newAnswerPath(t)

	deliverOverOverlay(t, testVNI, gatewayQuestion(t, path.gatewayMAC, host2Address))
	awaitAsker(t, path.arpAsker, host2Address)

	answer := answerTo(t, path.gatewayMAC, path.hostMAC, host2Address)
	bpftest.Run(t, path.l2Egress.Objs.TcL2Egress, answer, path.host)

	entry := path.awaitHeldBy(t, path.hostMAC)
	if want := hostOrderIPv4(t, loopbackVTEP); entry.VtepIp != want {
		t.Errorf("the answer came back from %d, want the node that asked (%d)", entry.VtepIp, want)
	}
}
