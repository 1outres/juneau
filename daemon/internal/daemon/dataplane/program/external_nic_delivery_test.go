package program_test

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

// inbound is a packet for an address as it reaches the node from the
// router on the uplink.
func inbound(t *testing.T, destination string) []byte {
	t.Helper()
	return bpftest.Frame(t, uplinkMAC, routerMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, internetPeer, destination, 51000, 443))
}

// A packet for an ElasticIP a NIC on this node carries is placed on the
// NIC's veth as it is: no NAT, only the destination MAC of the NIC.
func TestNodeIngressDeliversADirectElasticIPToTheNICOnThisNode(t *testing.T) {
	node := newExternalNode(t)
	node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	verdict, out := bpftest.RunFrame(t, node.nodeIngress.Objs.TcNodeIngress, inbound(t, webElasticIP), node.uplink)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want the packet redirected to the veth (%d)", verdict, bpftest.ActRedirect)
	}
	if got := net.HardwareAddr(out[0:6]); got.String() != webPodMAC.String() {
		t.Errorf("the packet goes to %s, want the NIC %s", got, webPodMAC)
	}
	if got := bpftest.SourceAddress(t, out); got != internetPeer {
		t.Errorf("the packet has source %s, want %s untouched", got, internetPeer)
	}
}

// BGP ECMP lands a packet for the address on any node. The node that has
// it sends it over the overlay to the node the NIC runs on.
func TestNodeIngressSendsADirectElasticIPOnAnotherNodeOverTheOverlay(t *testing.T) {
	node := newExternalNode(t)
	node.addRemoteNIC(t, "db", dbElasticIP, dbPodMAC)

	verdict, out := bpftest.RunFrame(t, node.nodeIngress.Objs.TcNodeIngress, inbound(t, dbElasticIP), node.uplink)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want the packet redirected to the overlay (%d)", verdict, bpftest.ActRedirect)
	}
	if got := net.HardwareAddr(out[0:6]); got.String() != dbPodMAC.String() {
		t.Errorf("the packet goes to %s, want the NIC %s", got, dbPodMAC)
	}
}

// The disposition only replaces the drop for addresses a NIC carries. An
// owned address nothing is attached to is still dropped.
func TestNodeIngressStillDropsAnOwnedAddressNoNICCarries(t *testing.T) {
	node := newExternalNode(t)
	node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)
	node.claimPool(t, "203.0.113.0/24")

	if verdict := bpftest.Run(t, node.nodeIngress.Objs.TcNodeIngress, inbound(t, "203.0.113.99"), node.uplink); verdict != bpftest.ActShot {
		t.Fatalf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
}

// The address is known but the NIC is not resolved on its network yet,
// for instance while the endpoint of a NIC is still being programmed.
func TestNodeIngressDropsADirectElasticIPWhoseNICIsNotResolved(t *testing.T) {
	node := newExternalNode(t)
	node.claimPool(t, "203.0.113.0/24")
	if err := node.podEgress.Objs.ElasticIpDirect.Update(
		&bpf.PodEgressElasticIpDirectKey{Addr: hostOrderIPv4(t, webElasticIP)},
		&bpf.PodEgressElasticIpDirectVal{NetworkId: testExternalNetworkID},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("write elastic_ip_direct: %v", err)
	}

	if verdict := bpftest.Run(t, node.nodeIngress.Objs.TcNodeIngress, inbound(t, webElasticIP), node.uplink); verdict != bpftest.ActShot {
		t.Fatalf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
}

// awaitDelivered waits for a device to have been handed want frames. A
// frame the overlay carries is delivered in a softirq after the write
// returns.
func awaitDelivered(t *testing.T, watched *bpftest.Ports, device bpftest.Device, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for watched.Delivered(t, device) < want {
		if time.Now().After(deadline) {
			t.Fatalf("%s was handed %d frames, want %d", device.Name, watched.Delivered(t, device), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The node the other node sent the packet to over the overlay hands it to
// the NIC's veth.
func TestVxlanIngressDeliversADirectElasticIPToTheNICOnThisNode(t *testing.T) {
	node := newExternalNode(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	watched := bpftest.WatchPorts(t, web.veth)
	deliverOverOverlay(t, testExternalNetworkID,
		bpftest.Frame(t, webPodMAC, routerMAC, bpftest.EtherTypeIPv4,
			bpftest.TCPv4(t, internetPeer, webElasticIP, 51000, 443)))

	awaitDelivered(t, watched, web.veth, 1)
}

// A network ID is only good for the NICs on that ExternalNetwork. A frame
// that names another one does not reach the veth, even when the forwarding
// table has been made to point there.
func TestVxlanIngressKeepsADirectElasticIPOnItsOwnNetwork(t *testing.T) {
	node := newExternalNode(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)
	strayNetworkID := uint32(testExternalNetworkID + 1)
	if err := node.vxlanIngress.Objs.Fdb.Update(
		&bpf.PodEgressFdbKey{SubnetId: strayNetworkID, Mac: macArray(t, webPodMAC)},
		&bpf.PodEgressFdbVal{Ifindex: uint32(web.veth.Index)},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("point a stray network at the veth: %v", err)
	}

	frame := bpftest.Frame(t, webPodMAC, routerMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, internetPeer, webElasticIP, 51000, 443))
	watched := bpftest.WatchPorts(t, web.veth)
	deliverOverOverlay(t, strayNetworkID, frame)
	// The frame on the right network goes second, so once it has arrived
	// the stray one has had every chance to arrive before it.
	deliverOverOverlay(t, testExternalNetworkID, frame)

	awaitDelivered(t, watched, web.veth, 1)
	if got := watched.Delivered(t, web.veth); got != 1 {
		t.Errorf("the veth was handed %d frames, want only the one on its own network", got)
	}
}
