package program_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

// An address juneau owns is decided by node_ingress: a direct ElasticIP on
// this node or another, the address of a NATGateway, a LoadBalancer VIP.
// Sent out of the uplink, such a packet would have to come back from the
// router, which it may never do. pod_egress hands it to node_ingress
// instead, untouched: the host FIB, which would have written the router's
// MAC into it, never sees it.
func TestPodEgressHandsWhatANICOnAnElasticIPSendsToAnOwnedAddressToNodeIngress(t *testing.T) {
	node := newExternalNode(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)
	node.addRemoteNIC(t, "db", dbElasticIP, dbPodMAC)
	node.claimPool(t, "198.51.100.64/26")

	for name, destination := range map[string]string{
		"a direct ElasticIP on another node": dbElasticIP,
		"an address of a claimed pool":       "198.51.100.70",
	} {
		frame := bpftest.Frame(t, webHostMAC, webPodMAC, bpftest.EtherTypeIPv4,
			bpftest.TCPv4(t, webElasticIP, destination, 40000, 443))
		verdict, out := bpftest.RunFrame(t, node.podEgress.Objs.TcPodEgress, frame, web.veth)

		if verdict != bpftest.ActRedirect {
			t.Errorf("%s: verdict %d, want the packet redirected (%d)", name, verdict, bpftest.ActRedirect)
			continue
		}
		if got := net.HardwareAddr(out[0:6]); got.String() != webHostMAC.String() {
			t.Errorf("%s: the packet was sent to %s, want it untouched for node_ingress", name, got)
		}
	}
}

// The whole way, on the real hooks: the Pod on one NIC sends to the
// ElasticIP of a NIC on the same node. pod_egress hands the packet to the
// ingress of the uplink, node_ingress runs there and places the packet on
// the other NIC's veth. The packet arriving there is the proof: pod_egress
// alone has no path to it, since the host routes that address out of the
// uplink.
func TestAHairpinReachesADirectElasticIPOnTheSameNodeThroughNodeIngress(t *testing.T) {
	node := newExternalNode(t)
	hostEnd, podEnd := bpftest.Veth(t, "web", "web-pod", webHostMAC)
	node.addLocalNICOn(t, hostEnd, "web", webElasticIP, webPodMAC, webHostMAC)
	db := node.addLocalNIC(t, "db", dbElasticIP, dbPodMAC, bpftest.MAC(0x21))

	attached, err := ebpflink.AttachTCX(ebpflink.TCXOptions{
		Program:   node.podEgress.Objs.TcPodEgress,
		Interface: hostEnd.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		t.Fatalf("attach pod_egress to the veth: %v", err)
	}
	t.Cleanup(func() { _ = attached.Close() })

	watched := bpftest.WatchPorts(t, db.veth, node.uplink)
	bpftest.Send(t, podEnd, bpftest.Frame(t, webHostMAC, webPodMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, webElasticIP, dbElasticIP, 40000, 5432)))

	awaitDelivered(t, watched, db.veth, 1)
	if got := watched.Delivered(t, node.uplink); got != 0 {
		t.Errorf("the uplink sent %d frames, want the packet kept on the node", got)
	}
}
