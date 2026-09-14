package program_test

import (
	"net"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

// The addresses and MACs of the NICs these tests build.
const (
	webElasticIP = "203.0.113.10"
	dbElasticIP  = "203.0.113.20"
)

var (
	webPodMAC  = bpftest.MAC(0x10)
	webHostMAC = bpftest.MAC(0x11)
	dbPodMAC   = bpftest.MAC(0x20)
)

// The NIC holds only a /32 and reaches everything through an onlink
// default route to PodElasticIPGateway. Nothing on the host owns that
// address and the host has no proxy ARP, so the only answer the Pod ever
// gets comes from pod_egress, and it names the host side of the veth.
func TestPodEgressAnswersARPForTheGatewayOfANICOnAnElasticIP(t *testing.T) {
	node := newExternalNode(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	request := bpftest.Frame(t, bpftest.Broadcast, webPodMAC, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, webPodMAC, webElasticIP,
			net.HardwareAddr{0, 0, 0, 0, 0, 0}, juneauv1alpha1.PodElasticIPGateway))

	verdict, out := bpftest.RunFrame(t, node.podEgress.Objs.TcPodEgress, request, web.veth)
	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want the answer sent back out of the veth (%d)", verdict, bpftest.ActRedirect)
	}

	reply := readARP(t, out)
	if reply.opcode != bpftest.ARPReply {
		t.Errorf("opcode %d, want a reply", reply.opcode)
	}
	if reply.destination.String() != webPodMAC.String() || reply.source.String() != webHostMAC.String() {
		t.Errorf("the reply goes %s -> %s, want %s -> %s", reply.source, reply.destination, webHostMAC, webPodMAC)
	}
	if reply.senderMAC.String() != webHostMAC.String() || reply.senderIP.String() != juneauv1alpha1.PodElasticIPGateway {
		t.Errorf("the reply says %s is at %s, want %s at %s",
			reply.senderIP, reply.senderMAC, juneauv1alpha1.PodElasticIPGateway, webHostMAC)
	}
	if reply.targetMAC.String() != webPodMAC.String() || reply.targetIP.String() != webElasticIP {
		t.Errorf("the reply is for %s at %s, want %s at %s", reply.targetIP, reply.targetMAC, webElasticIP, webPodMAC)
	}
}

// The node reaches the Pod over the host route to its ElasticIP, so the
// kernel asks the Pod for its MAC and must get the answer.
func TestPodEgressHandsTheARPReplyOfANICOnAnElasticIPToTheNode(t *testing.T) {
	node := newExternalNode(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	reply := bpftest.Frame(t, webHostMAC, webPodMAC, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPReply, webPodMAC, webElasticIP, webHostMAC, "192.0.2.20"))

	if verdict := bpftest.Run(t, node.podEgress.Objs.TcPodEgress, reply, web.veth); verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the reply handed to the kernel (%d)", verdict, bpftest.ActOK)
	}
}

// The veth has no other neighbour than the gateway, and the Pod speaks for
// no address but its ElasticIP. Anything else would teach the node, or
// ask it about, addresses the NIC does not hold.
func TestPodEgressDropsEveryOtherARPOfANICOnAnElasticIP(t *testing.T) {
	node := newExternalNode(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	// No subtests: they run on another goroutine, which is outside the
	// network namespace this one is pinned to.
	for name, payload := range map[string][]byte{
		"a request for another address": bpftest.ARP(t, bpftest.ARPRequest, webPodMAC, webElasticIP,
			net.HardwareAddr{0, 0, 0, 0, 0, 0}, "192.0.2.20"),
		"a reply for another address": bpftest.ARP(t, bpftest.ARPReply, webPodMAC, dbElasticIP,
			webHostMAC, "192.0.2.20"),
	} {
		frame := bpftest.Frame(t, bpftest.Broadcast, webPodMAC, bpftest.EtherTypeARP, payload)
		if verdict := bpftest.Run(t, node.podEgress.Objs.TcPodEgress, frame, web.veth); verdict != bpftest.ActShot {
			t.Errorf("%s: verdict %d, want a drop (%d)", name, verdict, bpftest.ActShot)
		}
	}
}

// A NIC on an ElasticIP is on the internet as itself: no SNAT, so what it
// sends leaves the node with the ElasticIP as its source. The node does
// the routing, and the frame goes out of the interface and to the next
// hop the host FIB names.
func TestPodEgressRoutesWhatANICOnAnElasticIPSendsThroughTheHost(t *testing.T) {
	node := newExternalNode(t)
	node.addUplink(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	frame := bpftest.Frame(t, webHostMAC, webPodMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, webElasticIP, internetPeer, 40000, 443))
	verdict, out := bpftest.RunFrame(t, node.podEgress.Objs.TcPodEgress, frame, web.veth)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want the packet sent out of the uplink (%d)", verdict, bpftest.ActRedirect)
	}
	if got := net.HardwareAddr(out[0:6]); got.String() != routerMAC.String() {
		t.Errorf("the packet leaves for %s, want the router %s", got, routerMAC)
	}
	if got := net.HardwareAddr(out[6:12]); got.String() != uplinkMAC.String() {
		t.Errorf("the packet leaves from %s, want the uplink %s", got, uplinkMAC)
	}
	if got := bpftest.SourceAddress(t, out); got != webElasticIP {
		t.Errorf("the packet leaves with source %s, want the ElasticIP %s", got, webElasticIP)
	}
}

// kubelet reaches a Pod whose eth0 carries an ElasticIP over the host
// route to it, and the reply comes back to an address of the node. The
// host FIB does not forward that, and the node's own stack has to have it.
func TestPodEgressHandsWhatANICOnAnElasticIPSendsToTheNodeToTheKernel(t *testing.T) {
	node := newExternalNode(t)
	node.addUplink(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	reply := bpftest.Frame(t, webHostMAC, webPodMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, webElasticIP, nodeAddress, 8080, 51000))

	if verdict := bpftest.Run(t, node.podEgress.Objs.TcPodEgress, reply, web.veth); verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the reply handed to the kernel (%d)", verdict, bpftest.ActOK)
	}
}

// The NIC is on the internet as its ElasticIP and as nothing else. With no
// SNAT in the way, a source it does not hold would leave the node as it
// stands.
func TestPodEgressDropsWhatANICOnAnElasticIPSendsFromAnotherAddress(t *testing.T) {
	node := newExternalNode(t)
	node.addUplink(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	for name, destination := range map[string]string{
		"to the internet": internetPeer,
		"to the node":     nodeAddress,
	} {
		frame := bpftest.Frame(t, webHostMAC, webPodMAC, bpftest.EtherTypeIPv4,
			bpftest.TCPv4(t, dbElasticIP, destination, 40000, 443))
		if verdict := bpftest.Run(t, node.podEgress.Objs.TcPodEgress, frame, web.veth); verdict != bpftest.ActShot {
			t.Errorf("%s: verdict %d, want a drop (%d)", name, verdict, bpftest.ActShot)
		}
	}
}

// Only IPv4 and ARP are carried for the NIC. An ElasticIP is an IPv4
// address, and the NIC is given nothing else to speak with.
func TestPodEgressDropsWhatANICOnAnElasticIPSendsThatIsNotIPv4(t *testing.T) {
	node := newExternalNode(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	frame := bpftest.Frame(t, webHostMAC, webPodMAC, bpftest.EtherTypeIPv6, make([]byte, 40))
	if verdict := bpftest.Run(t, node.podEgress.Objs.TcPodEgress, frame, web.veth); verdict != bpftest.ActShot {
		t.Fatalf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
}

// A frame that reaches the Pod has been routed by the node, so it comes
// from the gateway: the MAC the Pod resolved PodElasticIPGateway to. The
// hooks that send it here leave the source of the last hop in place, so
// the last hook before the Pod writes it.
func TestPodIngressSendsWhatReachesANICOnAnElasticIPFromTheGateway(t *testing.T) {
	node := newExternalNode(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	frame := bpftest.Frame(t, webPodMAC, dbPodMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, dbElasticIP, webElasticIP, 40000, 80))
	verdict, out := bpftest.RunFrame(t, node.podIngress.Objs.TcPodIngress, frame, web.veth)

	if verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the frame delivered (%d)", verdict, bpftest.ActOK)
	}
	if got := net.HardwareAddr(out[6:12]); got.String() != webHostMAC.String() {
		t.Errorf("the frame reaches the Pod from %s, want the gateway %s", got, webHostMAC)
	}
	if got := net.HardwareAddr(out[0:6]); got.String() != webPodMAC.String() {
		t.Errorf("the frame reaches %s, want the Pod %s", got, webPodMAC)
	}
}

// The node asks the Pod for its MAC before it can send it anything.
func TestPodIngressLetsTheNodeAskANICOnAnElasticIPForItsMAC(t *testing.T) {
	node := newExternalNode(t)
	web := node.addLocalNIC(t, "web", webElasticIP, webPodMAC, webHostMAC)

	request := bpftest.Frame(t, bpftest.Broadcast, webHostMAC, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, webHostMAC, "192.0.2.20",
			net.HardwareAddr{0, 0, 0, 0, 0, 0}, webElasticIP))

	if verdict := bpftest.Run(t, node.podIngress.Objs.TcPodIngress, request, web.veth); verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the request delivered (%d)", verdict, bpftest.ActOK)
	}
}
