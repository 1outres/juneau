package program_test

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/ownedaddr"
)

// externalNICPinPath is where these tests pin the maps of the objects
// they load. It has to sit on bpffs and must not be the path a daemon on
// this host, or another harness in this package, is using.
const externalNICPinPath = "/sys/fs/bpf/juneau-external-nic"

// The ExternalNetwork the NICs in these tests carry their ElasticIPs on,
// and the two nodes they run on.
const (
	testExternalNetwork   = "internet"
	testExternalNetworkID = 4250
	thisNode              = "node-a"
	otherNode             = "node-b"
)

// The node's side of the underlay these tests build: the address of this
// node and of the other one on the uplink, and the router the default
// route goes through.
const (
	nodeAddress      = "192.0.2.20"
	otherNodeAddress = "192.0.2.30"
	routerAddress    = "192.0.2.1"
	internetPeer     = "198.51.100.7"
)

// A second router on the uplink, and the routing table whose default
// route goes through it. Source-based rules send traffic to it.
const (
	policyRouterAddress = "192.0.2.2"
	policyRoutingTable  = 100
)

var (
	uplinkMAC       = bpftest.MAC(0xa0)
	routerMAC       = bpftest.MAC(0xa1)
	policyRouterMAC = bpftest.MAC(0xa2)
)

// endpointReconciler is what every reconciler that reads a
// NetworkEndpoint offers.
type endpointReconciler interface {
	Reconcile(ctx context.Context, key string) error
	Name() string
}

// externalNode is one node as the data plane of a NIC that carries an
// ElasticIP directly sees it. Every program is loaded under one pin path,
// so the maps are one kernel object the way they are on a node, and every
// map entry is written by the reconciler that writes it on a node.
type externalNode struct {
	podEgress    *program.PodEgress
	podIngress   *program.PodIngress
	nodeIngress  *program.NodeIngress
	vxlanIngress *program.VxlanIngress
	uplink       bpftest.Device
	vxlan        bpftest.Device
	owned        *ownedaddr.Store
	client       client.Client
	reconcilers  []endpointReconciler
}

// externalNIC is one NIC on the ExternalNetwork. veth stands in for the
// host side of its veth, and is only built for a NIC on this node.
type externalNIC struct {
	name      string
	elasticIP string
	podMAC    net.HardwareAddr
	hostMAC   net.HardwareAddr
	veth      bpftest.Device
}

func newExternalNode(t *testing.T) *externalNode {
	t.Helper()
	bpftest.Require(t)
	bpftest.Netns(t)

	if err := os.RemoveAll(externalNICPinPath); err != nil {
		t.Fatalf("clear the pin path: %v", err)
	}
	if err := os.Mkdir(externalNICPinPath, 0o700); err != nil {
		t.Skipf("cannot pin under bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(externalNICPinPath) })

	n := &externalNode{
		uplink: buildUplink(t),
		vxlan:  buildOverlayDevice(t),
	}

	var err error
	n.podEgress, err = program.NewPodEgress(externalNICPinPath, 0)
	if err != nil {
		t.Fatalf("load pod_egress: %+v", err)
	}
	t.Cleanup(func() { _ = n.podEgress.Close() })

	n.podIngress, err = program.NewPodIngress(externalNICPinPath)
	if err != nil {
		t.Fatalf("load pod_ingress: %+v", err)
	}
	t.Cleanup(func() { _ = n.podIngress.Close() })

	n.nodeIngress, err = program.NewNodeIngress(externalNICPinPath, n.uplink.Index)
	if err != nil {
		t.Fatalf("load node_ingress: %+v", err)
	}
	t.Cleanup(func() { _ = n.nodeIngress.Close() })

	n.vxlanIngress, err = program.NewVxlanIngress(externalNICPinPath, n.vxlan.Index)
	if err != nil {
		t.Fatalf("load vxlan_ingress: %+v", err)
	}
	t.Cleanup(func() { _ = n.vxlanIngress.Close() })

	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("build the scheme: %v", err)
	}
	n.client = fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		&juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: testExternalNetwork},
			Status:     juneauv1alpha1.ExternalNetworkStatus{NetworkID: testExternalNetworkID},
		},
	).Build()

	n.owned = ownedaddr.NewStore(n.podEgress.Objs.ExternalAddressPools)
	n.reconcilers = []endpointReconciler{
		reconciler.NewPodIface(n.client, n.podEgress, thisNode),
		reconciler.NewArp(n.client, n.podEgress),
		reconciler.NewFdb(n.client, n.podEgress, n.vxlanIngress, thisNode),
		reconciler.NewElasticIPDirect(n.client, n.podEgress, n.owned),
	}
	return n
}

// buildUplink builds the node's uplink the way a node has one: an address
// of the node, a default route through a router whose MAC is already
// resolved, and forwarding on. bpf_fib_lookup reads exactly that.
func buildUplink(t *testing.T) bpftest.Device {
	t.Helper()

	for _, path := range []string{
		"/proc/sys/net/ipv4/conf/all/forwarding",
		"/proc/sys/net/ipv4/conf/default/forwarding",
	} {
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
			t.Fatalf("turn forwarding on in the test namespace: %v", err)
		}
	}

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "uplink", HardwareAddr: uplinkMAC}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatalf("add the uplink: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bring the uplink up: %v", err)
	}
	built, err := netlink.LinkByName("uplink")
	if err != nil {
		t.Fatalf("look up the uplink: %v", err)
	}

	address, err := netlink.ParseAddr(nodeAddress + "/24")
	if err != nil {
		t.Fatalf("parse the node address: %v", err)
	}
	if err := netlink.AddrAdd(built, address); err != nil {
		t.Fatalf("give the uplink the node address: %v", err)
	}

	uplink := bpftest.Device{Name: "uplink", Index: built.Attrs().Index}
	addRouter(t, uplink, routerAddress, routerMAC, unix.RT_TABLE_MAIN)
	return uplink
}

// addRouter puts a router whose MAC is already resolved on the uplink and
// sends the default route of a routing table through it.
func addRouter(t *testing.T, uplink bpftest.Device, address string, mac net.HardwareAddr, table int) {
	t.Helper()

	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    uplink.Index,
		Family:       netlink.FAMILY_V4,
		State:        netlink.NUD_PERMANENT,
		IP:           net.ParseIP(address),
		HardwareAddr: mac,
	}); err != nil {
		t.Fatalf("resolve the router %s: %v", address, err)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: uplink.Index,
		Gw:        net.ParseIP(address),
		Table:     table,
	}); err != nil {
		t.Fatalf("add the default route through %s to table %d: %v", address, table, err)
	}
}

// routeSourceByTable makes the host look up what comes from source in
// table, the way `ip rule add from <source> lookup <table>` does.
func routeSourceByTable(t *testing.T, source string, table int) {
	t.Helper()

	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Src = &net.IPNet{IP: net.ParseIP(source).To4(), Mask: net.CIDRMask(32, 32)}
	rule.Table = table
	if err := netlink.RuleAdd(rule); err != nil {
		t.Fatalf("look up what comes from %s in table %d: %v", source, table, err)
	}
}

// addLocalNIC builds the host side of a NIC's veth on this node and
// publishes the NetworkEndpoint the CNI publishes for it.
func (n *externalNode) addLocalNIC(t *testing.T, name, elasticIP string, podMAC, hostMAC net.HardwareAddr) externalNIC {
	t.Helper()
	return n.addLocalNICOn(t, bpftest.Dummy(t, name), name, elasticIP, podMAC, hostMAC)
}

// addLocalNICOn is addLocalNIC on a device the test built itself, such as
// one end of a real veth pair.
func (n *externalNode) addLocalNICOn(t *testing.T, veth bpftest.Device, name, elasticIP string, podMAC, hostMAC net.HardwareAddr) externalNIC {
	t.Helper()
	nic := externalNIC{
		name:      name,
		elasticIP: elasticIP,
		podMAC:    podMAC,
		hostMAC:   hostMAC,
		veth:      veth,
	}
	endpoint := externalEndpoint(nic, thisNode)
	endpoint.Spec.Attachment = &juneauv1alpha1.NetworkEndpointAttachment{
		Ifindex:        nic.veth.Index,
		HostMACAddress: hostMAC.String(),
	}
	n.publish(t, endpoint)
	return nic
}

// addRemoteNIC publishes the NetworkEndpoint of a NIC that runs on the
// other node, the way this node sees it.
func (n *externalNode) addRemoteNIC(t *testing.T, name, elasticIP string, podMAC net.HardwareAddr) externalNIC {
	t.Helper()
	nic := externalNIC{name: name, elasticIP: elasticIP, podMAC: podMAC}
	endpoint := externalEndpoint(nic, otherNode)
	endpoint.Status.NodeIP = otherNodeAddress
	n.publish(t, endpoint)
	return nic
}

// publish stores an endpoint and runs every reconciler that reads one, as
// the informers of a node do.
func (n *externalNode) publish(t *testing.T, endpoint *juneauv1alpha1.NetworkEndpoint) {
	t.Helper()
	if err := n.client.Create(context.Background(), endpoint); err != nil {
		t.Fatalf("publish the endpoint %s: %v", endpoint.Name, err)
	}
	key := endpoint.Namespace + "/" + endpoint.Name
	for _, r := range n.reconcilers {
		if err := r.Reconcile(context.Background(), key); err != nil {
			t.Fatalf("%s: reconcile %s: %v", r.Name(), key, err)
		}
	}
}

// claimPool takes a whole pool the way the bgp-pool reconciler does.
func (n *externalNode) claimPool(t *testing.T, prefix string) {
	t.Helper()
	key, err := ownedaddr.ParsePrefix(prefix)
	if err != nil {
		t.Fatalf("parse %s: %v", prefix, err)
	}
	if err := n.owned.Scope("bgp-pool").Set("address-pools", []ownedaddr.Key{key}); err != nil {
		t.Fatalf("claim %s: %v", prefix, err)
	}
}

// claimElsewhere records a prefix another node advertises by itself, the
// way the bgp-pool reconciler records the NAPT address of another node.
func (n *externalNode) claimElsewhere(t *testing.T, prefix string) {
	t.Helper()
	key, err := ownedaddr.ParsePrefix(prefix)
	if err != nil {
		t.Fatalf("parse %s: %v", prefix, err)
	}
	claim := ownedaddr.Claim{Key: key, Delivery: ownedaddr.DeliveredElsewhere}
	if err := n.owned.Scope("bgp-pool").SetClaims("elsewhere "+prefix, []ownedaddr.Claim{claim}); err != nil {
		t.Fatalf("claim %s for another node: %v", prefix, err)
	}
}

func externalEndpoint(nic externalNIC, nodeName string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: nic.name + ".eth0"},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:            juneauv1alpha1.EndpointKindPod,
			NodeName:        nodeName,
			ExternalNetwork: testExternalNetwork,
			Address:         nic.elasticIP + "/32",
			MACAddress:      nic.podMAC.String(),
			PodRef:          &juneauv1alpha1.NetworkEndpointPodReference{Name: nic.name, Interface: "eth0", UID: "uid-" + nic.name},
		},
	}
}
