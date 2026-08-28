package reconciler

import (
	"context"
	"fmt"
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/l2"
)

const (
	gatewayTestVNI     = 4242
	gatewayTestIfindex = 31
	gatewayTestMAC     = "02:00:00:00:00:fe"
)

// fakeL2GatewayPorts stands in for the veth pairs the daemon builds. A
// real one needs netlink and CAP_NET_ADMIN.
type fakeL2GatewayPorts struct {
	ifindex uint32
	ports   map[uint32]net.HardwareAddr
	fail    error
}

func newFakeL2GatewayPorts() *fakeL2GatewayPorts {
	return &fakeL2GatewayPorts{ifindex: gatewayTestIfindex, ports: make(map[uint32]net.HardwareAddr)}
}

func (f *fakeL2GatewayPorts) Ensure(vni uint32, mac net.HardwareAddr) (uint32, error) {
	if f.fail != nil {
		return 0, f.fail
	}
	f.ports[vni] = mac
	return f.ifindex, nil
}

func (f *fakeL2GatewayPorts) Remove(vni uint32) error {
	delete(f.ports, vni)
	return nil
}

type l2GatewayFixture struct {
	reconciler    *L2Gateway
	ports         *fakeL2GatewayPorts
	gatewayMap    *fakeBpfMap
	subnetMap     *fakeBpfMap
	ifindexSubnet *fakeBpfMap
	ifindexMap    *fakeBpfMap
	fdb           *fakeL2Table
	bumLocal      *fakeL2Table
}

func newL2GatewayFixture(t *testing.T, objs ...runtime.Object) *l2GatewayFixture {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...).Build()
	f := &l2GatewayFixture{
		ports:         newFakeL2GatewayPorts(),
		gatewayMap:    newFakeBpfMap(),
		subnetMap:     newFakeBpfMap(),
		ifindexSubnet: newFakeBpfMap(),
		ifindexMap:    newFakeBpfMap(),
		fdb:           newFakeL2Table(),
		bumLocal:      newFakeL2Table(),
	}
	f.reconciler = NewL2Gateway(cl, f.ports, L2GatewayMaps{
		Gateway:       f.gatewayMap,
		Subnet:        f.subnetMap,
		IfindexSubnet: f.ifindexSubnet,
		Ifindex:       f.ifindexMap,
		Fdb:           f.fdb,
		BumLocal:      f.bumLocal,
	}, "node-a")
	return f
}

func newGatewayTestVpc() *juneauv1alpha1.Vpc {
	return &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: "vpc-a"},
		Status:     juneauv1alpha1.VpcStatus{VpcID: 11, MainRouteTable: "rt-main"},
	}
}

func newGatewayTestRouteTable(name string, tableID uint32) *juneauv1alpha1.RouteTable {
	return &juneauv1alpha1.RouteTable{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.RouteTableSpec{Vpc: "vpc-a"},
		Status:     juneauv1alpha1.RouteTableStatus{TableID: tableID},
	}
}

func newGatewayTestNetwork() *juneauv1alpha1.L2Network {
	return &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
		Spec: juneauv1alpha1.L2NetworkSpec{
			Vpc:     "vpc-a",
			CIDR:    "10.60.0.0/24",
			Gateway: &juneauv1alpha1.L2NetworkGateway{},
		},
		Status: juneauv1alpha1.L2NetworkStatus{
			VNI:        gatewayTestVNI,
			Gateway:    "10.60.0.1",
			GatewayMAC: gatewayTestMAC,
		},
	}
}

func newGatewayTestEndpoint(nodeName string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "lab-a.eth1"},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			L2Network: "lab-net",
			NodeName:  nodeName,
		},
	}
}

func gatewayMACArray(t *testing.T) [6]uint8 {
	t.Helper()
	mac, err := net.ParseMAC(gatewayTestMAC)
	if err != nil {
		t.Fatalf("parse the test MAC: %v", err)
	}
	var out [6]uint8
	copy(out[:], mac)
	return out
}

func TestL2GatewayStandsUpThePortOfASegment(t *testing.T) {
	f := newL2GatewayFixture(t, newGatewayTestNetwork(), newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), newGatewayTestEndpoint("node-a"))

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if _, ok := f.ports.ports[gatewayTestVNI]; !ok {
		t.Fatal("no veth was built for the segment")
	}

	mac := gatewayMACArray(t)
	if got, ok := f.gatewayMap.entries[bpf.PodEgressL2GatewayKey{Vni: gatewayTestVNI}]; !ok {
		t.Error("l2_gateway has no entry for the segment")
	} else if want := (bpf.PodEgressL2GatewayVal{Ifindex: gatewayTestIfindex, Mac: mac}); got != want {
		t.Errorf("l2_gateway = %+v, want %+v", got, want)
	}

	if got, ok := f.subnetMap.entries[bpf.PodEgressSubnetKey{SubnetId: gatewayTestVNI}]; !ok {
		t.Error("subnet_map has no entry for the segment")
	} else {
		want := bpf.PodEgressSubnetVal{
			TableId: 7,
			VpcId:   11,
			GwMac:   mac,
			GwAddr:  0x0a3c0001,
			Mask:    0xffffff00,
		}
		if got != want {
			t.Errorf("subnet_map = %+v, want %+v", got, want)
		}
	}

	if got, ok := f.ifindexSubnet.entries[bpf.PodEgressIfindexSubnetKey{Ifindex: gatewayTestIfindex}]; !ok {
		t.Error("ifindex_subnet has no entry for the gateway veth")
	} else if got.(bpf.PodEgressIfindexSubnetVal).SubnetId != gatewayTestVNI {
		t.Errorf("ifindex_subnet = %+v, want the segment behind the veth", got)
	}

	if got, ok := f.ifindexMap.entries[bpf.PodEgressL2IfindexKey{Ifindex: gatewayTestIfindex}]; !ok {
		t.Error("l2_ifindex has no entry for the gateway veth")
	} else if want := (bpf.PodEgressL2IfindexVal{Vni: gatewayTestVNI}); got != want {
		t.Errorf("l2_ifindex = %+v, want %+v", got, want)
	}

	if got, ok := f.bumLocal.value(gatewayTestVNI, uint32(gatewayTestIfindex)); !ok {
		t.Error("the gateway is not on the local flood list")
	} else if want := l2.PortFlagPresent | l2.PortFlagGateway; got != want {
		t.Errorf("the gateway is on the flood list as %v, want %v", got, want)
	}

	if got, ok := f.fdb.value(gatewayTestVNI, bpf.PodEgressL2FdbKey{Mac: mac}); !ok {
		t.Error("the forwarding table has no entry for the gateway MAC")
	} else {
		want := bpf.PodEgressL2FdbVal{Ifindex: gatewayTestIfindex, Flags: l2.FdbFlagGateway}
		if got != want {
			t.Errorf("the gateway entry = %+v, want %+v", got, want)
		}
	}
}

// spec.gateway.routeTable picks which RouteTable governs what leaves
// the segment. Without it the Vpc's main one applies.
func TestL2GatewayTakesTheRouteTableTheSegmentNames(t *testing.T) {
	network := newGatewayTestNetwork()
	network.Spec.Gateway.RouteTable = "rt-lab"
	f := newL2GatewayFixture(t, network, newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), newGatewayTestRouteTable("rt-lab", 9),
		newGatewayTestEndpoint("node-a"))

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := f.subnetMap.entries[bpf.PodEgressSubnetKey{SubnetId: gatewayTestVNI}]
	if id := got.(bpf.PodEgressSubnetVal).TableId; id != 9 {
		t.Errorf("subnet_map names route table %d, want the one the gateway asked for (9)", id)
	}
}

// The ACL of a segment is enforced at the gateway, which is the only
// place the L2 data plane meets a program that reads policy at all.
func TestL2GatewayProgramsTheNetworkACLOfTheSegment(t *testing.T) {
	network := newGatewayTestNetwork()
	network.Spec.NetworkACL = "acl-a"
	network.Status.NetworkACL = &juneauv1alpha1.NetworkACLRef{Name: "acl-a", ACLID: 5}
	f := newL2GatewayFixture(t, network, newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), newGatewayTestEndpoint("node-a"))

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := f.subnetMap.entries[bpf.PodEgressSubnetKey{SubnetId: gatewayTestVNI}]
	if id := got.(bpf.PodEgressSubnetVal).AclId; id != 5 {
		t.Errorf("subnet_map carries acl %d, want 5", id)
	}
}

func TestL2GatewayLeavesASegmentWithNoGatewayAlone(t *testing.T) {
	network := newGatewayTestNetwork()
	network.Spec.Gateway = nil
	network.Status.Gateway = ""
	network.Status.GatewayMAC = ""
	f := newL2GatewayFixture(t, network, newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), newGatewayTestEndpoint("node-a"))

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(f.ports.ports) != 0 {
		t.Error("a veth was built for a segment that declares no gateway")
	}
	if len(f.gatewayMap.entries) != 0 {
		t.Errorf("l2_gateway was written for a segment with no gateway: %v", f.gatewayMap.entries)
	}
}

// The gateway is anycast: every node that holds a port on the segment
// runs one. A node that holds none has nothing to route for.
func TestL2GatewayWaitsForAnEndpointOnThisNode(t *testing.T) {
	f := newL2GatewayFixture(t, newGatewayTestNetwork(), newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), newGatewayTestEndpoint("node-b"))

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(f.ports.ports) != 0 {
		t.Error("a veth was built on a node that holds no port on the segment")
	}
}

// Nothing is programmed under a MAC the controller has not published:
// the daemon does not invent the identity of a port.
func TestL2GatewayWaitsForTheIdentityOfThePort(t *testing.T) {
	network := newGatewayTestNetwork()
	network.Status.GatewayMAC = ""
	f := newL2GatewayFixture(t, network, newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), newGatewayTestEndpoint("node-a"))

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(f.ports.ports) != 0 {
		t.Error("a veth was built before the controller published a MAC for it")
	}
}

func TestL2GatewayTakesThePortDownWhenTheLastEndpointLeaves(t *testing.T) {
	endpoint := newGatewayTestEndpoint("node-a")
	f := newL2GatewayFixture(t, newGatewayTestNetwork(), newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), endpoint)

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := f.reconciler.client.Delete(context.Background(), endpoint); err != nil {
		t.Fatalf("delete the endpoint: %v", err)
	}
	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile after the endpoint left: %v", err)
	}

	assertGatewayGone(t, f)
}

func TestL2GatewayTakesThePortDownWithTheSegment(t *testing.T) {
	f := newL2GatewayFixture(t, newGatewayTestNetwork(), newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), newGatewayTestEndpoint("node-a"))

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := f.reconciler.client.Delete(context.Background(),
		&juneauv1alpha1.L2Network{ObjectMeta: metav1.ObjectMeta{Name: "lab-net"}}); err != nil {
		t.Fatalf("delete the segment: %v", err)
	}
	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile after the segment went away: %v", err)
	}

	assertGatewayGone(t, f)
}

// A pass that fails halfway has to leave nothing recorded, or the
// retry would read a snapshot it never managed to program and decide
// there was nothing left to do.
func TestL2GatewayRetriesAPortItCouldNotBuild(t *testing.T) {
	f := newL2GatewayFixture(t, newGatewayTestNetwork(), newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), newGatewayTestEndpoint("node-a"))
	f.ports.fail = fmt.Errorf("no room for another veth")

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err == nil {
		t.Fatal("Reconcile reported success although the veth was never built")
	}

	f.ports.fail = nil
	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile on the retry: %v", err)
	}
	if _, ok := f.gatewayMap.entries[bpf.PodEgressL2GatewayKey{Vni: gatewayTestVNI}]; !ok {
		t.Error("the retry did not program the port")
	}
}

func assertGatewayGone(t *testing.T, f *l2GatewayFixture) {
	t.Helper()
	if len(f.ports.ports) != 0 {
		t.Error("the veth is still there")
	}
	if len(f.gatewayMap.entries) != 0 {
		t.Errorf("l2_gateway still names the port: %v", f.gatewayMap.entries)
	}
	if len(f.subnetMap.entries) != 0 {
		t.Errorf("subnet_map still describes the segment: %v", f.subnetMap.entries)
	}
	if len(f.ifindexSubnet.entries) != 0 {
		t.Errorf("ifindex_subnet still names the veth: %v", f.ifindexSubnet.entries)
	}
	if len(f.ifindexMap.entries) != 0 {
		t.Errorf("l2_ifindex still names the veth: %v", f.ifindexMap.entries)
	}
	if members := f.bumLocal.list(gatewayTestVNI); len(members) != 0 {
		t.Errorf("the gateway is still on the local flood list: %v", members)
	}
	if _, ok := f.fdb.value(gatewayTestVNI, bpf.PodEgressL2FdbKey{Mac: gatewayMACArray(t)}); ok {
		t.Error("the forwarding table still names the gateway MAC")
	}
}

// A veth the kernel rebuilt comes back under another index. The entries
// under the old one name a port that is gone, but the veth itself is
// the one this pass just brought up.
func TestL2GatewayMovesThePortToANewIfindex(t *testing.T) {
	f := newL2GatewayFixture(t, newGatewayTestNetwork(), newGatewayTestVpc(),
		newGatewayTestRouteTable("rt-main", 7), newGatewayTestEndpoint("node-a"))

	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	const rebuilt = gatewayTestIfindex + 1
	f.ports.ifindex = rebuilt
	if err := f.reconciler.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("Reconcile after the veth came back: %v", err)
	}

	if _, ok := f.ports.ports[gatewayTestVNI]; !ok {
		t.Error("the veth this pass brought up was taken down again")
	}
	if _, ok := f.ifindexMap.entries[bpf.PodEgressL2IfindexKey{Ifindex: gatewayTestIfindex}]; ok {
		t.Error("l2_ifindex still names the veth that is gone")
	}
	if _, ok := f.ifindexSubnet.entries[bpf.PodEgressIfindexSubnetKey{Ifindex: gatewayTestIfindex}]; ok {
		t.Error("ifindex_subnet still names the veth that is gone")
	}
	if members := f.bumLocal.list(gatewayTestVNI); len(members) != 1 || members[0] != rebuilt {
		t.Errorf("the local flood list holds %v, want just the new ifindex %d", members, rebuilt)
	}
	got, ok := f.gatewayMap.entries[bpf.PodEgressL2GatewayKey{Vni: gatewayTestVNI}]
	if !ok {
		t.Fatal("l2_gateway no longer names the port")
	}
	if got.(bpf.PodEgressL2GatewayVal).Ifindex != rebuilt {
		t.Errorf("l2_gateway names ifindex %d, want %d", got.(bpf.PodEgressL2GatewayVal).Ifindex, rebuilt)
	}
}
