package reconciler

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

func newFibFixture(t *testing.T, objects ...runtime.Object) *Fib {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(juneauv1alpha1.AddToScheme(scheme))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	return &Fib{client: cl, snapshots: make(map[string]fibSnapshot)}
}

func peerSubnet() *juneauv1alpha1.Subnet {
	return &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-subnet"},
		Status: juneauv1alpha1.SubnetStatus{
			VNI:        77,
			GatewayMAC: "02:00:00:00:00:07",
		},
	}
}

func TestBuildFibValVpcPeeringForwardsToPeerSubnet(t *testing.T) {
	r := newFibFixture(t, peerSubnet())

	route := &juneauv1alpha1.ResolvedRoute{
		Dst:    "10.1.0.0/24",
		Subnet: "peer-subnet",
		Via: juneauv1alpha1.RouteVia{
			Type:       juneauv1alpha1.ViaVpcPeering,
			VpcPeering: "peering-a",
		},
	}

	val, skip, err := r.buildFibVal(context.Background(), route)
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if skip {
		t.Fatal("buildFibVal skipped a vpcPeering route")
	}
	if val.Type != fibRouteTypePeering {
		t.Errorf("type = %d, want %d", val.Type, fibRouteTypePeering)
	}
	if val.SubnetId != 77 {
		t.Errorf("subnet ID = %d, want 77", val.SubnetId)
	}
	wantMAC := [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x07}
	if val.Smac != wantMAC {
		t.Errorf("smac = %v, want %v", val.Smac, wantMAC)
	}
	if val.Dmac != [6]uint8{} {
		t.Errorf("dmac = %v, want zero", val.Dmac)
	}
}

func TestBuildFibValVpcPeeringOnlyDiffersFromConnectedByType(t *testing.T) {
	r := newFibFixture(t, peerSubnet())

	connected, _, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedRoute{
		Dst:    "10.1.0.0/24",
		Subnet: "peer-subnet",
		Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
	})
	if err != nil {
		t.Fatalf("buildFibVal connected: %v", err)
	}
	peering, _, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedRoute{
		Dst:    "10.1.0.0/24",
		Subnet: "peer-subnet",
		Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: "peering-a"},
	})
	if err != nil {
		t.Fatalf("buildFibVal vpcPeering: %v", err)
	}

	if connected.Type == peering.Type {
		t.Fatalf("both route types render as %d", connected.Type)
	}
	peering.Type = connected.Type
	if peering != connected {
		t.Errorf("vpcPeering value = %+v, want the connected value %+v", peering, connected)
	}
}

func TestBuildFibValVpcPeeringMissingSubnetFails(t *testing.T) {
	r := newFibFixture(t)

	_, _, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedRoute{
		Dst:    "10.1.0.0/24",
		Subnet: "peer-subnet",
		Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: "peering-a"},
	})
	if err == nil {
		t.Fatal("buildFibVal accepted a vpcPeering route with no peer Subnet")
	}
}

func transitRouteTable(tableID uint32) *juneauv1alpha1.TransitGatewayRouteTable {
	return &juneauv1alpha1.TransitGatewayRouteTable{
		ObjectMeta: metav1.ObjectMeta{Name: "hub"},
		Spec:       juneauv1alpha1.TransitGatewayRouteTableSpec{TransitGateway: "tgw"},
		Status:     juneauv1alpha1.TransitGatewayRouteTableStatus{TableID: tableID},
	}
}

func transitRoute() *juneauv1alpha1.ResolvedRoute {
	return &juneauv1alpha1.ResolvedRoute{
		Dst:                      "10.2.0.0/16",
		TransitGatewayRouteTable: "hub",
		Via: juneauv1alpha1.RouteVia{
			Type:           juneauv1alpha1.ViaTransitGateway,
			TransitGateway: "tgw",
		},
	}
}

func TestBuildFibValTransitGatewayCarriesTableID(t *testing.T) {
	r := newFibFixture(t, transitRouteTable(42))

	val, skip, err := r.buildFibVal(context.Background(), transitRoute())
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if skip {
		t.Fatal("buildFibVal skipped a transitGateway route with an allocated table ID")
	}
	if val.Type != fibRouteTypeTransit {
		t.Errorf("type = %d, want %d", val.Type, fibRouteTypeTransit)
	}
	if val.SubnetId != 42 {
		t.Errorf("subnet ID = %d, want the table ID 42", val.SubnetId)
	}
	if val.Smac != [6]uint8{} || val.Dmac != [6]uint8{} {
		t.Errorf("value carries MACs %v/%v, want both zero", val.Smac, val.Dmac)
	}
}

func TestBuildFibValTransitGatewaySkipsUnallocatedTableID(t *testing.T) {
	r := newFibFixture(t, transitRouteTable(0))

	_, skip, err := r.buildFibVal(context.Background(), transitRoute())
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if !skip {
		t.Fatal("buildFibVal programmed a transitGateway route whose table ID is not allocated yet")
	}
}

func TestBuildFibValTransitGatewayMissingRouteTableFails(t *testing.T) {
	r := newFibFixture(t)

	_, _, err := r.buildFibVal(context.Background(), transitRoute())
	if err == nil {
		t.Fatal("buildFibVal accepted a transitGateway route with no TransitGatewayRouteTable")
	}
}

func TestBuildFibValVpcEndpointCarriesOnlyTheType(t *testing.T) {
	r := newFibFixture(t)

	route := &juneauv1alpha1.ResolvedRoute{
		Dst: "10.9.0.0/24",
		Via: juneauv1alpha1.RouteVia{
			Type: juneauv1alpha1.ViaVpcEndpoint,
		},
	}

	val, skip, err := r.buildFibVal(context.Background(), route)
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if skip {
		t.Fatal("buildFibVal skipped a vpcEndpoint route")
	}
	if val.Type != fibRouteTypeVpcEndpoint {
		t.Errorf("type = %d, want %d", val.Type, fibRouteTypeVpcEndpoint)
	}
	if val.SubnetId != 0 {
		t.Errorf("subnet ID = %d, want 0", val.SubnetId)
	}
	if val.Smac != [6]uint8{} || val.Dmac != [6]uint8{} {
		t.Errorf("value carries MACs %v/%v, want both zero", val.Smac, val.Dmac)
	}
}

func TestBuildFibValVpcEndpointDiffersFromServiceOnlyByType(t *testing.T) {
	r := newFibFixture(t)

	service, _, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedRoute{
		Dst: "10.9.0.0/24",
		Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
	})
	if err != nil {
		t.Fatalf("buildFibVal(service): %v", err)
	}
	endpoint, _, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedRoute{
		Dst: "10.9.0.0/24",
		Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcEndpoint},
	})
	if err != nil {
		t.Fatalf("buildFibVal(vpcEndpoint): %v", err)
	}

	if service.Type == endpoint.Type {
		t.Fatal("service and vpcEndpoint share a route type; the data plane cannot tell them apart")
	}
	service.Type = endpoint.Type
	if service != endpoint {
		t.Errorf("values differ beyond the type: %+v vs %+v", service, endpoint)
	}
}

// An L2Network reached through its gateway is a connected route with a
// port instead of a Subnet behind it. The ifindex of that port is
// node-local, so the route carries only the VNI and the data plane
// looks the port up itself.
func TestBuildFibValL2GatewayRoute(t *testing.T) {
	network := &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
		Status:     juneauv1alpha1.L2NetworkStatus{VNI: 4242, GatewayMAC: "02:00:00:00:00:fe"},
	}
	r := &Fib{client: fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(network).Build()}

	val, skip, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedRoute{
		Dst:       "10.60.0.0/24",
		L2Network: "lab-net",
		Via:       juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
	})
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if skip {
		t.Fatal("the route was skipped although the segment has a VNI")
	}
	if val.Type != fibRouteTypeL2Gateway {
		t.Errorf("route type %d, want %d", val.Type, fibRouteTypeL2Gateway)
	}
	if val.SubnetId != 4242 {
		t.Errorf("route names VNI %d, want 4242", val.SubnetId)
	}
}

// The VNI lands after the object exists. A route programmed under 0
// would name no segment at all.
func TestBuildFibValSkipsAnL2NetworkWithoutAVni(t *testing.T) {
	network := &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
	}
	r := &Fib{client: fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(network).Build()}

	_, skip, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedRoute{
		Dst:       "10.60.0.0/24",
		L2Network: "lab-net",
		Via:       juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
	})
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if !skip {
		t.Error("a segment with no VNI was programmed anyway")
	}
}

func endpointSubnet() *juneauv1alpha1.Subnet {
	return &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "router-subnet"},
		Status: juneauv1alpha1.SubnetStatus{
			VNI:        88,
			GatewayMAC: "02:00:00:00:00:08",
		},
	}
}

func routerEndpoint(namespace string, mac string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "router-a.eth0", Namespace: namespace},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:       juneauv1alpha1.EndpointKindPod,
			NodeName:   "node-a",
			Subnet:     "router-subnet",
			MACAddress: mac,
		},
	}
}

func endpointRoute(state juneauv1alpha1.RouteState, endpoint *juneauv1alpha1.ResolvedNetworkEndpointReference) *juneauv1alpha1.ResolvedRoute {
	route := &juneauv1alpha1.ResolvedRoute{
		Dst: "10.200.0.0/16",
		Via: juneauv1alpha1.RouteVia{
			Type: juneauv1alpha1.ViaEndpoint,
			Endpoint: &juneauv1alpha1.RouteEndpointReference{
				Namespace:          "net",
				AllocationIdentity: "router",
				Interface:          "eth0",
			},
		},
		NetworkEndpoint: endpoint,
		State:           state,
	}
	if state == juneauv1alpha1.RouteStateActive {
		route.Subnet = "router-subnet"
	}
	return route
}

// The NetworkEndpoint is namespaced. The route names the namespace the
// controller resolved it in, and an endpoint of the same name in another
// namespace belongs to someone else.
func TestBuildFibValEndpointForwardsToTheResolvedEndpoint(t *testing.T) {
	r := newFibFixture(t,
		endpointSubnet(),
		routerEndpoint("net", "02:42:ac:10:00:01"),
		routerEndpoint("other", "02:42:ac:10:00:99"),
	)

	val, skip, err := r.buildFibVal(context.Background(), endpointRoute(juneauv1alpha1.RouteStateActive,
		&juneauv1alpha1.ResolvedNetworkEndpointReference{Namespace: "net", Name: "router-a.eth0"}))
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if skip {
		t.Fatal("buildFibVal skipped an active endpoint route")
	}
	if val.Type != fibRouteTypeEndpoint {
		t.Errorf("type = %d, want %d", val.Type, fibRouteTypeEndpoint)
	}
	if val.SubnetId != 88 {
		t.Errorf("subnet ID = %d, want 88", val.SubnetId)
	}
	if want := [6]uint8{0x02, 0x42, 0xac, 0x10, 0x00, 0x01}; val.Dmac != want {
		t.Errorf("dmac = %v, want the MAC of the endpoint in namespace net %v", val.Dmac, want)
	}
	if want := [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x08}; val.Smac != want {
		t.Errorf("smac = %v, want the gateway MAC of the Subnet %v", val.Smac, want)
	}
}

func TestBuildFibValEndpointWithoutResolvedEndpointFails(t *testing.T) {
	r := newFibFixture(t, endpointSubnet())

	_, _, err := r.buildFibVal(context.Background(), endpointRoute(juneauv1alpha1.RouteStateActive, nil))
	if err == nil {
		t.Fatal("buildFibVal accepted an active endpoint route that names no NetworkEndpoint")
	}
}

func TestBuildFibValBlackholeStateDropsWithoutLookingAnythingUp(t *testing.T) {
	r := newFibFixture(t)

	val, skip, err := r.buildFibVal(context.Background(), endpointRoute(juneauv1alpha1.RouteStateBlackhole, nil))
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if skip {
		t.Fatal("buildFibVal skipped a blackhole route; the traffic would match a shorter prefix instead")
	}
	if val != (bpf.PodEgressFibVal{Type: fibRouteTypeBlackhole}) {
		t.Errorf("value = %+v, want a bare blackhole", val)
	}
}

func TestBuildFibValBlackholeRoute(t *testing.T) {
	r := newFibFixture(t)

	val, skip, err := r.buildFibVal(context.Background(), &juneauv1alpha1.ResolvedRoute{
		Dst:   "10.201.0.0/16",
		Via:   juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaBlackhole},
		State: juneauv1alpha1.RouteStateBlackhole,
	})
	if err != nil {
		t.Fatalf("buildFibVal: %v", err)
	}
	if skip {
		t.Fatal("buildFibVal skipped a blackhole route")
	}
	if val != (bpf.PodEgressFibVal{Type: fibRouteTypeBlackhole}) {
		t.Errorf("value = %+v, want a bare blackhole", val)
	}
}

// An endpoint route usually sends traffic through a firewall. When the
// daemon cannot build it, leaving it out would let the traffic match a
// shorter prefix, such as 0.0.0.0/0, and go around the firewall.
func TestFibValForDropsAnEndpointRouteItCannotBuild(t *testing.T) {
	r := newFibFixture(t, endpointSubnet())

	val, install := r.fibValFor(context.Background(), endpointRoute(juneauv1alpha1.RouteStateActive,
		&juneauv1alpha1.ResolvedNetworkEndpointReference{Namespace: "net", Name: "router-a.eth0"}))
	if !install {
		t.Fatal("fibValFor left out an endpoint route whose NetworkEndpoint is missing")
	}
	if val != (bpf.PodEgressFibVal{Type: fibRouteTypeBlackhole}) {
		t.Errorf("value = %+v, want a bare blackhole", val)
	}
}

func TestFibValForLeavesOutOtherRoutesItCannotBuild(t *testing.T) {
	r := newFibFixture(t)

	_, install := r.fibValFor(context.Background(), &juneauv1alpha1.ResolvedRoute{
		Dst:    "10.1.0.0/24",
		Subnet: "peer-subnet",
		Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: "peering-a"},
		State:  juneauv1alpha1.RouteStateActive,
	})
	if install {
		t.Fatal("fibValFor installed a vpcPeering route with no peer Subnet")
	}
}
