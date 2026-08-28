package program_test

import (
	"context"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/l2"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler"
)

// testVNI is the segment every L2 test builds. Any non-zero number
// works; a recognisable one makes a failed map dump easier to read.
const testVNI = 4242

// testVpcID is what the trace events of the segment are stamped with.
// The forwarding path never reads it.
const testVpcID = 7

// testSegmentCIDR is the prefix of the segment, and gatewayAddress is
// the first address of it.
const testSegmentCIDR = "10.60.0.0/24"

// l2Segment is one L2Network as the data plane sees it: the tables it
// reads, and the devices that stand in for its ports.
type l2Segment struct {
	objs      *bpftest.Objects
	fdb       *l2.Table
	bumLocal  *l2.Table
	bumRemote *l2.Table
	arp       *l2.Table
}

// newL2Segment loads one generated object and brings testVNI up as an
// L2Network.
//
// The tables are not built here. The reconciler the daemon runs is
// handed the same map handles and asked to reconcile an L2Network, so
// the segment these tests drive is built by the code that builds a real
// one. A table the reconciler stops creating then shows up as a failing
// program test rather than as traffic disappearing on a cluster, which
// is how the missing l2_arp table got out.
func newL2Segment(t *testing.T, load func() (*ebpf.CollectionSpec, error)) *l2Segment {
	t.Helper()

	objs := bpftest.Load(t, load)
	seg := &l2Segment{
		objs:      objs,
		fdb:       l2.NewTable("fdb", objs.Map(t, "l2_fdb"), objs.MapSpec(t, "l2_fdb_inner")),
		bumLocal:  l2.NewTable("bum-local", objs.Map(t, "l2_bum_local"), objs.MapSpec(t, "l2_bum_local_inner")),
		bumRemote: l2.NewTable("bum-remote", objs.Map(t, "l2_bum_remote"), objs.MapSpec(t, "l2_bum_remote_inner")),
		arp:       l2.NewTable("arp", objs.Map(t, "l2_arp"), objs.MapSpec(t, "l2_arp_inner")),
	}
	t.Cleanup(func() {
		for _, table := range []*l2.Table{seg.fdb, seg.bumLocal, seg.bumRemote, seg.arp} {
			if err := table.CloseAll(); err != nil {
				t.Errorf("close the per-VNI tables: %v", err)
			}
		}
	})

	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("build the scheme: %v", err)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		&juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: "lab-vpc"},
			Status:     juneauv1alpha1.VpcStatus{VpcID: testVpcID},
		},
		&juneauv1alpha1.L2Network{
			ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
			Spec:       juneauv1alpha1.L2NetworkSpec{Vpc: "lab-vpc"},
			Status:     juneauv1alpha1.L2NetworkStatus{VNI: testVNI},
		},
	).Build()

	network := reconciler.NewL2Network(client, objs.Map(t, "l2_network_map"),
		seg.fdb, seg.bumLocal, seg.bumRemote, seg.arp)
	if err := network.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("bring the segment up: %v", err)
	}

	// Said out loud rather than left to whichever test happens to read
	// the table that is missing. A table the reconciler forgot is a
	// segment that silently loses one kind of traffic.
	for name, table := range map[string]*l2.Table{
		"l2_fdb":        seg.fdb,
		"l2_bum_local":  seg.bumLocal,
		"l2_bum_remote": seg.bumRemote,
		"l2_arp":        seg.arp,
	} {
		built := false
		table.ForEachInner(func(vni uint32, _ *ebpf.Map) {
			built = built || vni == testVNI
		})
		if !built {
			t.Fatalf("the reconciler brought the segment up without %s", name)
		}
	}
	return seg
}

// addLocalPort makes a device a port of the segment: the data plane
// can look the segment up from it, and a flooded frame reaches it.
func (s *l2Segment) addLocalPort(t *testing.T, device bpftest.Device) {
	t.Helper()
	if err := s.objs.Map(t, "l2_ifindex").Update(
		&bpf.PodEgressL2IfindexKey{Ifindex: uint32(device.Index)},
		&bpf.PodEgressL2IfindexVal{Vni: testVNI},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the segment behind %s: %v", device.Name, err)
	}
	if err := s.bumLocal.AddMember(testVNI, uint32(device.Index)); err != nil {
		t.Fatalf("add %s to the local flood list: %v", device.Name, err)
	}
}

// addGatewayPort makes a device the gateway port of the segment.
//
// Like the tables above, this goes through the reconciler the daemon
// runs. A port occupies six maps and the list is easy to get out of
// step with by hand: the first version of these tests wrote five of
// them and every IPv4 test started failing the moment the program
// began reading the sixth.
func (s *l2Segment) addGatewayPort(t *testing.T, device bpftest.Device, mac net.HardwareAddr) {
	t.Helper()
	s.standUpGateway(t, device, mac, 0, 0)
}

// standUpGateway is addGatewayPort with the route table and the ACL of
// the boundary named, which is what the tests about policy need.
func (s *l2Segment) standUpGateway(t *testing.T, device bpftest.Device, mac net.HardwareAddr, tableID, aclID uint32) {
	t.Helper()
	StandUpGatewayPort(t, reconciler.L2GatewayMaps{
		Gateway:       s.objs.Map(t, "l2_gateway"),
		Subnet:        s.objs.Map(t, "subnet_map"),
		IfindexSubnet: s.objs.Map(t, "ifindex_subnet"),
		Ifindex:       s.objs.Map(t, "l2_ifindex"),
		Fdb:           s.fdb,
		BumLocal:      s.bumLocal,
	}, device, mac, tableID, aclID)
}

// fixedGatewayPort stands in for the veth pair the daemon builds. The
// device already exists here, so the reconciler is only told which
// ifindex it landed on.
type fixedGatewayPort struct{ ifindex uint32 }

func (f fixedGatewayPort) Ensure(uint32, net.HardwareAddr) (uint32, error) { return f.ifindex, nil }

func (f fixedGatewayPort) Remove(uint32) error { return nil }

// StandUpGatewayPort brings the router port of testVNI up on a device,
// through reconciler.L2Gateway. Every map a port occupies is written by
// the code that writes them on a node.
func StandUpGatewayPort(t *testing.T, maps reconciler.L2GatewayMaps, device bpftest.Device, mac net.HardwareAddr, tableID, aclID uint32) {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("build the scheme: %v", err)
	}
	network := &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
		Spec: juneauv1alpha1.L2NetworkSpec{
			Vpc:     "lab-vpc",
			CIDR:    testSegmentCIDR,
			Gateway: &juneauv1alpha1.L2NetworkGateway{},
		},
		Status: juneauv1alpha1.L2NetworkStatus{
			VNI:        testVNI,
			Gateway:    gatewayAddress,
			GatewayMAC: mac.String(),
		},
	}
	if aclID != 0 {
		network.Spec.NetworkACL = "lab-acl"
		network.Status.NetworkACL = &juneauv1alpha1.NetworkACLRef{Name: "lab-acl", ACLID: aclID}
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		&juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: "lab-vpc"},
			Status:     juneauv1alpha1.VpcStatus{VpcID: testVpcID, MainRouteTable: "lab-rt"},
		},
		&juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: "lab-rt"},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: "lab-vpc"},
			Status:     juneauv1alpha1.RouteTableStatus{TableID: tableID},
		},
		network,
	).Build()

	gateway := reconciler.NewL2Gateway(client, fixedGatewayPort{ifindex: uint32(device.Index)}, maps, "node-a")
	if err := gateway.Reconcile(context.Background(), "lab-net"); err != nil {
		t.Fatalf("stand the gateway port up: %v", err)
	}
}

// seedAddress records an address the way the daemon does for a node
// that holds no port on the segment: through reconciler.L2Arp, out of
// the NetworkEndpoint the controller published.
func (s *l2Segment) seedAddress(t *testing.T, address string, mac net.HardwareAddr) {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("build the scheme: %v", err)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		&juneauv1alpha1.L2Network{
			ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
			Spec: juneauv1alpha1.L2NetworkSpec{
				Vpc:     "lab-vpc",
				CIDR:    testSegmentCIDR,
				Gateway: &juneauv1alpha1.L2NetworkGateway{},
			},
			Status: juneauv1alpha1.L2NetworkStatus{VNI: testVNI},
		},
		&juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "lab-a.eth1"},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				L2Network:  "lab-net",
				NodeName:   "node-b",
				Address:    address + "/24",
				MACAddress: mac.String(),
			},
		},
	).Build()

	if err := reconciler.NewL2Arp(client, s.arp).Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("seed %s into the segment: %v", address, err)
	}
}

// resolve records an address on the segment as the gateway would have
// snooped it out of an ARP frame.
func (s *l2Segment) resolve(t *testing.T, address string, mac net.HardwareAddr) {
	t.Helper()
	if err := s.arp.Put(testVNI, bpf.PodEgressL2ArpKey{Ipv4: hostOrderIPv4(t, address)},
		bpf.PodEgressL2ArpVal{Mac: macArray(t, mac)}); err != nil {
		t.Fatalf("record %s on the segment: %v", address, err)
	}
}

// resolved reads back what the segment knows about one address.
func (s *l2Segment) resolved(t *testing.T, address string) (net.HardwareAddr, bool) {
	t.Helper()
	var (
		val   bpf.PodEgressL2ArpVal
		found bool
	)
	s.arp.ForEachInner(func(vni uint32, inner *ebpf.Map) {
		if vni != testVNI {
			return
		}
		found = inner.Lookup(&bpf.PodEgressL2ArpKey{Ipv4: hostOrderIPv4(t, address)}, &val) == nil
	})
	if !found {
		return nil, false
	}
	return net.HardwareAddr(val.Mac[:]), true
}

// addRemoteNode puts a node's underlay address on the remote flood
// list, which is what makes a broadcast leave this host.
func (s *l2Segment) addRemoteNode(t *testing.T, address string) {
	t.Helper()
	if err := s.bumRemote.AddMember(testVNI, hostOrderIPv4(t, address)); err != nil {
		t.Fatalf("add %s to the remote flood list: %v", address, err)
	}
}

// useTunnelDevice tells the data plane which device carries frames to
// other nodes.
func (s *l2Segment) useTunnelDevice(t *testing.T, device bpftest.Device) {
	t.Helper()
	if err := s.objs.Map(t, "vxlan_ifindex").Update(
		uint32(0), uint32(device.Index), ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the tunnel device: %v", err)
	}
}

// withFdb runs fn against the forwarding table of the segment. Table
// hands its inner maps out only while it holds its own lock, so the
// test reaches one the same way the aging sweep does.
func (s *l2Segment) withFdb(t *testing.T, fn func(inner *ebpf.Map)) {
	t.Helper()
	found := false
	s.fdb.ForEachInner(func(vni uint32, inner *ebpf.Map) {
		if vni != testVNI {
			return
		}
		found = true
		fn(inner)
	})
	if !found {
		t.Fatalf("the segment has no forwarding table for VNI %d", testVNI)
	}
}

// learn writes a forwarding entry by hand, standing in for a frame the
// data plane would have learned it from.
func (s *l2Segment) learn(t *testing.T, mac net.HardwareAddr, ifindex uint32, vtep string) {
	t.Helper()
	var vtepIP uint32
	if vtep != "" {
		vtepIP = hostOrderIPv4(t, vtep)
	}
	s.withFdb(t, func(inner *ebpf.Map) {
		if err := inner.Update(
			&bpf.PodEgressL2FdbKey{Mac: macArray(t, mac)},
			&bpf.PodEgressL2FdbVal{Ifindex: ifindex, VtepIp: vtepIP},
			ebpf.UpdateAny,
		); err != nil {
			t.Fatalf("write a forwarding entry: %v", err)
		}
	})
}

// lookup reads back what the segment knows about one MAC.
func (s *l2Segment) lookup(t *testing.T, mac net.HardwareAddr) (bpf.PodEgressL2FdbVal, bool) {
	t.Helper()
	var (
		val   bpf.PodEgressL2FdbVal
		found bool
	)
	s.withFdb(t, func(inner *ebpf.Map) {
		found = inner.Lookup(&bpf.PodEgressL2FdbKey{Mac: macArray(t, mac)}, &val) == nil
	})
	if !found {
		return bpf.PodEgressL2FdbVal{}, false
	}
	return val, true
}

func macArray(t *testing.T, mac net.HardwareAddr) [6]uint8 {
	t.Helper()
	if len(mac) != 6 {
		t.Fatalf("a MAC is 6 bytes, got %d", len(mac))
	}
	var out [6]uint8
	copy(out[:], mac)
	return out
}

// hostOrderIPv4 turns an address into the number the data plane hands
// to bpf_tunnel_key.remote_ipv4, which the kernel byte-swaps itself.
func hostOrderIPv4(t *testing.T, address string) uint32 {
	t.Helper()
	ip := net.ParseIP(address).To4()
	if ip == nil {
		t.Fatalf("%q is not an IPv4 address", address)
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
