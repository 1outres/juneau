package reconciler

import (
	"context"
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

const (
	testExternalNetworkID = 77
	testPodMAC            = "02:00:00:00:00:0a"
)

var testPodMACArray = [6]uint8{0x02, 0, 0, 0, 0, 0x0a}

func newExternalEndpoint(nodeName string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.eth0"},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:            juneauv1alpha1.EndpointKindPod,
			NodeName:        nodeName,
			ExternalNetwork: "internet",
			Address:         "203.0.113.10/32",
			MACAddress:      testPodMAC,
			Attachment: &juneauv1alpha1.NetworkEndpointAttachment{
				Ifindex:        9,
				HostMACAddress: "02:00:00:00:00:01",
			},
			PodRef: &juneauv1alpha1.NetworkEndpointPodReference{Name: "web", Interface: "eth0", UID: "uid-web"},
		},
		Status: juneauv1alpha1.NetworkEndpointStatus{NodeIP: "192.0.2.20"},
	}
}

func newTestExternalNetwork(networkID uint32) *juneauv1alpha1.ExternalNetwork {
	return &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "internet"},
		Status:     juneauv1alpha1.ExternalNetworkStatus{NetworkID: networkID},
	}
}

func newEndpointTestClient(t *testing.T, objs ...runtime.Object) *fake.ClientBuilder {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...)
}

func TestEndpointNetworkOf(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec juneauv1alpha1.NetworkEndpointSpec
		want endpointNetwork
	}{
		{name: "subnet", spec: juneauv1alpha1.NetworkEndpointSpec{Subnet: "web"}, want: endpointOnSubnet},
		{name: "l2Network", spec: juneauv1alpha1.NetworkEndpointSpec{L2Network: "lab"}, want: endpointOnL2Network},
		{name: "externalNetwork", spec: juneauv1alpha1.NetworkEndpointSpec{ExternalNetwork: "internet"}, want: endpointOnExternalNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := endpointNetworkOf(&juneauv1alpha1.NetworkEndpoint{Spec: tc.spec})
			if err != nil {
				t.Fatalf("endpointNetworkOf: %v", err)
			}
			if got != tc.want {
				t.Errorf("endpointNetworkOf = %v, want %v", got, tc.want)
			}
		})
	}

	if _, err := endpointNetworkOf(&juneauv1alpha1.NetworkEndpoint{}); err == nil {
		t.Error("an endpoint that names no network must be an error")
	}
}

func newArpFixture(t *testing.T, objs ...runtime.Object) (*Arp, *fakeBpfMap) {
	t.Helper()
	table := newFakeBpfMap()
	r := &Arp{
		client:    newEndpointTestClient(t, objs...).Build(),
		arpTable:  table,
		snapshots: make(map[string]arpSnapshot),
	}
	return r, table
}

func TestArpKeysAnExternalEndpointByTheNetworkIDOfItsExternalNetwork(t *testing.T) {
	r, table := newArpFixture(t, newExternalEndpoint("node-a"), newTestExternalNetwork(testExternalNetworkID))

	if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	key := bpf.PodEgressArpTableKey{SubnetId: testExternalNetworkID, Ipaddr: 0xcb00710a}
	got, ok := table.entries[key]
	if !ok {
		t.Fatalf("arp_table has no entry for %+v: %v", key, table.entries)
	}
	if got != (bpf.PodEgressArpTableVal{Mac: testPodMACArray}) {
		t.Errorf("arp_table value = %+v, want the pod MAC", got)
	}

	if err := r.client.Delete(context.Background(), newExternalEndpoint("node-a")); err != nil {
		t.Fatalf("delete endpoint: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
		t.Fatalf("Reconcile after delete: %v", err)
	}
	if len(table.entries) != 0 {
		t.Errorf("arp_table after the endpoint is gone = %v, want empty", table.entries)
	}
}

// The controller hands the NIC its address only once the ExternalNetwork
// has a network ID, but the daemon cache can still show the network
// without one. A zero would key the entry into no segment at all.
func TestArpWritesNothingForAnExternalNetworkWithoutANetworkID(t *testing.T) {
	for _, tc := range []struct {
		name string
		objs []runtime.Object
	}{
		{name: "no network ID", objs: []runtime.Object{newExternalEndpoint("node-a"), newTestExternalNetwork(0)}},
		{name: "network gone", objs: []runtime.Object{newExternalEndpoint("node-a")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, table := newArpFixture(t, tc.objs...)
			if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if len(table.entries) != 0 {
				t.Errorf("arp_table = %v, want empty", table.entries)
			}
		})
	}
}

func newFdbFixture(t *testing.T, objs ...runtime.Object) (*Fdb, *fakeBpfMap, *fakeBpfMap) {
	t.Helper()
	local := newFakeBpfMap()
	remote := newFakeBpfMap()
	r := &Fdb{
		client:    newEndpointTestClient(t, objs...).Build(),
		localFdb:  local,
		remoteFdb: remote,
		nodeName:  "node-a",
		snapshots: make(map[string]fdbSnapshot),
	}
	return r, local, remote
}

func TestFdbPointsALocalExternalEndpointAtItsVeth(t *testing.T) {
	r, local, remote := newFdbFixture(t, newExternalEndpoint("node-a"), newTestExternalNetwork(testExternalNetworkID))

	if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	key := bpf.PodEgressFdbKey{SubnetId: testExternalNetworkID, Mac: testPodMACArray}
	if got := local.entries[key]; got != (bpf.PodEgressFdbVal{Ifindex: 9}) {
		t.Errorf("local fdb[%+v] = %+v, want ifindex 9", key, got)
	}
	if len(remote.entries) != 0 {
		t.Errorf("remote fdb = %v, want empty", remote.entries)
	}
}

func TestFdbPointsARemoteExternalEndpointAtItsNode(t *testing.T) {
	r, local, remote := newFdbFixture(t, newExternalEndpoint("node-b"), newTestExternalNetwork(testExternalNetworkID))

	if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	key := bpf.PodEgressFdbKey{SubnetId: testExternalNetworkID, Mac: testPodMACArray}
	if got := remote.entries[key]; got != (bpf.PodEgressFdbVal{VtepIp: 0xc0000214}) {
		t.Errorf("remote fdb[%+v] = %+v, want the VTEP of node-b", key, got)
	}
	if len(local.entries) != 0 {
		t.Errorf("local fdb = %v, want empty", local.entries)
	}
}

func TestFdbWritesNothingForAnExternalNetworkWithoutANetworkID(t *testing.T) {
	r, local, remote := newFdbFixture(t, newExternalEndpoint("node-a"), newTestExternalNetwork(0))

	if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(local.entries) != 0 || len(remote.entries) != 0 {
		t.Errorf("fdb = %v / %v, want empty", local.entries, remote.entries)
	}
}

func TestPodIfaceNamesTheVethOfAnExternalEndpointByItsNetworkAndAddress(t *testing.T) {
	r, maps := newPodIfaceFixture(t, newExternalEndpoint("node-a"), newTestExternalNetwork(testExternalNetworkID))

	if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(maps.subnet.entries) != 0 {
		t.Errorf("ifindex_subnet = %v, want empty: the veth is on no Subnet", maps.subnet.entries)
	}
	wantNIC := bpf.PodEgressIfindexExternalNetworkVal{NetworkId: testExternalNetworkID, Ipv4: 0x0a7100cb}
	if got := maps.externalNetwork.entries[bpf.PodEgressIfindexExternalNetworkKey{Ifindex: 9}]; got != wantNIC {
		t.Errorf("ifindex_external_network[9] = %+v, want %+v", got, wantNIC)
	}
	wantMAC := bpf.PodEgressIfindexHostMacVal{Mac: [6]uint8{0x02, 0, 0, 0, 0, 0x01}}
	if got := maps.hostMAC.entries[bpf.PodEgressIfindexHostMacKey{Ifindex: 9}]; got != wantMAC {
		t.Errorf("ifindex_host_mac[9] = %+v, want %+v", got, wantMAC)
	}

	if err := r.client.Delete(context.Background(), newExternalEndpoint("node-a")); err != nil {
		t.Fatalf("delete endpoint: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
		t.Fatalf("Reconcile after delete: %v", err)
	}
	if len(maps.externalNetwork.entries) != 0 || len(maps.hostMAC.entries) != 0 {
		t.Errorf("after the endpoint is gone: ifindex_external_network = %v, ifindex_host_mac = %v, want both empty",
			maps.externalNetwork.entries, maps.hostMAC.entries)
	}
}

// A network ID of 0 names no segment, so the veth is not named at all
// until the ExternalNetwork has one. With no entry, pod_egress drops what
// the Pod sends.
func TestPodIfaceNamesNoVethForAnExternalNetworkWithoutANetworkID(t *testing.T) {
	for _, tc := range []struct {
		name string
		objs []runtime.Object
	}{
		{name: "no network ID", objs: []runtime.Object{newExternalEndpoint("node-a"), newTestExternalNetwork(0)}},
		{name: "network gone", objs: []runtime.Object{newExternalEndpoint("node-a")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, maps := newPodIfaceFixture(t, tc.objs...)
			if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			for name, m := range map[string]*fakeBpfMap{
				"ifindex_subnet":           maps.subnet,
				"ifindex_external_network": maps.externalNetwork,
				"ifindex_host_mac":         maps.hostMAC,
			} {
				if len(m.entries) != 0 {
					t.Errorf("%s = %v, want empty", name, m.entries)
				}
			}
		})
	}
}

func TestPodIfaceForgetsAnExternalEndpointWhenItsNetworkGoesAway(t *testing.T) {
	network := newTestExternalNetwork(testExternalNetworkID)
	r, maps := newPodIfaceFixture(t, newExternalEndpoint("node-a"), network)

	if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := r.client.Delete(context.Background(), network); err != nil {
		t.Fatalf("delete ExternalNetwork: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
		t.Fatalf("Reconcile after the network is gone: %v", err)
	}
	if len(maps.externalNetwork.entries) != 0 || len(maps.hostMAC.entries) != 0 {
		t.Errorf("ifindex_external_network = %v, ifindex_host_mac = %v, want both empty",
			maps.externalNetwork.entries, maps.hostMAC.entries)
	}
}

// A veth is on one kind of network. An entry of the other kind left at the
// same ifindex, by an endpoint whose delete has not been reconciled yet,
// would make pod_egress read the veth as that kind, so writing one kind
// removes the other.
func TestPodIfaceKeepsOneKindOfEntryPerVeth(t *testing.T) {
	t.Run("external endpoint removes a subnet entry", func(t *testing.T) {
		r, maps := newPodIfaceFixture(t, newExternalEndpoint("node-a"), newTestExternalNetwork(testExternalNetworkID))
		maps.subnet.entries[bpf.PodEgressIfindexSubnetKey{Ifindex: 9}] = bpf.PodEgressIfindexSubnetVal{SubnetId: 42}

		if err := r.Reconcile(context.Background(), "default/web.eth0"); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if len(maps.subnet.entries) != 0 {
			t.Errorf("ifindex_subnet = %v, want the stale entry gone", maps.subnet.entries)
		}
		if len(maps.externalNetwork.entries) != 1 {
			t.Errorf("ifindex_external_network = %v, want the one entry", maps.externalNetwork.entries)
		}
	})

	t.Run("subnet endpoint removes an external entry", func(t *testing.T) {
		r, maps := newPodIfaceFixture(t, newPodIfaceEndpoint("10.16.0.5/24"), newPodIfaceSubnet())
		maps.externalNetwork.entries[bpf.PodEgressIfindexExternalNetworkKey{Ifindex: 7}] =
			bpf.PodEgressIfindexExternalNetworkVal{NetworkId: testExternalNetworkID}

		if err := r.Reconcile(context.Background(), "default/pod-a"); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if len(maps.externalNetwork.entries) != 0 {
			t.Errorf("ifindex_external_network = %v, want the stale entry gone", maps.externalNetwork.entries)
		}
		if len(maps.subnet.entries) != 1 {
			t.Errorf("ifindex_subnet = %v, want the one entry", maps.subnet.entries)
		}
	})
}

func TestPodIfaceFanOutExternalNetworkToEndpoints(t *testing.T) {
	r, _ := newPodIfaceFixture(t, newExternalEndpoint("node-a"), newPodIfaceEndpoint("10.16.0.5/24"))

	got := r.FanOutExternalNetworkToEndpoints(newTestExternalNetwork(testExternalNetworkID))
	if len(got) != 1 || got[0] != "default/web.eth0" {
		t.Errorf("fan-out = %v, want the one endpoint on the network", got)
	}
}

func TestExternalNetworkEndpointKeysFindTheEndpointsOfTheNetwork(t *testing.T) {
	other := newExternalEndpoint("node-a")
	other.Name = "db.eth0"
	other.Spec.ExternalNetwork = "backbone"
	onSubnet := newPodIfaceEndpoint("10.16.0.5/24")

	cl := newEndpointTestClient(t, newExternalEndpoint("node-a"), other, onSubnet).Build()
	network := newTestExternalNetwork(testExternalNetworkID)

	for _, obj := range []any{network, toolscache.DeletedFinalStateUnknown{Key: "internet", Obj: network}} {
		got := externalNetworkEndpointKeys(cl, obj)
		sort.Strings(got)
		if len(got) != 1 || got[0] != "default/web.eth0" {
			t.Errorf("keys for %T = %v, want the one endpoint on internet", obj, got)
		}
	}
	if got := externalNetworkEndpointKeys(cl, onSubnet); got != nil {
		t.Errorf("keys for a non ExternalNetwork event = %v, want none", got)
	}
}
