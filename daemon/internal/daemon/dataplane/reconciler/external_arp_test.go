package reconciler

import (
	"context"
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/ownedaddr"
)

const (
	externalArpTestNode    = "node-a"
	externalArpTestIfindex = 7
	externalArpTestNetwork = "extnet"
	externalArpTestAdv     = "eip-default-web"
)

var (
	externalArpTestMac      = net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}
	externalArpTestOtherMac = net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x99}
)

func newExternalArpNetwork(name string, networkType juneauv1alpha1.ExternalNetworkType) *juneauv1alpha1.ExternalNetwork {
	return &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.ExternalNetworkSpec{
			Type:         networkType,
			AddressPools: []string{"pool-a"},
		},
	}
}

func newExternalArpAdvertisement(name, address, nodeName string) *juneauv1alpha1.ARPAdvertisement {
	return &juneauv1alpha1.ARPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.ARPAdvertisementSpec{
			ExternalNetwork: externalArpTestNetwork,
			Address:         address,
			NodeName:        nodeName,
		},
	}
}

func newExternalArpFixture(t *testing.T, objs ...runtime.Object) (*ExternalArp, *fakeBpfMap, *fakeBpfMap) {
	t.Helper()

	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...).Build()
	arpMap := newFakeBpfMap()
	poolMap := newFakeBpfMap()
	responder, err := newExternalArpResponder(externalArpTestIfindex, externalArpTestMac)
	if err != nil {
		t.Fatalf("newExternalArpResponder: %v", err)
	}
	r := &ExternalArp{
		client:    cl,
		arpTable:  arpMap,
		owned:     ownedaddr.NewStore(poolMap).Scope(externalArpScope),
		nodeName:  externalArpTestNode,
		responder: responder,
		installed: make(map[string]bpf.PodEgressExternalArpKey),
	}
	return r, arpMap, poolMap
}

func externalArpEntries(t *testing.T, m *fakeBpfMap) map[bpf.PodEgressExternalArpKey]bpf.PodEgressExternalArpVal {
	t.Helper()

	out := make(map[bpf.PodEgressExternalArpKey]bpf.PodEgressExternalArpVal, len(m.entries))
	for key, val := range m.entries {
		k, ok := key.(bpf.PodEgressExternalArpKey)
		if !ok {
			t.Fatalf("unexpected key type %T in external_arp_table", key)
		}
		v, ok := val.(bpf.PodEgressExternalArpVal)
		if !ok {
			t.Fatalf("unexpected value type %T in external_arp_table", val)
		}
		out[k] = v
	}
	return out
}

func externalArpTestKey(t *testing.T, address string) bpf.PodEgressExternalArpKey {
	t.Helper()

	ipaddr, err := convert.IPv4ToUint32(net.ParseIP(address))
	if err != nil {
		t.Fatalf("convert %q: %v", address, err)
	}
	return bpf.PodEgressExternalArpKey{Ifindex: externalArpTestIfindex, Ipaddr: ipaddr}
}

func TestExternalArpProgramsAdvertisementForThisNode(t *testing.T) {
	r, arpMap, poolMap := newExternalArpFixture(t,
		newExternalArpNetwork(externalArpTestNetwork, juneauv1alpha1.ExternalNetworkTypeARP),
		newExternalArpAdvertisement(externalArpTestAdv, "192.0.2.10", externalArpTestNode),
	)

	if err := r.Reconcile(context.Background(), externalArpTestAdv); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	entries := externalArpEntries(t, arpMap)
	if len(entries) != 1 {
		t.Fatalf("external_arp_table has %d entries, want 1", len(entries))
	}
	want := externalArpTestKey(t, "192.0.2.10")
	val, ok := entries[want]
	if !ok {
		t.Fatalf("external_arp_table = %+v, want key %+v", entries, want)
	}

	wantMac, err := convert.HardwareAddrToUint8Array(externalArpTestMac)
	if err != nil {
		t.Fatalf("convert MAC: %v", err)
	}
	if val.Mac != wantMac {
		t.Errorf("answered MAC = %v, want the node ingress NIC MAC %v", val.Mac, wantMac)
	}

	if got := poolPrefixes(t, poolMap); len(got) != 1 || got[0] != "192.0.2.10/32" {
		t.Errorf("external_address_pools = %v, want [192.0.2.10/32]", got)
	}
}

func TestExternalArpIgnoresAdvertisementForAnotherNode(t *testing.T) {
	r, arpMap, poolMap := newExternalArpFixture(t,
		newExternalArpNetwork(externalArpTestNetwork, juneauv1alpha1.ExternalNetworkTypeARP),
		newExternalArpAdvertisement(externalArpTestAdv, "192.0.2.10", "node-b"),
	)

	if err := r.Reconcile(context.Background(), externalArpTestAdv); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if entries := externalArpEntries(t, arpMap); len(entries) != 0 {
		t.Errorf("external_arp_table = %+v, want empty", entries)
	}
	if got := poolPrefixes(t, poolMap); len(got) != 0 {
		t.Errorf("external_address_pools = %v, want empty", got)
	}
}

func TestExternalArpReleasesWhenNodeNameMovesAway(t *testing.T) {
	adv := newExternalArpAdvertisement(externalArpTestAdv, "192.0.2.10", externalArpTestNode)
	r, arpMap, poolMap := newExternalArpFixture(t,
		newExternalArpNetwork(externalArpTestNetwork, juneauv1alpha1.ExternalNetworkTypeARP),
		adv,
	)

	if err := r.Reconcile(context.Background(), externalArpTestAdv); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	adv.Spec.NodeName = "node-b"
	if err := r.client.Update(context.Background(), adv); err != nil {
		t.Fatalf("update ARPAdvertisement: %v", err)
	}
	if err := r.Reconcile(context.Background(), externalArpTestAdv); err != nil {
		t.Fatalf("Reconcile after failover: %v", err)
	}

	if entries := externalArpEntries(t, arpMap); len(entries) != 0 {
		t.Errorf("external_arp_table = %+v, want empty", entries)
	}
	if got := poolPrefixes(t, poolMap); len(got) != 0 {
		t.Errorf("external_address_pools = %v, want empty", got)
	}
}

func TestExternalArpReleasesWhenAdvertisementIsDeleted(t *testing.T) {
	adv := newExternalArpAdvertisement(externalArpTestAdv, "192.0.2.10", externalArpTestNode)
	r, arpMap, poolMap := newExternalArpFixture(t,
		newExternalArpNetwork(externalArpTestNetwork, juneauv1alpha1.ExternalNetworkTypeARP),
		adv,
	)

	if err := r.Reconcile(context.Background(), externalArpTestAdv); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := r.client.Delete(context.Background(), adv); err != nil {
		t.Fatalf("delete ARPAdvertisement: %v", err)
	}
	if err := r.Reconcile(context.Background(), externalArpTestAdv); err != nil {
		t.Fatalf("Reconcile after delete: %v", err)
	}

	if entries := externalArpEntries(t, arpMap); len(entries) != 0 {
		t.Errorf("external_arp_table = %+v, want empty", entries)
	}
	if got := poolPrefixes(t, poolMap); len(got) != 0 {
		t.Errorf("external_address_pools = %v, want empty", got)
	}
}

func TestExternalArpRejectsNonARPExternalNetwork(t *testing.T) {
	r, arpMap, poolMap := newExternalArpFixture(t,
		newExternalArpNetwork(externalArpTestNetwork, juneauv1alpha1.ExternalNetworkTypeBGP),
		newExternalArpAdvertisement(externalArpTestAdv, "192.0.2.10", externalArpTestNode),
	)

	if err := r.Reconcile(context.Background(), externalArpTestAdv); err == nil {
		t.Fatal("Reconcile succeeded, want an error for a bgp ExternalNetwork")
	}

	if entries := externalArpEntries(t, arpMap); len(entries) != 0 {
		t.Errorf("external_arp_table = %+v, want empty", entries)
	}
	if got := poolPrefixes(t, poolMap); len(got) != 0 {
		t.Errorf("external_address_pools = %v, want empty", got)
	}
}

func TestExternalArpRejectsMissingExternalNetwork(t *testing.T) {
	r, arpMap, poolMap := newExternalArpFixture(t,
		newExternalArpAdvertisement(externalArpTestAdv, "192.0.2.10", externalArpTestNode),
	)

	if err := r.Reconcile(context.Background(), externalArpTestAdv); err == nil {
		t.Fatal("Reconcile succeeded, want an error for a missing ExternalNetwork")
	}

	if entries := externalArpEntries(t, arpMap); len(entries) != 0 {
		t.Errorf("external_arp_table = %+v, want empty", entries)
	}
	if got := poolPrefixes(t, poolMap); len(got) != 0 {
		t.Errorf("external_address_pools = %v, want empty", got)
	}
}

func TestExternalArpRejectsInvalidAddress(t *testing.T) {
	r, arpMap, _ := newExternalArpFixture(t,
		newExternalArpNetwork(externalArpTestNetwork, juneauv1alpha1.ExternalNetworkTypeARP),
		newExternalArpAdvertisement(externalArpTestAdv, "not-an-ip", externalArpTestNode),
	)

	if err := r.Reconcile(context.Background(), externalArpTestAdv); err == nil {
		t.Fatal("Reconcile succeeded, want an error for a malformed address")
	}
	if entries := externalArpEntries(t, arpMap); len(entries) != 0 {
		t.Errorf("external_arp_table = %+v, want empty", entries)
	}
}

func TestExternalArpReprogramsWhenAddressChanges(t *testing.T) {
	adv := newExternalArpAdvertisement(externalArpTestAdv, "192.0.2.10", externalArpTestNode)
	r, arpMap, poolMap := newExternalArpFixture(t,
		newExternalArpNetwork(externalArpTestNetwork, juneauv1alpha1.ExternalNetworkTypeARP),
		adv,
	)

	if err := r.Reconcile(context.Background(), externalArpTestAdv); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	adv.Spec.Address = "192.0.2.11"
	if err := r.client.Update(context.Background(), adv); err != nil {
		t.Fatalf("update ARPAdvertisement: %v", err)
	}
	if err := r.Reconcile(context.Background(), externalArpTestAdv); err != nil {
		t.Fatalf("Reconcile after readdress: %v", err)
	}

	entries := externalArpEntries(t, arpMap)
	if len(entries) != 1 {
		t.Fatalf("external_arp_table has %d entries, want 1", len(entries))
	}
	if _, ok := entries[externalArpTestKey(t, "192.0.2.11")]; !ok {
		t.Errorf("external_arp_table = %+v, want the new address", entries)
	}
	if got := poolPrefixes(t, poolMap); len(got) != 1 || got[0] != "192.0.2.11/32" {
		t.Errorf("external_address_pools = %v, want [192.0.2.11/32]", got)
	}
}

func TestExternalArpCloseAllRemovesEveryEntry(t *testing.T) {
	r, arpMap, poolMap := newExternalArpFixture(t,
		newExternalArpNetwork(externalArpTestNetwork, juneauv1alpha1.ExternalNetworkTypeARP),
		newExternalArpAdvertisement(externalArpTestAdv, "192.0.2.10", externalArpTestNode),
		newExternalArpAdvertisement("slb-default-web", "192.0.2.11", externalArpTestNode),
	)

	for _, name := range []string{externalArpTestAdv, "slb-default-web"} {
		if err := r.Reconcile(context.Background(), name); err != nil {
			t.Fatalf("Reconcile %q: %v", name, err)
		}
	}
	if entries := externalArpEntries(t, arpMap); len(entries) != 2 {
		t.Fatalf("external_arp_table has %d entries, want 2", len(entries))
	}

	if err := r.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}

	if entries := externalArpEntries(t, arpMap); len(entries) != 0 {
		t.Errorf("external_arp_table = %+v, want empty", entries)
	}
	if got := poolPrefixes(t, poolMap); len(got) != 0 {
		t.Errorf("external_address_pools = %v, want empty", got)
	}
}

func TestExternalArpFanOutExternalNetworkToAdvertisements(t *testing.T) {
	network := newExternalArpNetwork(externalArpTestNetwork, juneauv1alpha1.ExternalNetworkTypeARP)
	other := newExternalArpAdvertisement("ena-extnet--node-b", "192.0.2.12", "node-b")
	other.Spec.ExternalNetwork = "other-extnet"
	r, _, _ := newExternalArpFixture(t,
		network,
		newExternalArpAdvertisement(externalArpTestAdv, "192.0.2.10", externalArpTestNode),
		newExternalArpAdvertisement("slb-default-web", "192.0.2.11", "node-b"),
		other,
	)

	got := r.FanOutExternalNetworkToAdvertisements(network)
	want := map[string]struct{}{externalArpTestAdv: {}, "slb-default-web": {}}
	if len(got) != len(want) {
		t.Fatalf("fan-out keys = %v, want %v", got, want)
	}
	for _, key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("fan-out returned unexpected key %q", key)
		}
	}
}

func TestNewExternalArpResponderRejectsUnusableInterface(t *testing.T) {
	tests := []struct {
		name    string
		ifindex int
		mac     net.HardwareAddr
	}{
		{name: "unset ifindex", ifindex: 0, mac: externalArpTestMac},
		{name: "negative ifindex", ifindex: -1, mac: externalArpTestMac},
		{name: "missing MAC", ifindex: externalArpTestIfindex, mac: nil},
		{name: "non-Ethernet MAC", ifindex: externalArpTestIfindex, mac: net.HardwareAddr{0x02, 0x42}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newExternalArpResponder(tt.ifindex, tt.mac); err == nil {
				t.Fatal("newExternalArpResponder succeeded, want an error")
			}
		})
	}
}

func TestNewExternalArpResponderKeepsTheGivenInterface(t *testing.T) {
	responder, err := newExternalArpResponder(externalArpTestIfindex, externalArpTestOtherMac)
	if err != nil {
		t.Fatalf("newExternalArpResponder: %v", err)
	}
	wantMac, err := convert.HardwareAddrToUint8Array(externalArpTestOtherMac)
	if err != nil {
		t.Fatalf("convert MAC: %v", err)
	}
	if responder.ifindex != externalArpTestIfindex || responder.mac != wantMac {
		t.Errorf("responder = %+v, want ifindex %d and MAC %v", responder, externalArpTestIfindex, wantMac)
	}
}
