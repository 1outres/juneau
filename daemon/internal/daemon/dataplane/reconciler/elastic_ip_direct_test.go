package reconciler

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/ownedaddr"
)

// testElasticIPHostOrder is 203.0.113.10, the address newExternalEndpoint
// carries, in the byte order elastic_ip_direct is keyed on.
const testElasticIPHostOrder = 0xcb00710a

type elasticIPDirectFixture struct {
	reconciler *ElasticIPDirect
	direct     *fakeBpfMap
	pools      *fakeBpfMap
	store      *ownedaddr.Store
}

func newElasticIPDirectFixture(t *testing.T, objs ...runtime.Object) elasticIPDirectFixture {
	t.Helper()
	direct := newFakeBpfMap()
	pools := newFakeBpfMap()
	store := ownedaddr.NewStore(pools)
	return elasticIPDirectFixture{
		reconciler: newElasticIPDirect(newEndpointTestClient(t, objs...).Build(), direct, store),
		direct:     direct,
		pools:      pools,
		store:      store,
	}
}

func (f elasticIPDirectFixture) reconcile(t *testing.T, key string) {
	t.Helper()
	if err := f.reconciler.Reconcile(context.Background(), key); err != nil {
		t.Fatalf("Reconcile %s: %v", key, err)
	}
}

func (f elasticIPDirectFixture) assertDelivers(t *testing.T) {
	t.Helper()
	key := bpf.PodEgressElasticIpDirectKey{Addr: testElasticIPHostOrder}
	if got, ok := f.direct.entries[key]; !ok || got != (bpf.PodEgressElasticIpDirectVal{NetworkId: testExternalNetworkID}) {
		t.Errorf("elastic_ip_direct = %v, want 203.0.113.10 on network %d", f.direct.entries, testExternalNetworkID)
	}
	if got := poolPrefixes(t, f.pools); len(got) != 1 || got[0] != "203.0.113.10/32" {
		t.Errorf("external_address_pools = %v, want [203.0.113.10/32]", got)
	}
}

func (f elasticIPDirectFixture) assertDeliversNothing(t *testing.T) {
	t.Helper()
	if len(f.direct.entries) != 0 {
		t.Errorf("elastic_ip_direct = %v, want empty", f.direct.entries)
	}
	if got := poolPrefixes(t, f.pools); len(got) != 0 {
		t.Errorf("external_address_pools = %v, want empty", got)
	}
}

// BGP ECMP lands a packet for the address on any node, and a Pod on any
// node may send to it, so every node takes the address and knows the
// network to find the NIC on, wherever the NIC runs.
func TestElasticIPDirectTakesTheAddressOnEveryNode(t *testing.T) {
	for _, nodeName := range []string{"node-a", "node-b"} {
		f := newElasticIPDirectFixture(t, newExternalEndpoint(nodeName), newTestExternalNetwork(testExternalNetworkID))
		f.reconcile(t, "default/web.eth0")
		f.assertDelivers(t)
	}
}

func TestElasticIPDirectLeavesAnEndpointOnASubnetAlone(t *testing.T) {
	f := newElasticIPDirectFixture(t, newPodIfaceEndpoint("10.16.0.5/24"), newPodIfaceSubnet())
	f.reconcile(t, "default/pod-a")
	f.assertDeliversNothing(t)
}

// A network ID of 0 names no segment the NIC could be found on, so the
// address is not taken until the ExternalNetwork has one.
func TestElasticIPDirectWaitsForTheNetworkID(t *testing.T) {
	for name, objs := range map[string][]runtime.Object{
		"no network ID": {newExternalEndpoint("node-a"), newTestExternalNetwork(0)},
		"network gone":  {newExternalEndpoint("node-a")},
	} {
		f := newElasticIPDirectFixture(t, objs...)
		f.reconcile(t, "default/web.eth0")
		if len(f.direct.entries) != 0 || len(f.pools.entries) != 0 {
			t.Errorf("%s: elastic_ip_direct = %v, external_address_pools = %v, want both empty",
				name, f.direct.entries, f.pools.entries)
		}
	}
}

func TestElasticIPDirectGivesTheAddressBackWhenTheEndpointGoes(t *testing.T) {
	f := newElasticIPDirectFixture(t, newExternalEndpoint("node-b"), newTestExternalNetwork(testExternalNetworkID))
	f.reconcile(t, "default/web.eth0")

	if err := f.reconciler.client.Delete(context.Background(), newExternalEndpoint("node-b")); err != nil {
		t.Fatalf("delete endpoint: %v", err)
	}
	f.reconcile(t, "default/web.eth0")
	f.assertDeliversNothing(t)
}

// An endpoint's address is always a single ElasticIP.
func TestElasticIPDirectRejectsAnAddressThatIsNotOneIPv4Address(t *testing.T) {
	for _, address := range []string{"203.0.113.0/24", "2001:db8::10/128", "not-an-address", ""} {
		endpoint := newExternalEndpoint("node-a")
		endpoint.Spec.Address = address
		f := newElasticIPDirectFixture(t, endpoint, newTestExternalNetwork(testExternalNetworkID))

		if err := f.reconciler.Reconcile(context.Background(), "default/web.eth0"); err == nil {
			t.Errorf("address %q: Reconcile succeeded, want an error", address)
		}
		if len(f.direct.entries) != 0 || len(f.pools.entries) != 0 {
			t.Errorf("address %q: elastic_ip_direct = %v, external_address_pools = %v, want both empty",
				address, f.direct.entries, f.pools.entries)
		}
	}
}

// In ARP mode the node the Pod runs on also answers ARP for the address,
// and that claim is the external-arp reconciler's own. Neither one may take
// the address away from the other.
func TestElasticIPDirectSharesTheAddressWithAnARPAdvertisement(t *testing.T) {
	f := newElasticIPDirectFixture(t, newExternalEndpoint("node-a"), newTestExternalNetwork(testExternalNetworkID))
	arp := f.store.Scope("external-arp")
	host, err := ownedaddr.ParsePrefix("203.0.113.10/32")
	if err != nil {
		t.Fatalf("ParsePrefix: %v", err)
	}
	if err := arp.Set("eip-default-public", []ownedaddr.Key{host}); err != nil {
		t.Fatalf("claim for external-arp: %v", err)
	}

	f.reconcile(t, "default/web.eth0")
	if err := f.reconciler.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if got := poolPrefixes(t, f.pools); len(got) != 1 || got[0] != "203.0.113.10/32" {
		t.Errorf("external_address_pools = %v, want the /32 external-arp still claims", got)
	}
	if len(f.direct.entries) != 0 {
		t.Errorf("elastic_ip_direct = %v, want empty once no endpoint carries the address", f.direct.entries)
	}
}

// In BGP mode the pool the address comes from is already taken whole. The
// /32 is a claim of its own inside it, so letting it go leaves the pool.
func TestElasticIPDirectClaimsItsOwnPrefixInsideABGPPool(t *testing.T) {
	f := newElasticIPDirectFixture(t, newExternalEndpoint("node-a"), newTestExternalNetwork(testExternalNetworkID))
	pool, err := ownedaddr.ParsePrefix("203.0.113.0/24")
	if err != nil {
		t.Fatalf("ParsePrefix: %v", err)
	}
	if err := f.store.Scope("bgp-pool").Set("address-pools", []ownedaddr.Key{pool}); err != nil {
		t.Fatalf("claim for bgp-pool: %v", err)
	}

	f.reconcile(t, "default/web.eth0")
	if got := poolPrefixes(t, f.pools); len(got) != 2 {
		t.Errorf("external_address_pools = %v, want the pool and the /32", got)
	}
	if err := f.reconciler.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if got := poolPrefixes(t, f.pools); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Errorf("external_address_pools = %v, want only the pool", got)
	}
}

// A node that dies keeps its NetworkEndpoints until something removes
// them, and by then the ElasticIP may already be carried by a NIC on
// another node. The stale endpoint going away must not take the address
// from the live one.
func TestElasticIPDirectKeepsAnAddressTwoEndpointsCarry(t *testing.T) {
	stale := newExternalEndpoint("node-a")
	stale.Name = "web-old.eth0"
	f := newElasticIPDirectFixture(t, stale, newExternalEndpoint("node-b"), newTestExternalNetwork(testExternalNetworkID))
	f.reconcile(t, "default/web-old.eth0")
	f.reconcile(t, "default/web.eth0")

	if err := f.reconciler.client.Delete(context.Background(), stale); err != nil {
		t.Fatalf("delete the stale endpoint: %v", err)
	}
	f.reconcile(t, "default/web-old.eth0")
	f.assertDelivers(t)
}

// One address belongs to one ExternalNetwork, because an AddressPool does.
// Two endpoints that disagree mean one of them is wrong, and the data
// plane cannot tell which: what is programmed stays and the other is an
// error.
func TestElasticIPDirectRefusesAnAddressOnTwoNetworks(t *testing.T) {
	other := newExternalEndpoint("node-b")
	other.Name = "db.eth0"
	other.Spec.ExternalNetwork = "backbone"
	backbone := newTestExternalNetwork(testExternalNetworkID + 1)
	backbone.Name = "backbone"

	f := newElasticIPDirectFixture(t, newExternalEndpoint("node-a"), other,
		newTestExternalNetwork(testExternalNetworkID), backbone)
	f.reconcile(t, "default/web.eth0")

	if err := f.reconciler.Reconcile(context.Background(), "default/db.eth0"); err == nil {
		t.Fatal("Reconcile of the second endpoint succeeded, want an error")
	}
	f.assertDelivers(t)
}

func TestElasticIPDirectFanOutExternalNetworkToEndpoints(t *testing.T) {
	f := newElasticIPDirectFixture(t, newExternalEndpoint("node-b"), newPodIfaceEndpoint("10.16.0.5/24"))

	got := f.reconciler.FanOutExternalNetworkToEndpoints(newTestExternalNetwork(testExternalNetworkID))
	if len(got) != 1 || got[0] != "default/web.eth0" {
		t.Errorf("fan-out = %v, want the one endpoint on the network", got)
	}
}
