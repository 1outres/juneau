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
)

const (
	seedTestVNI     = 4242
	seedTestAddress = "10.60.0.5/24"
	seedTestIPv4    = 0x0a3c0005
	seedTestMAC     = "02:00:00:00:00:05"
)

func seedMACArray(t *testing.T, mac string) [6]uint8 {
	t.Helper()
	parsed, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("parse %q: %v", mac, err)
	}
	var out [6]uint8
	copy(out[:], parsed)
	return out
}

func newL2ArpFixture(t *testing.T, objs ...runtime.Object) (*L2Arp, *fakeL2Table) {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...).Build()
	table := newFakeL2Table()
	return NewL2Arp(cl, table), table
}

func newSeedTestNetwork(gateway bool) *juneauv1alpha1.L2Network {
	network := &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
		Spec:       juneauv1alpha1.L2NetworkSpec{Vpc: "vpc-a", CIDR: "10.60.0.0/24"},
		Status:     juneauv1alpha1.L2NetworkStatus{VNI: seedTestVNI},
	}
	if gateway {
		network.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
	}
	return network
}

func newSeedTestEndpoint(nodeName, address, mac string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "lab-a.eth1"},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			L2Network:  "lab-net",
			NodeName:   nodeName,
			Address:    address,
			MACAddress: mac,
		},
	}
}

func seedEntry(t *testing.T, table *fakeL2Table) (bpf.PodEgressL2ArpVal, bool) {
	t.Helper()
	value, ok := table.value(seedTestVNI, bpf.PodEgressL2ArpKey{Ipv4: seedTestIPv4})
	if !ok {
		return bpf.PodEgressL2ArpVal{}, false
	}
	return value.(bpf.PodEgressL2ArpVal), true
}

// The gateway of a segment resolves a destination out of what it has
// snooped, and a node that holds no port on the segment snoops nothing.
// The controller already knows the address and the MAC of every NIC on
// it, so it says so, and every node can address the segment from the
// moment it exists.
func TestL2ArpSeedsTheAddressAnEndpointDeclares(t *testing.T) {
	r, table := newL2ArpFixture(t, newSeedTestNetwork(true),
		newSeedTestEndpoint("node-b", seedTestAddress, seedTestMAC))

	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got, ok := seedEntry(t, table)
	if !ok {
		t.Fatal("the segment holds no address for the endpoint")
	}
	if want := seedMACArray(t, seedTestMAC); got.Mac != want {
		t.Errorf("the address resolves to %v, want %v", got.Mac, want)
	}
}

// A segment with no gateway has nothing that reads this table.
func TestL2ArpLeavesASegmentWithNoGatewayAlone(t *testing.T) {
	r, table := newL2ArpFixture(t, newSeedTestNetwork(false),
		newSeedTestEndpoint("node-b", seedTestAddress, seedTestMAC))

	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := seedEntry(t, table); ok {
		t.Error("an address was recorded for a segment that has no gateway to read it")
	}
}

// What the data plane saw beats what the controller handed out. A NIC
// with a bridge behind it speaks for addresses under a MAC of its own,
// and the seed must not put the NIC's back.
func TestL2ArpNeverOverwritesWhatTheSegmentHasSpoken(t *testing.T) {
	r, table := newL2ArpFixture(t, newSeedTestNetwork(true),
		newSeedTestEndpoint("node-b", seedTestAddress, seedTestMAC))

	behindABridge := seedMACArray(t, "0a:bc:de:f0:12:34")
	if err := table.Put(seedTestVNI, bpf.PodEgressL2ArpKey{Ipv4: seedTestIPv4},
		bpf.PodEgressL2ArpVal{Mac: behindABridge}); err != nil {
		t.Fatalf("record what the segment spoke: %v", err)
	}

	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got, _ := seedEntry(t, table)
	if got.Mac != behindABridge {
		t.Errorf("the seed put %v back over the %v the segment spoke", got.Mac, behindABridge)
	}
}

// The other direction has to work: a frame arriving after the seed
// corrects it.
func TestL2ArpLetsTheSegmentCorrectTheSeed(t *testing.T) {
	r, table := newL2ArpFixture(t, newSeedTestNetwork(true),
		newSeedTestEndpoint("node-b", seedTestAddress, seedTestMAC))

	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	behindABridge := seedMACArray(t, "0a:bc:de:f0:12:34")
	if err := table.Put(seedTestVNI, bpf.PodEgressL2ArpKey{Ipv4: seedTestIPv4},
		bpf.PodEgressL2ArpVal{Mac: behindABridge}); err != nil {
		t.Fatalf("record what the segment spoke: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile again: %v", err)
	}

	got, _ := seedEntry(t, table)
	if got.Mac != behindABridge {
		t.Errorf("a later pass put %v back over the %v the segment spoke", got.Mac, behindABridge)
	}
}

// An address the endpoint no longer holds has to go, or the next
// workload to take it resolves to a NIC that is gone.
func TestL2ArpTakesItsSeedBackWithTheEndpoint(t *testing.T) {
	endpoint := newSeedTestEndpoint("node-b", seedTestAddress, seedTestMAC)
	r, table := newL2ArpFixture(t, newSeedTestNetwork(true), endpoint)

	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := r.client.Delete(context.Background(), endpoint); err != nil {
		t.Fatalf("delete the endpoint: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile after the endpoint went away: %v", err)
	}

	if _, ok := seedEntry(t, table); ok {
		t.Error("the seed outlived the endpoint that declared it")
	}
}

// It takes back only its own. An address the segment has since spoken
// for belongs to whoever is speaking, not to the endpoint that is
// leaving.
func TestL2ArpLeavesACorrectedAddressBehind(t *testing.T) {
	endpoint := newSeedTestEndpoint("node-b", seedTestAddress, seedTestMAC)
	r, table := newL2ArpFixture(t, newSeedTestNetwork(true), endpoint)

	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	behindABridge := seedMACArray(t, "0a:bc:de:f0:12:34")
	if err := table.Put(seedTestVNI, bpf.PodEgressL2ArpKey{Ipv4: seedTestIPv4},
		bpf.PodEgressL2ArpVal{Mac: behindABridge}); err != nil {
		t.Fatalf("record what the segment spoke: %v", err)
	}
	if err := r.client.Delete(context.Background(), endpoint); err != nil {
		t.Fatalf("delete the endpoint: %v", err)
	}
	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile after the endpoint went away: %v", err)
	}

	got, ok := seedEntry(t, table)
	if !ok {
		t.Fatal("the address the segment spoke for was removed with the endpoint")
	}
	if got.Mac != behindABridge {
		t.Errorf("the address resolves to %v, want the %v the segment spoke", got.Mac, behindABridge)
	}
}

// An endpoint with no address hands out nothing to resolve. A segment
// without a CIDR is the ordinary case of that.
func TestL2ArpSkipsAnEndpointWithNoAddress(t *testing.T) {
	r, table := newL2ArpFixture(t, newSeedTestNetwork(true),
		newSeedTestEndpoint("node-b", "", seedTestMAC))

	if err := r.Reconcile(context.Background(), "default/lab-a.eth1"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := seedEntry(t, table); ok {
		t.Error("an address was recorded for an endpoint that declares none")
	}
}
