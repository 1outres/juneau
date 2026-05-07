package speaker

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
	"github.com/1outres/juneau/bgp-speaker/internal/prefixsource"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// buildAggregatedFromLists is the test-side bridge from the pre-refactor
// signature (pools, advs) to the new aggregated input. It runs the
// AddressPoolAdvertisementSource against a fake client seeded with the
// supplied lists so the tests below stay focused on peer-side logic.
func buildAggregatedFromLists(t *testing.T, nodeName string, pools *juneauv1alpha1.AddressPoolList, advs *juneauv1alpha1.BGPAdvertisementList) prefixsource.Aggregated {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	objs := []client.Object{}
	for i := range pools.Items {
		objs = append(objs, &pools.Items[i])
	}
	for i := range advs.Items {
		objs = append(objs, &advs.Items[i])
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	out, err := prefixsource.Aggregate(context.Background(), []prefixsource.Source{
		prefixsource.AddressPoolAdvertisementSource{},
	}, prefixsource.Input{NodeName: nodeName, Client: cl})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	return out
}

func TestBuildReconcileResult_PeerNamesAndAdvertisementsAndWarnings(t *testing.T) {
	t.Parallel()

	pools := &juneauv1alpha1.AddressPoolList{Items: []juneauv1alpha1.AddressPool{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-a"},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.1.0.0/24"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-b"},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.2.0.0/24", "10.3.0.0/24"},
			},
		},
	}}

	advs := &juneauv1alpha1.BGPAdvertisementList{Items: []juneauv1alpha1.BGPAdvertisement{
		{Spec: juneauv1alpha1.BGPAdvertisementSpec{AddressPools: []string{"pool-a", "pool-b"}}},
	}}

	peers := &juneauv1alpha1.BGPPeerList{Items: []juneauv1alpha1.BGPPeer{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "peer-x"},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       64512,
				PeerASN:     64513,
				PeerAddress: "10.0.0.2",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-peer"},
			Spec:       juneauv1alpha1.BGPPeerSpec{MyASN: 64512, PeerASN: 0, PeerAddress: "10.0.0.9"},
		},
	}}

	aggregated := buildAggregatedFromLists(t, "node-a", pools, advs)
	res := buildReconcileResult("node-a", aggregated, peers)

	if got, want := len(res.Desired.Peers), 1; got != want {
		t.Errorf("Desired.Peers: want %d, got %d", want, got)
	}

	wantIndex := map[string]string{"10.0.0.2": "peer-x"}
	if !reflect.DeepEqual(res.PeerNamesByAddress, wantIndex) {
		t.Errorf("PeerNamesByAddress: want %v, got %v", wantIndex, res.PeerNamesByAddress)
	}

	if got := len(res.Advertisements); got != 2 {
		t.Fatalf("Advertisements: want 2, got %d: %+v", got, res.Advertisements)
	}
	// Sorted by AddressPool; each Prefixes list sorted CIDRs from spec.addresses.
	if diff := cmp.Diff(
		[]nodestate.Advertisement{
			{AddressPool: "pool-a", Prefixes: []string{"10.1.0.0/24"}},
			{AddressPool: "pool-b", Prefixes: []string{"10.2.0.0/24", "10.3.0.0/24"}},
		},
		res.Advertisements,
	); diff != "" {
		t.Errorf("Advertisements mismatch (-want +got):\n%s", diff)
	}

	foundBadPeer := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "bad-peer") {
			foundBadPeer = true
		}
	}
	if !foundBadPeer {
		t.Errorf("Warnings: want one mentioning bad-peer, got %v", res.Warnings)
	}
}

func TestBuildReconcileResult_PerNodePrefixOverride(t *testing.T) {
	t.Parallel()

	pools := &juneauv1alpha1.AddressPoolList{Items: []juneauv1alpha1.AddressPool{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-a"},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.1.0.0/24"},
			},
		},
	}}

	advs := &juneauv1alpha1.BGPAdvertisementList{Items: []juneauv1alpha1.BGPAdvertisement{
		// Per-node /32 advertisement targeted at node-a.
		{
			ObjectMeta: metav1.ObjectMeta{Name: "adv-node-a"},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{"pool-a"},
				NodeName:     "node-a",
				Prefix:       "10.1.0.5/32",
			},
		},
		// Per-node /32 advertisement targeted at node-b (must be ignored on node-a).
		{
			ObjectMeta: metav1.ObjectMeta{Name: "adv-node-b"},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{"pool-a"},
				NodeName:     "node-b",
				Prefix:       "10.1.0.6/32",
			},
		},
	}}

	peers := &juneauv1alpha1.BGPPeerList{Items: []juneauv1alpha1.BGPPeer{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "peer-x"},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       64512,
				PeerASN:     64513,
				PeerAddress: "10.0.0.2",
			},
		},
	}}

	aggregated := buildAggregatedFromLists(t, "node-a", pools, advs)
	res := buildReconcileResult("node-a", aggregated, peers)

	if got := len(res.Desired.Peers); got != 1 {
		t.Fatalf("Desired.Peers: want 1, got %d", got)
	}

	prefixes := res.Desired.Peers[0].Prefixes
	if got := len(prefixes); got != 1 {
		t.Fatalf("Desired.Peers[0].Prefixes: want 1, got %d (%v)", got, prefixes)
	}
	if got := prefixes[0].String(); got != "10.1.0.5/32" {
		t.Errorf("Desired.Peers[0].Prefixes[0]: want 10.1.0.5/32, got %s", got)
	}
}

func TestBuildReconcileResult_NodeNameAllNodes(t *testing.T) {
	t.Parallel()

	pools := &juneauv1alpha1.AddressPoolList{Items: []juneauv1alpha1.AddressPool{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-a"},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.1.0.0/24"},
			},
		},
	}}

	// nodeName empty: every node should advertise the pool's CIDR.
	advs := &juneauv1alpha1.BGPAdvertisementList{Items: []juneauv1alpha1.BGPAdvertisement{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "adv-all"},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{"pool-a"},
			},
		},
	}}

	peers := &juneauv1alpha1.BGPPeerList{Items: []juneauv1alpha1.BGPPeer{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "peer-x"},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       64512,
				PeerASN:     64513,
				PeerAddress: "10.0.0.2",
			},
		},
	}}

	for _, node := range []string{"node-a", "node-b"} {
		aggregated := buildAggregatedFromLists(t, node, pools, advs)
		res := buildReconcileResult(node, aggregated, peers)
		if got := len(res.Desired.Peers); got != 1 {
			t.Fatalf("[%s] Desired.Peers: want 1, got %d", node, got)
		}
		prefixes := res.Desired.Peers[0].Prefixes
		if got := len(prefixes); got != 1 || prefixes[0].String() != "10.1.0.0/24" {
			t.Errorf("[%s] Desired.Peers[0].Prefixes: want [10.1.0.0/24], got %v", node, prefixes)
		}
	}
}
