package speaker

import (
	"reflect"
	"strings"
	"testing"

	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

	res := buildReconcileResult("node-a", pools, advs, peers)

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
