package prefixsource

import (
	"context"
	"reflect"
	"sort"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func TestAddressPoolSource_PreservesPriorBehaviour(t *testing.T) {
	t.Parallel()

	pool := &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: "pool-a"},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
			Addresses:     []string{"10.1.0.0/24"},
		},
	}
	adv := &juneauv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: "adv-a"},
		Spec: juneauv1alpha1.BGPAdvertisementSpec{
			AddressPools: []string{"pool-a"},
		},
	}

	cl := newFakeClient(t, pool, adv)
	res, err := AddressPoolAdvertisementSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := len(res.Advertisements); got != 1 {
		t.Fatalf("Advertisements: want 1, got %d", got)
	}
	got := res.Advertisements[0]
	if got.SourceKind != "BGPAdvertisement" || got.AddressPool != "pool-a" || len(got.Prefixes) != 1 {
		t.Fatalf("unexpected advertisement: %+v", got)
	}
	if cidr := got.Prefixes[0].String(); cidr != "10.1.0.0/24" {
		t.Errorf("prefix: want 10.1.0.0/24, got %s", cidr)
	}
}

func TestAddressPoolSource_NodeFilter(t *testing.T) {
	t.Parallel()

	pool := &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: "pool-a"},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
			Addresses:     []string{"10.1.0.0/24"},
		},
	}
	advA := &juneauv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: "adv-a"},
		Spec: juneauv1alpha1.BGPAdvertisementSpec{
			AddressPools: []string{"pool-a"},
			NodeName:     "node-a",
			Prefix:       "10.1.0.5/32",
		},
	}
	advB := &juneauv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: "adv-b"},
		Spec: juneauv1alpha1.BGPAdvertisementSpec{
			AddressPools: []string{"pool-a"},
			NodeName:     "node-b",
			Prefix:       "10.1.0.6/32",
		},
	}

	cl := newFakeClient(t, pool, advA, advB)
	res, err := AddressPoolAdvertisementSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := len(res.Advertisements); got != 1 {
		t.Fatalf("Advertisements: want 1, got %d", got)
	}
	if cidr := res.Advertisements[0].Prefixes[0].String(); cidr != "10.1.0.5/32" {
		t.Errorf("expected node-a-only prefix, got %s", cidr)
	}
}

func TestAddressPoolSource_ReportsArpModePoolAsError(t *testing.T) {
	t.Parallel()

	pool := &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: "pool-arp"},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeARP,
			Addresses:     []string{"10.1.0.10-10.1.0.20"},
		},
	}
	adv := &juneauv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: "adv"},
		Spec: juneauv1alpha1.BGPAdvertisementSpec{
			AddressPools: []string{"pool-arp"},
		},
	}

	cl := newFakeClient(t, pool, adv)
	res, err := AddressPoolAdvertisementSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Advertisements) != 0 {
		t.Errorf("ARP pool must not produce advertisements: %v", res.Advertisements)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("Errors: want 1, got %v", res.Errors)
	}
	if res.Errors[0].ResourceKind != "AddressPool" {
		t.Errorf("Errors[0].ResourceKind: want AddressPool, got %s", res.Errors[0].ResourceKind)
	}
}

func TestAddressPoolSource_DeduplicatesPrefixesAcrossAdvs(t *testing.T) {
	t.Parallel()

	pool := &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: "pool-a"},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
			Addresses:     []string{"10.1.0.0/24", "10.2.0.0/24"},
		},
	}
	advs := []client.Object{
		&juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: "a1"},
			Spec:       juneauv1alpha1.BGPAdvertisementSpec{AddressPools: []string{"pool-a"}},
		},
		&juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: "a2"},
			Spec:       juneauv1alpha1.BGPAdvertisementSpec{AddressPools: []string{"pool-a"}},
		},
	}
	cl := newFakeClient(t, append(advs, pool)...)
	res, err := AddressPoolAdvertisementSource{}.Build(context.Background(), Input{Client: cl, NodeName: "node-a"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := len(res.Advertisements); got != 1 {
		t.Fatalf("Advertisements (one per pool): want 1, got %d", got)
	}
	prefixes := []string{}
	for _, p := range res.Advertisements[0].Prefixes {
		prefixes = append(prefixes, p.String())
	}
	sort.Strings(prefixes)
	if !reflect.DeepEqual(prefixes, []string{"10.1.0.0/24", "10.2.0.0/24"}) {
		t.Errorf("unexpected prefix list: %v", prefixes)
	}
}
