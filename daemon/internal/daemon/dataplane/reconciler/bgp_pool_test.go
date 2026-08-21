package reconciler

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/ownedaddr"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(juneauv1alpha1.AddToScheme(s))
	return s
}

func newBgpPool(t *testing.T, objs []runtime.Object) (*BgpPool, *fakeBpfMap) {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithRuntimeObjects(objs...).Build()
	poolMap := newFakeBpfMap()
	return NewBgpPool(cl, ownedaddr.NewStore(poolMap)), poolMap
}

func prefixStrings(keys []ownedaddr.Key) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key.String())
	}
	sort.Strings(out)
	return out
}

func newBgpTestPool(name string, mode juneauv1alpha1.AddressPoolAdvertiseMode, addrs ...string) *juneauv1alpha1.AddressPool {
	return &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: mode,
			Addresses:     addrs,
		},
	}
}

func newBgpTestAdvertisement(name string, pools ...string) *juneauv1alpha1.BGPAdvertisement {
	return &juneauv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.BGPAdvertisementSpec{AddressPools: pools},
	}
}

func TestBgpPool_BuildDesired(t *testing.T) {
	tests := []struct {
		name         string
		objs         []runtime.Object
		wantCanon    []string
		wantWarnRegx []string
	}{
		{
			name: "referenced BGP pool emits entries, non-BGP is warned",
			objs: []runtime.Object{
				newBgpTestPool("bgp", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.1.0.0/24", "192.168.1.1"),
				newBgpTestPool("arp", juneauv1alpha1.AddressPoolAdvertiseModeARP, "10.2.0.0/24"),
				newBgpTestAdvertisement("adv", "bgp", "arp"),
			},
			wantCanon:    []string{"10.1.0.0/24", "192.168.1.1/32"},
			wantWarnRegx: []string{"advertiseMode"},
		},
		{
			name: "missing pool reference is warned and skipped",
			objs: []runtime.Object{
				newBgpTestAdvertisement("adv", "ghost"),
			},
			wantCanon:    nil,
			wantWarnRegx: []string{"missing AddressPool/ghost"},
		},
		{
			name: "unreferenced BGP pool is not emitted",
			objs: []runtime.Object{
				newBgpTestPool("idle", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.3.0.0/24"),
			},
			wantCanon: nil,
		},
		{
			name: "invalid address is warned, valid siblings still emitted",
			objs: []runtime.Object{
				newBgpTestPool("bgp", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "bogus", "10.4.0.0/24"),
				newBgpTestAdvertisement("adv", "bgp"),
			},
			wantCanon:    []string{"10.4.0.0/24"},
			wantWarnRegx: []string{"invalid address"},
		},
		{
			name: "duplicate prefixes across pools are deduped",
			objs: []runtime.Object{
				newBgpTestPool("a", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.5.0.0/24"),
				newBgpTestPool("b", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.5.0.0/24"),
				newBgpTestAdvertisement("adv", "a", "b"),
			},
			wantCanon: []string{"10.5.0.0/24"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newBgpPool(t, tt.objs)
			desired, warnings, err := r.buildDesired(context.Background())
			if err != nil {
				t.Fatalf("buildDesired: %v", err)
			}

			gotCanon := prefixStrings(desired)
			want := append([]string{}, tt.wantCanon...)
			sort.Strings(want)
			if len(gotCanon) != len(want) || (len(gotCanon) > 0 && !reflect.DeepEqual(gotCanon, want)) {
				t.Errorf("desired canonical = %v, want %v", gotCanon, want)
			}

			for _, needle := range tt.wantWarnRegx {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, needle) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("want warning containing %q, got %v", needle, warnings)
				}
			}
		})
	}
}

func TestBgpPool_ReconcileProgramsDesiredPrefixes(t *testing.T) {
	objs := []runtime.Object{
		newBgpTestPool("bgp", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.1.0.0/24", "192.168.1.1"),
		newBgpTestAdvertisement("adv", "bgp"),
	}
	r, poolMap := newBgpPool(t, objs)

	if err := r.Reconcile(context.Background(), "__singleton__"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := poolPrefixes(t, poolMap)
	want := []string{"10.1.0.0/24", "192.168.1.1/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("external_address_pools = %v, want %v", got, want)
	}
}

func TestBgpPool_ReconcileDropsPrefixesThatLeftThePool(t *testing.T) {
	pool := newBgpTestPool("bgp", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.1.0.0/24", "10.2.0.0/24")
	objs := []runtime.Object{pool, newBgpTestAdvertisement("adv", "bgp")}
	r, poolMap := newBgpPool(t, objs)

	if err := r.Reconcile(context.Background(), "__singleton__"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	pool.Spec.Addresses = []string{"10.1.0.0/24"}
	if err := r.client.Update(context.Background(), pool); err != nil {
		t.Fatalf("update AddressPool: %v", err)
	}
	if err := r.Reconcile(context.Background(), "__singleton__"); err != nil {
		t.Fatalf("Reconcile after shrink: %v", err)
	}

	got := poolPrefixes(t, poolMap)
	want := []string{"10.1.0.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("external_address_pools = %v, want %v", got, want)
	}
}

func TestBgpPool_ReconcileKeepsPrefixClaimedByNapt(t *testing.T) {
	pool := newBgpTestPool("bgp", juneauv1alpha1.AddressPoolAdvertiseModeBGP, "192.0.2.5")
	objs := []runtime.Object{pool, newBgpTestAdvertisement("adv", "bgp")}
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithRuntimeObjects(objs...).Build()
	poolMap := newFakeBpfMap()
	store := ownedaddr.NewStore(poolMap)
	r := NewBgpPool(cl, store)

	naptClaim, err := ownedaddr.ParsePrefix("192.0.2.5")
	if err != nil {
		t.Fatalf("ParsePrefix: %v", err)
	}
	if err := store.Scope(naptScope).Set("extnet--node-a", []ownedaddr.Key{naptClaim}); err != nil {
		t.Fatalf("Set napt claim: %v", err)
	}
	if err := r.Reconcile(context.Background(), "__singleton__"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	pool.Spec.Addresses = nil
	if err := r.client.Update(context.Background(), pool); err != nil {
		t.Fatalf("update AddressPool: %v", err)
	}
	if err := r.Reconcile(context.Background(), "__singleton__"); err != nil {
		t.Fatalf("Reconcile after emptying pool: %v", err)
	}

	got := poolPrefixes(t, poolMap)
	want := []string{"192.0.2.5/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("external_address_pools = %v, want %v (napt still claims it)", got, want)
	}
}
