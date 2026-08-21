package reconciler

import (
	"context"
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/ownedaddr"
)

func newNaptAttachment(nodeName, assignedIP string) *juneauv1alpha1.ExternalNetworkAttachment {
	return &juneauv1alpha1.ExternalNetworkAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "extnet--node-a"},
		Spec: juneauv1alpha1.ExternalNetworkAttachmentSpec{
			ExternalNetwork: "extnet",
			NodeName:        nodeName,
		},
		Status: juneauv1alpha1.ExternalNetworkAttachmentStatus{AssignedIP: assignedIP},
	}
}

func newNaptFixture(t *testing.T, objs ...runtime.Object) (*Napt, *fakeBpfMap, *ownedaddr.Store) {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(newNatTestScheme(t)).WithRuntimeObjects(objs...).Build()
	poolMap := newFakeBpfMap()
	store := ownedaddr.NewStore(poolMap)
	r := &Napt{
		client:       cl,
		naptSrc:      newFakeBpfMap(),
		nodeName:     "node-a",
		owned:        store.Scope(naptScope),
		srcInstalled: make(map[string]map[uint32]struct{}),
	}
	return r, poolMap, store
}

func poolPrefixes(t *testing.T, m *fakeBpfMap) []string {
	t.Helper()
	out := make([]string, 0, len(m.entries))
	for key := range m.entries {
		k, ok := key.(bpf.PodEgressExternalAddressPoolsKey)
		if !ok {
			t.Fatalf("unexpected key type %T in external_address_pools", key)
		}
		out = append(out, ownedaddr.Key{Prefixlen: k.Prefixlen, Addr: k.Addr}.String())
	}
	sort.Strings(out)
	return out
}

func TestNaptClaimsAssignedIPAsHostPrefix(t *testing.T) {
	r, poolMap, _ := newNaptFixture(t, newNaptAttachment("node-a", "192.0.2.5"))

	if err := r.Reconcile(context.Background(), "extnet--node-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := poolPrefixes(t, poolMap)
	if len(got) != 1 || got[0] != "192.0.2.5/32" {
		t.Fatalf("external_address_pools = %v, want [192.0.2.5/32]", got)
	}
}

func TestNaptReleasesClaimWhenAttachmentLeavesTheNode(t *testing.T) {
	attachment := newNaptAttachment("node-a", "192.0.2.5")
	r, poolMap, _ := newNaptFixture(t, attachment)

	if err := r.Reconcile(context.Background(), "extnet--node-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	attachment.Spec.NodeName = "node-b"
	if err := r.client.Update(context.Background(), attachment); err != nil {
		t.Fatalf("update attachment: %v", err)
	}
	if err := r.Reconcile(context.Background(), "extnet--node-a"); err != nil {
		t.Fatalf("Reconcile after move: %v", err)
	}

	if got := poolPrefixes(t, poolMap); len(got) != 0 {
		t.Fatalf("external_address_pools = %v, want empty", got)
	}
}

func TestNaptReleasesClaimWhenAttachmentIsDeleted(t *testing.T) {
	r, poolMap, _ := newNaptFixture(t, newNaptAttachment("node-a", "192.0.2.5"))

	if err := r.Reconcile(context.Background(), "extnet--node-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := r.client.Delete(context.Background(), newNaptAttachment("node-a", "192.0.2.5")); err != nil {
		t.Fatalf("delete attachment: %v", err)
	}
	if err := r.Reconcile(context.Background(), "extnet--node-a"); err != nil {
		t.Fatalf("Reconcile after delete: %v", err)
	}

	if got := poolPrefixes(t, poolMap); len(got) != 0 {
		t.Fatalf("external_address_pools = %v, want empty", got)
	}
}

func TestNaptReclaimsWhenAssignedIPChanges(t *testing.T) {
	attachment := newNaptAttachment("node-a", "192.0.2.5")
	r, poolMap, _ := newNaptFixture(t, attachment)

	if err := r.Reconcile(context.Background(), "extnet--node-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	attachment.Status.AssignedIP = "192.0.2.6"
	if err := r.client.Update(context.Background(), attachment); err != nil {
		t.Fatalf("update attachment: %v", err)
	}
	if err := r.Reconcile(context.Background(), "extnet--node-a"); err != nil {
		t.Fatalf("Reconcile after readdress: %v", err)
	}

	got := poolPrefixes(t, poolMap)
	if len(got) != 1 || got[0] != "192.0.2.6/32" {
		t.Fatalf("external_address_pools = %v, want [192.0.2.6/32]", got)
	}
}

func TestNaptCloseAllReleasesEveryClaim(t *testing.T) {
	r, poolMap, _ := newNaptFixture(t, newNaptAttachment("node-a", "192.0.2.5"))

	if err := r.Reconcile(context.Background(), "extnet--node-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := r.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}

	if got := poolPrefixes(t, poolMap); len(got) != 0 {
		t.Fatalf("external_address_pools = %v, want empty", got)
	}
}

func TestNaptKeepsClaimHeldByAnotherReconciler(t *testing.T) {
	r, poolMap, store := newNaptFixture(t, newNaptAttachment("node-a", "192.0.2.5"))
	other := store.Scope("external-arp")
	shared, err := ownedaddr.ParsePrefix("192.0.2.5/32")
	if err != nil {
		t.Fatalf("ParsePrefix: %v", err)
	}

	if err := r.Reconcile(context.Background(), "extnet--node-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := other.Set("adv-a", []ownedaddr.Key{shared}); err != nil {
		t.Fatalf("Set external-arp claim: %v", err)
	}
	if err := r.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}

	got := poolPrefixes(t, poolMap)
	if len(got) != 1 || got[0] != "192.0.2.5/32" {
		t.Fatalf("external_address_pools = %v, want [192.0.2.5/32] still claimed by external-arp", got)
	}
}
