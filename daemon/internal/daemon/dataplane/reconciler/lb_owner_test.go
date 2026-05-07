package reconciler

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// fakeSlotWriter records every UpdateSlot call and exposes the
// resulting slot table so tests can assert ordering, idempotency, and
// diff-only updates without standing up a real BPF map.
type fakeSlotWriter struct {
	mu         sync.Mutex
	slots      []uint32
	updates    []slotUpdate
	failOnSlot int
}

type slotUpdate struct {
	slot     uint32
	ownerNBO uint32
}

func newFakeSlotWriter(slotCount uint32) *fakeSlotWriter {
	return &fakeSlotWriter{
		slots:      make([]uint32, slotCount),
		failOnSlot: -1,
	}
}

func (w *fakeSlotWriter) UpdateSlot(slot, owner uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failOnSlot >= 0 && int(slot) == w.failOnSlot {
		return errFakeWriter
	}
	w.slots[slot] = owner
	w.updates = append(w.updates, slotUpdate{slot: slot, ownerNBO: owner})
	return nil
}

func (w *fakeSlotWriter) ResetUpdateLog() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.updates = nil
}

var errFakeWriter = fakeWriterError{}

type fakeWriterError struct{}

func (fakeWriterError) Error() string { return "fake writer forced failure" }

func newClient(objs ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = juneauv1alpha1.AddToScheme(scheme)
	b := fake.NewClientBuilder().WithScheme(scheme)
	if len(objs) > 0 {
		b = b.WithObjects(objs...)
	}
	return b.Build()
}

func nodeNWEP(name, nodeIP string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.NetworkEndpointSpec{Kind: juneauv1alpha1.EndpointKindNode},
		Status:     juneauv1alpha1.NetworkEndpointStatus{NodeIP: nodeIP},
	}
}

// nbo turns a dotted-quad IPv4 into network-byte-order uint32.
func nbo(t *testing.T, ip string) uint32 {
	t.Helper()
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		t.Fatalf("invalid test IP %q", ip)
	}
	return binary.BigEndian.Uint32(v4)
}

const testSlotCount uint32 = 53 // small prime so the fake writer's slot vector stays cheap

func TestLBOwner_FirstReconcileWritesEverySlot(t *testing.T) {
	t.Parallel()
	cl := newClient(
		nodeNWEP("node-1", "10.0.0.1"),
		nodeNWEP("node-2", "10.0.0.2"),
		nodeNWEP("node-3", "10.0.0.3"),
	)
	w := newFakeSlotWriter(testSlotCount)
	r := newLBOwnerWithWriter(cl, w, testSlotCount)

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Every slot should hold one of the three Node IPs (no zeros).
	got := r.Snapshot()
	allowed := map[uint32]bool{
		nbo(t, "10.0.0.1"): true,
		nbo(t, "10.0.0.2"): true,
		nbo(t, "10.0.0.3"): true,
	}
	for i, ip := range got {
		if !allowed[ip] {
			t.Fatalf("slot %d = 0x%x, want one of {10.0.0.1, .2, .3}", i, ip)
		}
	}

	// Updates issued: at most testSlotCount; the diff path skips zero
	// → zero transitions, but every initial slot is non-zero so we
	// should see exactly testSlotCount updates.
	if len(w.updates) != int(testSlotCount) {
		t.Fatalf("first Reconcile issued %d updates, want %d", len(w.updates), testSlotCount)
	}
}

func TestLBOwner_SecondReconcileWithSameNodesIsNoOp(t *testing.T) {
	t.Parallel()
	cl := newClient(
		nodeNWEP("node-1", "10.0.0.1"),
		nodeNWEP("node-2", "10.0.0.2"),
		nodeNWEP("node-3", "10.0.0.3"),
	)
	w := newFakeSlotWriter(testSlotCount)
	r := newLBOwnerWithWriter(cl, w, testSlotCount)

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("first Reconcile failed: %v", err)
	}
	w.ResetUpdateLog()

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("second Reconcile failed: %v", err)
	}
	if len(w.updates) != 0 {
		t.Fatalf("second Reconcile (same input) issued %d updates, want 0 (diff is empty)", len(w.updates))
	}
}

func TestLBOwner_AddingNodeOnlyRewritesAffectedSlots(t *testing.T) {
	t.Parallel()
	cl := newClient(
		nodeNWEP("node-1", "10.0.0.1"),
		nodeNWEP("node-2", "10.0.0.2"),
	)
	w := newFakeSlotWriter(testSlotCount)
	r := newLBOwnerWithWriter(cl, w, testSlotCount)

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("first Reconcile failed: %v", err)
	}

	// Add a third Node and reconcile again. Maglev guarantees ≈ M/N
	// disruption — assert that the diff is bounded well below
	// "rewrite everything".
	if err := cl.Create(context.Background(), nodeNWEP("node-3", "10.0.0.3")); err != nil {
		t.Fatalf("create third NWEP: %v", err)
	}
	w.ResetUpdateLog()

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("second Reconcile failed: %v", err)
	}

	// Loose bound: half the table is the worst case we tolerate; in
	// practice Maglev moves much less. The strict bound is exercised
	// by the maglev package's own disruption tests.
	upper := int(testSlotCount) / 2
	if len(w.updates) > upper {
		t.Fatalf("add-node reconcile rewrote %d slots, want ≤ %d (Maglev disruption bound)", len(w.updates), upper)
	}
	if len(w.updates) == 0 {
		t.Fatalf("add-node reconcile rewrote 0 slots; expected the new Node to claim some")
	}
}

func TestLBOwner_RemovingNodeOnlyRewritesAffectedSlots(t *testing.T) {
	t.Parallel()
	nweps := []client.Object{
		nodeNWEP("node-1", "10.0.0.1"),
		nodeNWEP("node-2", "10.0.0.2"),
		nodeNWEP("node-3", "10.0.0.3"),
	}
	cl := newClient(nweps...)
	w := newFakeSlotWriter(testSlotCount)
	r := newLBOwnerWithWriter(cl, w, testSlotCount)

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("first Reconcile failed: %v", err)
	}

	if err := cl.Delete(context.Background(), nweps[2]); err != nil {
		t.Fatalf("delete NWEP: %v", err)
	}
	w.ResetUpdateLog()

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("second Reconcile failed: %v", err)
	}
	upper := int(testSlotCount) / 2
	if len(w.updates) > upper {
		t.Fatalf("remove-node reconcile rewrote %d slots, want ≤ %d", len(w.updates), upper)
	}
}

func TestLBOwner_NWEPWithoutNodeIPIsSkipped(t *testing.T) {
	t.Parallel()
	cl := newClient(
		nodeNWEP("node-1", "10.0.0.1"),
		nodeNWEP("node-pending", ""),
	)
	w := newFakeSlotWriter(testSlotCount)
	r := newLBOwnerWithWriter(cl, w, testSlotCount)

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	got := r.Snapshot()
	want := nbo(t, "10.0.0.1")
	for i, v := range got {
		if v != want {
			t.Fatalf("slot %d = 0x%x, want 0x%x (only one ready NWEP)", i, v, want)
		}
	}
}

func TestLBOwner_PodNWEPsAreIgnored(t *testing.T) {
	t.Parallel()
	pod := &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-thing"},
		Spec:       juneauv1alpha1.NetworkEndpointSpec{Kind: juneauv1alpha1.EndpointKindPod},
		Status:     juneauv1alpha1.NetworkEndpointStatus{NodeIP: "10.0.0.99"},
	}
	cl := newClient(nodeNWEP("node-1", "10.0.0.1"), pod)
	w := newFakeSlotWriter(testSlotCount)
	r := newLBOwnerWithWriter(cl, w, testSlotCount)

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	pretender := nbo(t, "10.0.0.99")
	for i, v := range r.Snapshot() {
		if v == pretender {
			t.Fatalf("slot %d picked up Pod NWEP IP 0x%x; only Kind=Node should contribute", i, v)
		}
	}
}

func TestLBOwner_EmptyMembershipResultsInZeroOwners(t *testing.T) {
	t.Parallel()
	cl := newClient()
	w := newFakeSlotWriter(testSlotCount)
	r := newLBOwnerWithWriter(cl, w, testSlotCount)

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	for i, v := range r.Snapshot() {
		if v != 0 {
			t.Fatalf("slot %d = 0x%x, want 0 (no Nodes); zero is the lb_resolve_owner sentinel", i, v)
		}
	}
}

func TestLBOwner_RebuildHookFiresWithChangedSlotCount(t *testing.T) {
	t.Parallel()
	cl := newClient(nodeNWEP("node-1", "10.0.0.1"))
	w := newFakeSlotWriter(testSlotCount)

	var calls []int
	r := newLBOwnerWithWriter(cl, w, testSlotCount, WithLBOwnerRebuildHook(func(n int) {
		calls = append(calls, n)
	}))

	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if err := r.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("second Reconcile failed: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("hook fired %d times, want 2", len(calls))
	}
	if calls[0] == 0 {
		t.Fatalf("first hook reported 0 changes; expected ≥ 1 on initial fill")
	}
	if calls[1] != 0 {
		t.Fatalf("second hook reported %d changes; expected 0 on idempotent rerun", calls[1])
	}
}

func TestLBOwner_PropagatesWriterFailure(t *testing.T) {
	t.Parallel()
	cl := newClient(nodeNWEP("node-1", "10.0.0.1"))
	w := newFakeSlotWriter(testSlotCount)
	w.failOnSlot = 0 // force an error on the first slot update

	r := newLBOwnerWithWriter(cl, w, testSlotCount)

	if err := r.Reconcile(context.Background(), ""); err == nil {
		t.Fatalf("Reconcile succeeded, expected propagated writer failure")
	}
}
