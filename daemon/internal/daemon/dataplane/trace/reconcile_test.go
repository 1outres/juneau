package trace

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestBuildSessionSpec covers the CRD → daemon SessionSpec
// translation. Numeric fields must round-trip exactly so the BPF
// side sees the operator's intent.
func TestBuildSessionSpec(t *testing.T) {
	exp := time.Now().Add(time.Minute)
	ts := &juneauv1alpha1.TraceSession{
		ObjectMeta: metav1.ObjectMeta{Generation: 7},
		Spec: juneauv1alpha1.TraceSessionSpec{
			TraceID:   42,
			Mode:      juneauv1alpha1.TraceModeActiveProbe,
			ExpiresAt: metav1.NewTime(exp),
			Capture: juneauv1alpha1.TraceCaptureConfig{
				Level:             juneauv1alpha1.TraceCaptureLevelVerbose,
				IncludePacketMeta: true,
				IncludeMapMiss:    true,
				IncludePolicy:     false,
				IncludeNAT:        true,
			},
			InitialTuples: []juneauv1alpha1.TraceTuple{
				{
					Scope:    juneauv1alpha1.TraceTupleScopeVPC,
					VPCID:    7,
					SrcIP:    "10.0.1.1",
					DstIP:    "10.0.2.2",
					DstPort:  443,
					Protocol: juneauv1alpha1.TraceProtocolTCP,
				},
			},
		},
	}

	spec, err := buildSessionSpec(ts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if spec.TraceID != 42 {
		t.Fatalf("trace_id: %d", spec.TraceID)
	}
	if spec.Generation != 7 {
		t.Fatalf("generation: %d", spec.Generation)
	}
	if spec.Mode != 1 {
		t.Fatalf("mode: %d (want 1=active)", spec.Mode)
	}
	if spec.Level != LevelVerbose {
		t.Fatalf("level: %d", spec.Level)
	}
	wantFlags := CapturePacketMeta | CaptureMapMiss | CaptureNAT
	if spec.CaptureFlags != wantFlags {
		t.Fatalf("flags: %x (want %x)", spec.CaptureFlags, wantFlags)
	}
	if !spec.ExpiresAt.Equal(exp) {
		t.Fatalf("expiresAt: %v (want %v)", spec.ExpiresAt, exp)
	}
	if len(spec.Tuples) != 1 {
		t.Fatalf("tuples: %d", len(spec.Tuples))
	}
	tk := spec.Tuples[0]
	if tk.Scope != ScopeVPC || tk.VPCID != 7 || tk.Protocol != 6 || tk.DstPort != 443 {
		t.Fatalf("tuple: %+v", tk)
	}
	if tk.SrcIP != [4]byte{10, 0, 1, 1} {
		t.Fatalf("src: %v", tk.SrcIP)
	}
}

// fakeStore captures Apply / Delete calls so the reconciler logic can
// be tested without a real BPF-backed Store.
type fakeStore struct {
	applied []SessionSpec
	deleted []uint32
	failOn  uint32 // if non-zero, Delete returns an error for this id
}

func (f *fakeStore) Apply(s SessionSpec) error {
	f.applied = append(f.applied, s)
	return nil
}

func (f *fakeStore) Delete(id uint32) error {
	if f.failOn != 0 && id == f.failOn {
		return errors.New("boom")
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func TestReconcilerDeleteByNameOnlyTouchesNamedSession(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}

	exp := metav1.NewTime(time.Now().Add(time.Minute))
	tsA := &juneauv1alpha1.TraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "trace-a", Generation: 1},
		Spec: juneauv1alpha1.TraceSessionSpec{
			TraceID:   100,
			Mode:      juneauv1alpha1.TraceModeObserveOnly,
			ExpiresAt: exp,
		},
	}
	tsB := &juneauv1alpha1.TraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "trace-b", Generation: 1},
		Spec: juneauv1alpha1.TraceSessionSpec{
			TraceID:   200,
			Mode:      juneauv1alpha1.TraceModeObserveOnly,
			ExpiresAt: exp,
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&juneauv1alpha1.TraceSession{}).
		WithObjects(tsA, tsB).
		Build()

	store := &fakeStore{}
	r := &Reconciler{client: cl, store: store, idByName: map[string]uint32{}}

	ctx := context.Background()
	if err := r.Reconcile(ctx, "trace-a"); err != nil {
		t.Fatalf("reconcile a: %v", err)
	}
	if err := r.Reconcile(ctx, "trace-b"); err != nil {
		t.Fatalf("reconcile b: %v", err)
	}
	if len(store.applied) != 2 {
		t.Fatalf("applied: got %d, want 2", len(store.applied))
	}

	// Now simulate trace-a being deleted from the API server. The next
	// reconcile observes NotFound and must drop ONLY trace-a.
	if err := cl.Delete(ctx, tsA); err != nil {
		t.Fatalf("delete a: %v", err)
	}
	if err := r.Reconcile(ctx, "trace-a"); err != nil {
		t.Fatalf("reconcile after delete: %v", err)
	}

	if !slices.Equal(store.deleted, []uint32{100}) {
		t.Fatalf("store.deleted = %v, want [100]", store.deleted)
	}

	r.mu.Lock()
	_, stillTracked := r.idByName["trace-a"]
	idB, ok := r.idByName["trace-b"]
	r.mu.Unlock()
	if stillTracked {
		t.Fatalf("trace-a still in idByName after delete")
	}
	if !ok || idB != 200 {
		t.Fatalf("idByName[trace-b] = %d/%v, want 200/true", idB, ok)
	}
}

func TestReconcilerDeleteByNameUntrackedIsNoop(t *testing.T) {
	// If we never observed an Apply on this node (e.g., daemon
	// restarted between Apply and the delete event), deleteByName must
	// not blow away peer sessions. Existence in the store is GC'd on
	// expiresAt.
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	store := &fakeStore{}
	r := &Reconciler{client: cl, store: store, idByName: map[string]uint32{}}

	if err := r.Reconcile(context.Background(), "ghost"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("store.deleted should be empty, got %v", store.deleted)
	}
}

func TestBuildSessionSpecObserveOnlyDefaultsLevel(t *testing.T) {
	ts := &juneauv1alpha1.TraceSession{
		Spec: juneauv1alpha1.TraceSessionSpec{
			TraceID:   1,
			Mode:      juneauv1alpha1.TraceModeObserveOnly,
			ExpiresAt: metav1.NewTime(time.Now().Add(time.Minute)),
		},
	}
	spec, err := buildSessionSpec(ts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if spec.Mode != 0 {
		t.Fatalf("mode: %d (want 0=observe)", spec.Mode)
	}
	if spec.Level != LevelDecision {
		t.Fatalf("level default: %d (want %d)", spec.Level, LevelDecision)
	}
}
