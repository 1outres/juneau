package nodestate_test

import (
	"context"
	"testing"
	"time"

	"github.com/1outres/juneau/bgp-speaker/internal/bmp"
	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
	"github.com/1outres/juneau/bgp-speaker/internal/peerindex"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Full SSA round-trip is exercised by envtest/e2e since controller-runtime's
// fake client does not implement apply patches:
// https://github.com/kubernetes/kubernetes/issues/115598

func TestMergeConditions_StatusUnchanged_KeepsExistingLastTransitionTime(t *testing.T) {
	t.Parallel()

	old := time.Date(2026, 4, 24, 9, 0, 0, 0, time.UTC)
	now := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)

	existing := []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Healthy",
		Message:            "all good",
		LastTransitionTime: metav1.NewTime(old),
	}}
	desired := []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Healthy",
		Message:            "all good",
		LastTransitionTime: metav1.NewTime(now),
	}}

	got := nodestate.MergeConditions(existing, desired)
	if len(got) != 1 {
		t.Fatalf("want 1 condition, got %d", len(got))
	}
	if !got[0].LastTransitionTime.Time.Equal(old) {
		t.Errorf("LastTransitionTime: want preserved %v, got %v", old, got[0].LastTransitionTime)
	}
}

func TestMergeConditions_StatusChanged_AdvancesLastTransitionTime(t *testing.T) {
	t.Parallel()

	old := time.Date(2026, 4, 24, 9, 0, 0, 0, time.UTC)
	now := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)

	existing := []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Healthy",
		LastTransitionTime: metav1.NewTime(old),
	}}
	desired := []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             "BirdNotRunning",
		LastTransitionTime: metav1.NewTime(now),
	}}

	got := nodestate.MergeConditions(existing, desired)
	if len(got) != 1 {
		t.Fatalf("want 1 condition, got %d", len(got))
	}
	if !got[0].LastTransitionTime.Time.Equal(now) {
		t.Errorf("LastTransitionTime: want advanced to %v, got %v", now, got[0].LastTransitionTime)
	}
	if got[0].Reason != "BirdNotRunning" {
		t.Errorf("Reason: want updated, got %q", got[0].Reason)
	}
}

func TestMergeConditions_NewConditionType_Appended(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	desired := []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Healthy",
		LastTransitionTime: metav1.NewTime(now),
	}}

	got := nodestate.MergeConditions(nil, desired)
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if !got[0].LastTransitionTime.Time.Equal(now) {
		t.Errorf("LastTransitionTime: want %v, got %v", now, got[0].LastTransitionTime)
	}
}

func TestPublisher_ApplyOnce_NotFound_NoError(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&juneauv1alpha1.BGPNodeState{}).
		Build()

	builder := nodestate.NewBuilder("node-a", bmp.NewTracker(), peerindex.New())
	pub := nodestate.NewPublisher("node-a", cl, builder,
		func() nodestate.Inputs { return nodestate.Inputs{} })

	if err := pub.ApplyOnce(context.Background()); err != nil {
		t.Errorf("ApplyOnce: want nil on NotFound, got %v", err)
	}

	// Sanity: nothing was created.
	got := &juneauv1alpha1.BGPNodeState{}
	if err := cl.Get(context.Background(), types.NamespacedName{Name: "node-a"}, got); err == nil {
		t.Errorf("Get: want NotFound, got object %+v", got)
	}
}
