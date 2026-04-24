package nodestate_test

import (
	"context"
	"testing"

	"github.com/1outres/juneau/bgp-speaker/internal/bmp"
	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
	"github.com/1outres/juneau/bgp-speaker/internal/peerindex"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Full SSA round-trip is exercised by envtest/e2e since controller-runtime's
// fake client does not implement apply patches:
// https://github.com/kubernetes/kubernetes/issues/115598

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
