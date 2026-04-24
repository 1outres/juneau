package nodestate

import (
	"context"
	"fmt"
	"time"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DefaultInterval     = 15 * time.Second
	DefaultFieldManager = "bgp-speaker"
)

type Publisher struct {
	nodeName     string
	client       client.Client
	builder      *Builder
	inputsFn     func() Inputs
	interval     time.Duration
	fieldManager string
}

type PublisherOption func(*Publisher)

func WithInterval(d time.Duration) PublisherOption {
	return func(p *Publisher) { p.interval = d }
}

func WithFieldManager(name string) PublisherOption {
	return func(p *Publisher) { p.fieldManager = name }
}

func NewPublisher(nodeName string, cl client.Client, builder *Builder, inputsFn func() Inputs, opts ...PublisherOption) *Publisher {
	p := &Publisher{
		nodeName:     nodeName,
		client:       cl,
		builder:      builder,
		inputsFn:     inputsFn,
		interval:     DefaultInterval,
		fieldManager: DefaultFieldManager,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Run applies the status on each interval tick until ctx is cancelled.
// Individual apply failures are logged; the loop continues.
func (p *Publisher) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		if err := p.ApplyOnce(ctx); err != nil {
			zap.S().Warnw("apply BGPNodeState status", "node", p.nodeName, "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// ApplyOnce builds and server-side-applies the status once.
// Returns nil if the BGPNodeState resource does not yet exist.
func (p *Publisher) ApplyOnce(ctx context.Context) error {
	var current juneauv1alpha1.BGPNodeState
	if err := p.client.Get(ctx, types.NamespacedName{Name: p.nodeName}, &current); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get BGPNodeState/%s: %w", p.nodeName, err)
	}

	status := p.builder.Build(p.inputsFn())
	status.Conditions = MergeConditions(current.Status.Conditions, status.Conditions)

	apply := &juneauv1alpha1.BGPNodeState{
		TypeMeta: metav1.TypeMeta{
			APIVersion: juneauv1alpha1.GroupVersion.String(),
			Kind:       "BGPNodeState",
		},
		ObjectMeta: metav1.ObjectMeta{Name: p.nodeName},
		Status:     status,
	}

	if err := p.client.Status().Patch(ctx, apply, client.Apply,
		client.FieldOwner(p.fieldManager),
		client.ForceOwnership,
	); err != nil {
		return fmt.Errorf("apply BGPNodeState/%s status: %w", p.nodeName, err)
	}
	return nil
}

// MergeConditions folds desired conditions into existing, preserving
// LastTransitionTime for types whose Status did not change. Desired entries'
// LastTransitionTime is used only when the Status actually transitions.
func MergeConditions(existing, desired []metav1.Condition) []metav1.Condition {
	merged := append([]metav1.Condition(nil), existing...)
	for _, c := range desired {
		meta.SetStatusCondition(&merged, c)
	}
	return merged
}
