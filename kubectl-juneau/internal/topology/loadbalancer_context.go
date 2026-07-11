package topology

import (
	"context"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// LoadBalancerContext is the rendering input for `kubectl juneau
// describe loadbalancer`. It wraps the SLB resource alongside the
// parent Service and the resolved ExternalNetwork so the presenter
// does not have to perform additional lookups while rendering.
type LoadBalancerContext struct {
	Namespace string
	Name      string

	// Service is the parent Kubernetes Service (nil when not found).
	Service *corev1.Service

	// SLB is the ServiceLoadBalancer for this Service. nil when the
	// SLB does not exist (e.g. the Service is not Juneau-managed or
	// has not yet been reconciled).
	SLB *juneauv1alpha1.ServiceLoadBalancer

	// ExternalNetwork is the cluster-scoped ExternalNetwork the SLB
	// references via spec.externalNetwork. nil when missing.
	ExternalNetwork *juneauv1alpha1.ExternalNetwork
}

// ResolveLoadBalancerContext fetches the SLB and the resources it
// joins on (Service, ExternalNetwork). Missing resources surface as
// nil fields rather than errors so the presenter can render
// `(not found)` branches uniformly.
func ResolveLoadBalancerContext(ctx context.Context, v View, namespace, name string) (*LoadBalancerContext, error) {
	out := &LoadBalancerContext{Namespace: namespace, Name: name}

	svc, err := v.Service(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	out.Service = svc

	slb, err := v.ServiceLoadBalancer(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	out.SLB = slb
	if slb == nil || slb.Spec.ExternalNetwork == "" {
		return out, nil
	}

	en, err := v.ExternalNetwork(ctx, slb.Spec.ExternalNetwork)
	if err != nil {
		return nil, err
	}
	out.ExternalNetwork = en
	return out, nil
}
