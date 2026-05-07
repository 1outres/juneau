/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// SetupServiceLoadBalancerMutatingWebhookWithManager registers the
// mutating webhook that defaults Service.spec.allocateLoadBalancerNodePorts
// to false for Juneau-class LB Services. The mutation is necessary
// because Juneau implements LB ingress entirely in eBPF on each Node;
// the upstream-default NodePort allocation would only consume an
// unused port and risk colliding with operator-managed NodePort ranges.
//
// The webhook is failurePolicy=Fail to ensure the contract is honoured:
// if the mutator is unavailable, admission is blocked rather than
// allowing a Service to slip through with allocateLoadBalancerNodePorts
// unset (the kube-apiserver would then default it to true and waste a
// NodePort for every LB).
func SetupServiceLoadBalancerMutatingWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&corev1.Service{}).
		WithDefaulter(&ServiceLoadBalancerDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate--v1-service,mutating=true,failurePolicy=fail,sideEffects=None,groups="",resources=services,verbs=create;update,versions=v1,name=mservice-juneau-loutres-me.kb.io,admissionReviewVersions=v1

// ServiceLoadBalancerDefaulter mutates Juneau-class LoadBalancer
// Services so that Kubernetes does not allocate NodePorts for them.
// Foreign-class Services are passed through unchanged so coexistence
// with MetalLB / cloud-controller-manager remains intact.
type ServiceLoadBalancerDefaulter struct{}

var _ webhook.CustomDefaulter = &ServiceLoadBalancerDefaulter{}

// Default implements webhook.CustomDefaulter. The function is invoked
// for every Service create/update; it inspects spec.loadBalancerClass
// and only mutates objects that have opted in to Juneau's LB.
func (d *ServiceLoadBalancerDefaulter) Default(_ context.Context, obj runtime.Object) error {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return fmt.Errorf("expected a Service object but got %T", obj)
	}
	if !isJuneauLoadBalancerService(svc) {
		return nil
	}
	// Force allocateLoadBalancerNodePorts=false. Setting an existing
	// `true` to `false` is permitted because the field is mutable and
	// the user opted in to Juneau LB by setting our class.
	svc.Spec.AllocateLoadBalancerNodePorts = ptr.To(false)
	return nil
}

// isJuneauLoadBalancerService is duplicated from
// service_webhook.go's logical surface to keep this file
// self-contained. Kept as a small free function rather than a method
// on the validator so the mutating defaulter does not need to depend
// on the validator's reader.
func isJuneauLoadBalancerService(svc *corev1.Service) bool {
	if svc == nil {
		return false
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return false
	}
	if svc.Spec.LoadBalancerClass == nil {
		return false
	}
	return *svc.Spec.LoadBalancerClass == juneauv1alpha1.ServiceLoadBalancerClass
}
