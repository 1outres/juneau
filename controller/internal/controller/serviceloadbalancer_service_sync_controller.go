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

package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// ServiceLoadBalancerSyncReconciler watches Kubernetes Services and
// keeps a 1:1 mapping with ServiceLoadBalancer resources for those
// in scope for Juneau (type=LoadBalancer + Juneau loadBalancerClass).
//
// The split between this reconciler and ServiceLoadBalancerReconciler
// is deliberate: the sync reconciler is the single owner of "does an
// SLB exist for this Service" while the SLB reconciler is the single
// owner of "what does this SLB do once it exists." Mixing them would
// make it harder to reason about transitions like classless ↔ Juneau-
// class, and would force a single Reconcile to juggle Service
// lifecycle and VIP allocation simultaneously.
type ServiceLoadBalancerSyncReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=serviceloadbalancers,verbs=get;list;watch;create;update;patch;delete

// Reconcile creates, updates, or deletes the ServiceLoadBalancer
// that fronts a Kubernetes Service. The function is idempotent: it
// is safe to invoke for a Service that has never been Juneau-managed
// (no SLB will be created), for one that just transitioned out of
// scope (the SLB is deleted), and for ongoing reconciles (the SLB
// spec is patched if drifted).
func (r *ServiceLoadBalancerSyncReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		if errors.IsNotFound(err) {
			// Service is gone: garbage-collect any matching SLB. We
			// don't store the SLB name on the Service, but the SLB
			// name is deterministic from the Service name.
			return ctrl.Result{}, r.deleteSLBIfExists(ctx, req.Namespace, ServiceLoadBalancerNameForService(req.Name))
		}
		logger.Error(err, "unable to get Service", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	slbName := ServiceLoadBalancerNameForService(svc.Name)

	if !isJuneauManagedLoadBalancerService(&svc) {
		// Out of scope (or never was): make sure no stale SLB lingers.
		// Most Services will never have had one, in which case
		// deleteSLBIfExists is a cheap NotFound.
		return ctrl.Result{}, r.deleteSLBIfExists(ctx, svc.Namespace, slbName)
	}

	return ctrl.Result{}, r.ensureSLB(ctx, &svc, slbName)
}

// ensureSLB creates the ServiceLoadBalancer when missing or patches
// the spec when it has drifted from the Service annotations. The
// resource is owned by the Service so deletion of the Service GCs
// the SLB even if the Service-sync controller is offline.
func (r *ServiceLoadBalancerSyncReconciler) ensureSLB(ctx context.Context, svc *corev1.Service, slbName string) error {
	desired := desiredSLBSpecFromService(svc)

	slb := &juneauv1alpha1.ServiceLoadBalancer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      slbName,
			Namespace: svc.Namespace,
		},
	}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, slb, func() error {
		slb.Spec = desired
		// Owner reference + finalizer-on-Service is the safety net:
		// owner ref handles the common case (Service deletion → SLB
		// GC), and the SLB's own finalizer handles the AllocationClaim
		// release before the GC removes the SLB.
		return controllerutil.SetControllerReference(svc, slb, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("ensure ServiceLoadBalancer for service %s/%s: %w", svc.Namespace, svc.Name, err)
	}
	if op != controllerutil.OperationResultNone {
		log.FromContext(ctx).Info("ServiceLoadBalancer reconciled", "operation", op, "name", slbName, "namespace", svc.Namespace)
	}
	return nil
}

// deleteSLBIfExists best-effort deletes the SLB. The SLB's
// finalizer ensures the AllocationClaim is released before the
// resource disappears, so this function does not need to wait.
func (r *ServiceLoadBalancerSyncReconciler) deleteSLBIfExists(ctx context.Context, namespace, name string) error {
	slb := &juneauv1alpha1.ServiceLoadBalancer{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, slb); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if !slb.DeletionTimestamp.IsZero() {
		// Already being deleted; the SLB controller's finalizer will
		// finish the job.
		return nil
	}
	if err := r.Delete(ctx, slb); err != nil && !errors.IsNotFound(err) {
		return err
	}
	return nil
}

// desiredSLBSpecFromService is the canonical translation from
// Service annotations to ServiceLoadBalancerSpec. Centralising the
// translation here means the controller and webhook never disagree
// on what a given Service "means" as an SLB.
func desiredSLBSpecFromService(svc *corev1.Service) juneauv1alpha1.ServiceLoadBalancerSpec {
	return juneauv1alpha1.ServiceLoadBalancerSpec{
		ServiceRef: juneauv1alpha1.ServiceLoadBalancerServiceReference{
			Name: svc.Name,
		},
		ExternalNetwork: svc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork],
		RequestedIP:     svc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerRequestedIP],
	}
}

// isJuneauManagedLoadBalancerService is the controller-side mirror
// of webhook.IsJuneauManagedLoadBalancer. We deliberately re-derive
// it here so the controller package does not need a runtime
// dependency on the webhook package.
func isJuneauManagedLoadBalancerService(svc *corev1.Service) bool {
	if svc == nil {
		return false
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return false
	}
	if svc.Spec.LoadBalancerClass == nil {
		return false
	}
	return *svc.Spec.LoadBalancerClass == juneauv1alpha1.LoadBalancerClass
}

// ServiceLoadBalancerNameForService returns the deterministic SLB
// resource name for a given Service. Using the Service name verbatim
// keeps debugging trivial; namespace isolation is provided by the
// SLB being namespaced.
func ServiceLoadBalancerNameForService(serviceName string) string {
	return serviceName
}

// SetupWithManager registers the reconciler. We watch Services and
// also watch SLBs so that an out-of-band SLB deletion (or a manually
// created SLB whose Service was already gone) gets reconciled
// against the current Service set.
func (r *ServiceLoadBalancerSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Watches(
			&juneauv1alpha1.ServiceLoadBalancer{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				slb, ok := obj.(*juneauv1alpha1.ServiceLoadBalancer)
				if !ok {
					return nil
				}
				if slb.Spec.ServiceRef.Name == "" {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: client.ObjectKey{Namespace: slb.Namespace, Name: slb.Spec.ServiceRef.Name},
				}}
			}),
		).
		Named("serviceloadbalancer-sync").
		Complete(r)
}
