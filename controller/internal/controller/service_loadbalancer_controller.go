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
	stderrors "errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	// serviceLoadBalancerFinalizer scopes the finalizer to the LB
	// controller; Service is a core type owned by the user, so the
	// finalizer must be unambiguously attributable.
	serviceLoadBalancerFinalizer = "loadbalancer.juneau.loutres.me/allocation-claim"

	// Status condition vocabulary. corev1.Service has Status.Conditions
	// since 1.29; we surface a single "LoadBalancerReady" condition
	// whose Reason narrows down why an LB is or is not provisioned.
	serviceLoadBalancerConditionReady = "LoadBalancerReady"

	serviceLoadBalancerReasonAllocated          = "Allocated"
	serviceLoadBalancerReasonAllocating         = "Allocating"
	serviceLoadBalancerReasonNoAddressAvailable = "NoAddressAvailable"
	serviceLoadBalancerReasonMissingDependency  = "MissingDependency"
	serviceLoadBalancerReasonInvalidAddressPool = "InvalidAddressPool"

	serviceLoadBalancerRequeueAfter = 10 * time.Second

	// allocation Attribute is opaque to the AllocationClaim controller
	// but participates in claim name uniqueness, so the value is part
	// of our compatibility contract.
	serviceLoadBalancerAllocationAttribute = "status.loadBalancer.ingress[0].ip"
)

// ServiceLoadBalancerReconciler manages Kubernetes Services whose
// spec.loadBalancerClass selects this controller. It allocates an
// IPv4 from the configured ExternalNetwork via an AllocationClaim,
// mirrors the result onto Service.status.loadBalancer.ingress, and
// keeps Status.Conditions synchronized with the allocation state.
//
// Foreign-class or non-LoadBalancer Services are ignored end-to-end:
// no claim is created, no status is mutated, and no finalizer is
// installed. The "ignored" path is critical for coexistence with
// MetalLB, cloud-controller-manager, and other LB implementers.
type ServiceLoadBalancerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=services/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=services/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworks,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete

// Reconcile implements the LoadBalancer Service control loop. The flow
// is intentionally short-circuited at the very top so foreign Services
// take a constant-time decision: opt-in is determined entirely by
// (spec.type, spec.loadBalancerClass) without touching any other
// state.
func (r *ServiceLoadBalancerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Service", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !isJuneauLoadBalancerService(&svc) {
		// Even on the deletion path we leave foreign Services alone:
		// our finalizer is never installed on them.
		return ctrl.Result{}, nil
	}

	if !svc.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.handleDeletion(ctx, &svc)
	}

	if !controllerutil.ContainsFinalizer(&svc, serviceLoadBalancerFinalizer) {
		controllerutil.AddFinalizer(&svc, serviceLoadBalancerFinalizer)
		if err := r.Update(ctx, &svc); err != nil {
			return ctrl.Result{}, err
		}
		// Re-fetch so we observe our own finalizer write before mutating
		// status; otherwise the next Update may race the cache.
		if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	return r.reconcileNormal(ctx, &svc)
}

func (r *ServiceLoadBalancerReconciler) reconcileNormal(ctx context.Context, svc *corev1.Service) (ctrl.Result, error) {
	externalNetwork := strings.TrimSpace(svc.Annotations[juneauv1alpha1.ServiceAnnotationLBExternalNetwork])

	pools, err := ResolveExternalNetworkBGPPools(ctx, r.Client, externalNetwork)
	if err != nil {
		var resolveErr *ExternalNetworkResolveError
		if stderrors.As(err, &resolveErr) {
			return ctrl.Result{}, r.markFailed(ctx, svc, resolveErr.Reason, resolveErr.Message)
		}
		return ctrl.Result{}, err
	}

	address, requeue, err := r.ensureClaim(ctx, svc, pools)
	if err != nil {
		return ctrl.Result{}, err
	}

	if requeue {
		// Pool exhaustion: keep the user's previously allocated IP (if
		// any) intact rather than yanking it on a transient pressure
		// event. NoAddressAvailable surfaces the cause so users know to
		// expand the pool.
		if err := r.updateStatus(ctx, svc, svc.Status.LoadBalancer.Ingress, metav1.Condition{
			Type:    serviceLoadBalancerConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  serviceLoadBalancerReasonNoAddressAvailable,
			Message: "no available address in referenced AddressPools",
		}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: serviceLoadBalancerRequeueAfter}, nil
	}

	if address == "" {
		// Claim exists but is still allocating; surface that as a
		// transient pending state rather than dropping the previous IP.
		if err := r.updateStatus(ctx, svc, svc.Status.LoadBalancer.Ingress, metav1.Condition{
			Type:    serviceLoadBalancerConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  serviceLoadBalancerReasonAllocating,
			Message: "AllocationClaim is still allocating an address",
		}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	ingress := []corev1.LoadBalancerIngress{{
		IP:     address,
		IPMode: ptr.To(corev1.LoadBalancerIPModeVIP),
	}}
	if err := r.updateStatus(ctx, svc, ingress, metav1.Condition{
		Type:    serviceLoadBalancerConditionReady,
		Status:  metav1.ConditionTrue,
		Reason:  serviceLoadBalancerReasonAllocated,
		Message: fmt.Sprintf("LoadBalancer ingress allocated: %s", address),
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *ServiceLoadBalancerReconciler) handleDeletion(ctx context.Context, svc *corev1.Service) error {
	if !controllerutil.ContainsFinalizer(svc, serviceLoadBalancerFinalizer) {
		return nil
	}

	claimName := serviceLoadBalancerClaimName(svc)
	var claim juneauv1alpha1.AllocationClaim
	switch err := r.Get(ctx, client.ObjectKey{Name: claimName}, &claim); {
	case err == nil:
		if err := r.Delete(ctx, &claim); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	case apierrors.IsNotFound(err):
		// already collected
	default:
		return err
	}

	controllerutil.RemoveFinalizer(svc, serviceLoadBalancerFinalizer)
	return r.Update(ctx, svc)
}

func (r *ServiceLoadBalancerReconciler) ensureClaim(ctx context.Context, svc *corev1.Service, poolNames []string) (string, bool, error) {
	claimName := serviceLoadBalancerClaimName(svc)
	poolRefs := make([]juneauv1alpha1.AllocationPoolReference, 0, len(poolNames))
	for _, name := range poolNames {
		poolRefs = append(poolRefs, juneauv1alpha1.AllocationPoolReference{Name: name})
	}

	desiredSpec := juneauv1alpha1.AllocationClaimSpec{
		PoolRefs: poolRefs,
		ResourceRef: juneauv1alpha1.AllocationResourceReference{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "Service",
			Namespace:  svc.Namespace,
			Name:       svc.Name,
		},
		Attribute: serviceLoadBalancerAllocationAttribute,
	}
	if requested := strings.TrimSpace(svc.Annotations[juneauv1alpha1.ServiceAnnotationLBRequestedIP]); requested != "" {
		ip := requested
		desiredSpec.RequestedIP = &ip
	}

	var existing juneauv1alpha1.AllocationClaim
	err := r.Get(ctx, client.ObjectKey{Name: claimName}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		claim := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: claimName},
			Spec:       desiredSpec,
		}
		if err := r.Create(ctx, claim); err != nil && !apierrors.IsAlreadyExists(err) {
			return "", false, fmt.Errorf("create AllocationClaim: %w", err)
		}
		return "", false, nil
	case err != nil:
		return "", false, err
	}

	switch existing.Status.Phase {
	case juneauv1alpha1.AllocationClaimPhasePending:
		ready := meta.FindStatusCondition(existing.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady)
		if ready != nil && ready.Reason == allocationClaimReasonPending {
			return "", true, nil
		}
		return "", false, nil
	case juneauv1alpha1.AllocationClaimPhaseAllocated:
		if existing.Status.Value.IP == "" {
			return "", false, nil
		}
		return existing.Status.Value.IP, false, nil
	default:
		return "", false, nil
	}
}

func (r *ServiceLoadBalancerReconciler) markFailed(ctx context.Context, svc *corev1.Service, reason, message string) error {
	// Configuration failures (missing ExternalNetwork, non-BGP pool)
	// clear the previously announced ingress because the pool the
	// address came from may no longer be valid.
	return r.updateStatus(ctx, svc, nil, metav1.Condition{
		Type:    serviceLoadBalancerConditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
}

func (r *ServiceLoadBalancerReconciler) updateStatus(ctx context.Context, svc *corev1.Service, ingress []corev1.LoadBalancerIngress, condition metav1.Condition) error {
	updated := svc.DeepCopy()
	updated.Status.LoadBalancer.Ingress = ingress
	condition.ObservedGeneration = svc.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, condition)

	if reflect.DeepEqual(svc.Status, updated.Status) {
		return nil
	}

	svc.Status = updated.Status
	return r.Status().Update(ctx, svc)
}

// serviceLoadBalancerClaimName composes the deterministic claim name
// that backs an LB Service's ingress IP. Exported lower-case so tests
// in the same package can address the resource by name without
// duplicating the recipe.
func serviceLoadBalancerClaimName(svc *corev1.Service) string {
	return allocationClaimName(
		"loadbalancer",
		schema.GroupVersionKind{Group: corev1.GroupName, Version: "v1", Kind: "Service"},
		svc.Namespace,
		svc.Name,
		serviceLoadBalancerAllocationAttribute,
	)
}

// SetupWithManager wires the LB reconciler into the manager. Services
// without the Juneau loadBalancerClass are filtered out at the source
// so that the reconcile queue is not flooded by unrelated Service
// churn (every cluster has many ClusterIPs); the Reconcile method
// itself also re-checks the predicate as a defensive measure.
func (r *ServiceLoadBalancerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	servicePredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			svc, ok := e.Object.(*corev1.Service)
			return ok && isJuneauLoadBalancerService(svc)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSvc, ok := e.ObjectOld.(*corev1.Service)
			if !ok {
				return false
			}
			newSvc, ok := e.ObjectNew.(*corev1.Service)
			if !ok {
				return false
			}
			// Stay subscribed across class transitions so we can clean
			// up on the way out: if a Service had the Juneau class and
			// is being moved away, we still need to retire the claim.
			return isJuneauLoadBalancerService(newSvc) || isJuneauLoadBalancerService(oldSvc)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			svc, ok := e.Object.(*corev1.Service)
			return ok && isJuneauLoadBalancerService(svc)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			svc, ok := e.Object.(*corev1.Service)
			return ok && isJuneauLoadBalancerService(svc)
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("service-loadbalancer").
		For(&corev1.Service{}, builder.WithPredicates(servicePredicate)).
		Watches(
			&juneauv1alpha1.AllocationClaim{},
			handler.EnqueueRequestsFromMapFunc(r.mapAllocationClaimToService),
		).
		Watches(
			&juneauv1alpha1.ExternalNetwork{},
			handler.EnqueueRequestsFromMapFunc(r.mapExternalNetworkToServices),
		).
		Watches(
			&juneauv1alpha1.AddressPool{},
			handler.EnqueueRequestsFromMapFunc(r.mapAddressPoolToServices),
		).
		Complete(r)
}

// mapAllocationClaimToService routes an AllocationClaim event to the
// Service that owns it. Claims for non-Service kinds are filtered out
// so the LB reconciler is not woken up by ElasticIP / RouteTable churn.
func (r *ServiceLoadBalancerReconciler) mapAllocationClaimToService(_ context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
	if !ok {
		return nil
	}
	ref := claim.Spec.ResourceRef
	if ref.Kind != "Service" || ref.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}}}
}

// mapExternalNetworkToServices fans an ExternalNetwork change out to
// every Juneau-class LB Service whose annotation references it. We
// list across all namespaces because Services are namespaced but
// ExternalNetwork is cluster-scoped.
func (r *ServiceLoadBalancerReconciler) mapExternalNetworkToServices(ctx context.Context, obj client.Object) []reconcile.Request {
	extNet, ok := obj.(*juneauv1alpha1.ExternalNetwork)
	if !ok {
		return nil
	}
	return r.servicesReferencingExternalNetwork(ctx, extNet.Name)
}

// mapAddressPoolToServices fans an AddressPool change out via the
// ExternalNetwork(s) that include the pool. We re-list ExternalNetworks
// rather than caching to keep the controller stateless; the volume of
// ExternalNetwork resources in a Juneau cluster is small.
func (r *ServiceLoadBalancerReconciler) mapAddressPoolToServices(ctx context.Context, obj client.Object) []reconcile.Request {
	pool, ok := obj.(*juneauv1alpha1.AddressPool)
	if !ok {
		return nil
	}
	var extNets juneauv1alpha1.ExternalNetworkList
	if err := r.List(ctx, &extNets); err != nil {
		log.FromContext(ctx).Error(err, "list ExternalNetwork for AddressPool fan-out", "addressPool", pool.Name)
		return nil
	}
	seen := make(map[string]struct{})
	var requests []reconcile.Request
	for i := range extNets.Items {
		extNet := &extNets.Items[i]
		matches := false
		for _, refName := range extNet.Spec.AddressPools {
			if strings.TrimSpace(refName) == pool.Name {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		for _, req := range r.servicesReferencingExternalNetwork(ctx, extNet.Name) {
			key := req.String()
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			requests = append(requests, req)
		}
	}
	return requests
}

func (r *ServiceLoadBalancerReconciler) servicesReferencingExternalNetwork(ctx context.Context, externalNetworkName string) []reconcile.Request {
	var svcs corev1.ServiceList
	if err := r.List(ctx, &svcs); err != nil {
		log.FromContext(ctx).Error(err, "list Services for ExternalNetwork fan-out", "externalNetwork", externalNetworkName)
		return nil
	}
	var requests []reconcile.Request
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if !isJuneauLoadBalancerService(svc) {
			continue
		}
		if strings.TrimSpace(svc.Annotations[juneauv1alpha1.ServiceAnnotationLBExternalNetwork]) != externalNetworkName {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Namespace: svc.Namespace, Name: svc.Name}})
	}
	return requests
}

// isJuneauLoadBalancerService is the controller-side equivalent of
// svcpolicy.IsJuneauLoadBalancer; duplicated here so the controller
// package does not pull the daemon-internal svcpolicy into its imports
// (cross-module visibility forbids that anyway).
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
