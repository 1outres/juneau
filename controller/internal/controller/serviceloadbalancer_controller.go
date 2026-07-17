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
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	serviceLoadBalancerKind        = "ServiceLoadBalancer"
	serviceLoadBalancerClaimPrefix = "serviceloadbalancer"
	serviceLoadBalancerClaimAttr   = "status.vip"

	serviceLoadBalancerRequeueAfter = 10 * time.Second
)

// serviceLoadBalancerReconcileError carries a (reason, message) pair
// out of helpers that detect user-visible misconfigurations such as a
// missing ExternalNetwork. The Reconcile loop catches this type and
// surfaces it through Status conditions instead of returning an error
// (which would just re-queue immediately).
type serviceLoadBalancerReconcileError struct {
	reason  string
	message string
}

func (e *serviceLoadBalancerReconcileError) Error() string { return e.message }

// ServiceLoadBalancerReconciler owns the lifecycle of one
// ServiceLoadBalancer resource: VIP allocation through an
// AllocationClaim, status mirroring (vip, addressPool, ports), and
// patching the parent Service's status.loadBalancer.ingress with the
// allocated address.
//
// Advertising-node calculation lives in Phase 3 and is intentionally
// not implemented yet; the resource still tracks Allocated /
// Available conditions and a coarse Phase so consumers can observe
// readiness as the system evolves.
type ServiceLoadBalancerReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// APIReader bypasses the controller-runtime cache for the very
	// first read of the parent Service after we add the SLB owner
	// reference. The cache may not have observed the Service yet, so
	// a non-cached read avoids spurious "Service not found" errors
	// during creation races. Other reads use the cached client.
	APIReader client.Reader
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=serviceloadbalancers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=serviceloadbalancers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=serviceloadbalancers/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworks,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch

// Reconcile drives one ServiceLoadBalancer towards its desired
// state. Errors are returned only for transient conditions (API
// errors). User-visible misconfigurations are surfaced through
// Status conditions and the Phase field so the resource is
// observable even when reconciliation cannot make progress.
func (r *ServiceLoadBalancerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.ServiceLoadBalancer
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get ServiceLoadBalancer", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.handleDeletion(ctx, &resource)
	}

	if !controllerutil.ContainsFinalizer(&resource, juneauv1alpha1.ServiceLoadBalancerFinalizer) {
		controllerutil.AddFinalizer(&resource, juneauv1alpha1.ServiceLoadBalancerFinalizer)
		if err := r.Update(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
		// Re-read so the rest of the reconcile sees the finalizer and
		// the latest resourceVersion.
		if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	return r.reconcileNormal(ctx, &resource)
}

func (r *ServiceLoadBalancerReconciler) handleDeletion(ctx context.Context, resource *juneauv1alpha1.ServiceLoadBalancer) error {
	if !controllerutil.ContainsFinalizer(resource, juneauv1alpha1.ServiceLoadBalancerFinalizer) {
		return nil
	}

	claimName := serviceLoadBalancerClaimName(resource)
	var claim juneauv1alpha1.AllocationClaim
	switch err := r.Get(ctx, client.ObjectKey{Name: claimName}, &claim); {
	case err == nil:
		if err := r.Delete(ctx, &claim); err != nil && !errors.IsNotFound(err) {
			return err
		}
	case errors.IsNotFound(err):
		// already cleaned up
	default:
		return err
	}

	controllerutil.RemoveFinalizer(resource, juneauv1alpha1.ServiceLoadBalancerFinalizer)
	return r.Update(ctx, resource)
}

func (r *ServiceLoadBalancerReconciler) reconcileNormal(ctx context.Context, resource *juneauv1alpha1.ServiceLoadBalancer) (ctrl.Result, error) {
	svc, err := r.fetchParentService(ctx, resource)
	if err != nil {
		var reconcileErr *serviceLoadBalancerReconcileError
		if stderrors.As(err, &reconcileErr) {
			return r.commitErrorStatus(ctx, resource, reconcileErr.reason, reconcileErr.message)
		}
		return ctrl.Result{}, err
	}

	endpointAgg, err := r.collectEndpointAggregate(ctx, svc)
	if err != nil {
		return ctrl.Result{}, err
	}

	desired := buildDesiredStatus(resource, svc, endpointAgg)

	poolNames, err := r.resolvePoolRefs(ctx, resource)
	if err != nil {
		var reconcileErr *serviceLoadBalancerReconcileError
		if stderrors.As(err, &reconcileErr) {
			desired.Phase = juneauv1alpha1.ServiceLoadBalancerPhaseError
			meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
				Type:               juneauv1alpha1.ServiceLoadBalancerConditionAccepted,
				Status:             metav1.ConditionFalse,
				Reason:             reconcileErr.reason,
				Message:            reconcileErr.message,
				ObservedGeneration: resource.Generation,
			})
			meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
				Type:               juneauv1alpha1.ServiceLoadBalancerConditionAllocated,
				Status:             metav1.ConditionFalse,
				Reason:             reconcileErr.reason,
				Message:            reconcileErr.message,
				ObservedGeneration: resource.Generation,
			})
			return ctrl.Result{RequeueAfter: serviceLoadBalancerRequeueAfter}, r.commitStatus(ctx, resource, desired)
		}
		return ctrl.Result{}, err
	}

	address, addressPool, requeue, err := r.ensureClaim(ctx, resource, poolNames)
	if err != nil {
		return ctrl.Result{}, err
	}

	meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.ServiceLoadBalancerConditionAccepted,
		Status:             metav1.ConditionTrue,
		Reason:             juneauv1alpha1.ServiceLoadBalancerReasonReady,
		Message:            "Service configuration accepted",
		ObservedGeneration: resource.Generation,
	})

	switch {
	case requeue:
		desired.Phase = juneauv1alpha1.ServiceLoadBalancerPhasePending
		meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
			Type:               juneauv1alpha1.ServiceLoadBalancerConditionAllocated,
			Status:             metav1.ConditionFalse,
			Reason:             juneauv1alpha1.ServiceLoadBalancerReasonPoolExhausted,
			Message:            "no available address in referenced AddressPools",
			ObservedGeneration: resource.Generation,
		})
		if err := r.commitStatus(ctx, resource, desired); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: serviceLoadBalancerRequeueAfter}, nil

	case address == "":
		desired.Phase = juneauv1alpha1.ServiceLoadBalancerPhasePending
		meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
			Type:               juneauv1alpha1.ServiceLoadBalancerConditionAllocated,
			Status:             metav1.ConditionFalse,
			Reason:             juneauv1alpha1.ServiceLoadBalancerReasonAwaitingDataplane,
			Message:            "AllocationClaim is still allocating an address",
			ObservedGeneration: resource.Generation,
		})
		return ctrl.Result{}, r.commitStatus(ctx, resource, desired)
	}

	desired.VIP = address
	desired.AddressPool = addressPool
	desired.AllocationClaimName = serviceLoadBalancerClaimName(resource)
	meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.ServiceLoadBalancerConditionAllocated,
		Status:             metav1.ConditionTrue,
		Reason:             juneauv1alpha1.ServiceLoadBalancerReasonAllocated,
		Message:            fmt.Sprintf("VIP %s allocated from AddressPool %q", address, addressPool),
		ObservedGeneration: resource.Generation,
	})

	// Available reflects whether at least one node currently holds a
	// ready local backend. The condition is not just informational:
	// the BGP source (Phase 5) reads advertisingNodes to decide what
	// to advertise, so we make sure the data is consistent with the
	// condition we publish.
	if len(desired.AdvertisingNodes) > 0 {
		desired.Phase = juneauv1alpha1.ServiceLoadBalancerPhaseReady
		meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
			Type:               juneauv1alpha1.ServiceLoadBalancerConditionAvailable,
			Status:             metav1.ConditionTrue,
			Reason:             juneauv1alpha1.ServiceLoadBalancerReasonReady,
			Message:            fmt.Sprintf("%d node(s) advertising the VIP", len(desired.AdvertisingNodes)),
			ObservedGeneration: resource.Generation,
		})
	} else {
		desired.Phase = juneauv1alpha1.ServiceLoadBalancerPhaseDegraded
		meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
			Type:               juneauv1alpha1.ServiceLoadBalancerConditionAvailable,
			Status:             metav1.ConditionFalse,
			Reason:             juneauv1alpha1.ServiceLoadBalancerReasonNoReadyBackends,
			Message:            "no node currently has a ready local backend",
			ObservedGeneration: resource.Generation,
		})
	}

	if err := r.syncServiceStatus(ctx, svc, address); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.commitStatus(ctx, resource, desired); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// fetchParentService loads the Kubernetes Service that this
// ServiceLoadBalancer fronts. It double-checks that the Service is
// still in scope for Juneau (LoadBalancer + class match) so that
// out-of-scope transitions trigger a clean error status; the
// Service-driven sync controller is responsible for actually deleting
// the SLB in that case.
func (r *ServiceLoadBalancerReconciler) fetchParentService(ctx context.Context, resource *juneauv1alpha1.ServiceLoadBalancer) (*corev1.Service, error) {
	if strings.TrimSpace(resource.Spec.ServiceRef.Name) == "" {
		return nil, &serviceLoadBalancerReconcileError{
			reason:  juneauv1alpha1.ServiceLoadBalancerReasonInvalidConfig,
			message: "spec.serviceRef.name is empty",
		}
	}

	key := client.ObjectKey{Namespace: resource.Namespace, Name: resource.Spec.ServiceRef.Name}
	var svc corev1.Service
	reader := client.Reader(r.Client)
	if r.APIReader != nil {
		reader = r.APIReader
	}
	if err := reader.Get(ctx, key, &svc); err != nil {
		if errors.IsNotFound(err) {
			return nil, &serviceLoadBalancerReconcileError{
				reason:  juneauv1alpha1.ServiceLoadBalancerReasonInvalidConfig,
				message: fmt.Sprintf("Service %q not found", key),
			}
		}
		return nil, err
	}

	if !isJuneauManagedLoadBalancerService(&svc) {
		return nil, &serviceLoadBalancerReconcileError{
			reason:  juneauv1alpha1.ServiceLoadBalancerReasonInvalidConfig,
			message: fmt.Sprintf("Service %q is no longer a Juneau-managed LoadBalancer", key),
		}
	}

	return &svc, nil
}

// resolvePoolRefs walks ExternalNetwork → AddressPools and returns
// the AllocationPool names a claim should target. Only BGP-mode
// AddressPools are eligible at this phase; ARP-mode pools are
// reserved for future work.
func (r *ServiceLoadBalancerReconciler) resolvePoolRefs(ctx context.Context, resource *juneauv1alpha1.ServiceLoadBalancer) ([]poolRef, error) {
	if strings.TrimSpace(resource.Spec.ExternalNetwork) == "" {
		return nil, &serviceLoadBalancerReconcileError{
			reason:  juneauv1alpha1.ServiceLoadBalancerReasonInvalidConfig,
			message: "spec.externalNetwork is empty",
		}
	}

	var externalNetwork juneauv1alpha1.ExternalNetwork
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.ExternalNetwork}, &externalNetwork); err != nil {
		if errors.IsNotFound(err) {
			return nil, &serviceLoadBalancerReconcileError{
				reason:  juneauv1alpha1.ServiceLoadBalancerReasonExternalNetwork,
				message: fmt.Sprintf("ExternalNetwork %q not found", resource.Spec.ExternalNetwork),
			}
		}
		return nil, err
	}

	if len(externalNetwork.Spec.AddressPools) == 0 {
		return nil, &serviceLoadBalancerReconcileError{
			reason:  juneauv1alpha1.ServiceLoadBalancerReasonExternalNetwork,
			message: fmt.Sprintf("ExternalNetwork %q has no AddressPools", externalNetwork.Name),
		}
	}

	pools := make([]poolRef, 0, len(externalNetwork.Spec.AddressPools))
	for _, raw := range externalNetwork.Spec.AddressPools {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}

		var addressPool juneauv1alpha1.AddressPool
		if err := r.Get(ctx, client.ObjectKey{Name: name}, &addressPool); err != nil {
			if errors.IsNotFound(err) {
				return nil, &serviceLoadBalancerReconcileError{
					reason:  juneauv1alpha1.ServiceLoadBalancerReasonExternalNetwork,
					message: fmt.Sprintf("AddressPool %q not found", name),
				}
			}
			return nil, err
		}

		if addressPool.Spec.AdvertiseMode != juneauv1alpha1.AddressPoolAdvertiseModeBGP {
			return nil, &serviceLoadBalancerReconcileError{
				reason:  juneauv1alpha1.ServiceLoadBalancerReasonExternalNetwork,
				message: fmt.Sprintf("AddressPool %q advertiseMode must be bgp", addressPool.Name),
			}
		}

		pools = append(pools, poolRef{
			AddressPool:    addressPool.Name,
			AllocationPool: AddressPoolAllocationPoolName(addressPool.Name),
		})
	}

	if len(pools) == 0 {
		return nil, &serviceLoadBalancerReconcileError{
			reason:  juneauv1alpha1.ServiceLoadBalancerReasonExternalNetwork,
			message: fmt.Sprintf("ExternalNetwork %q resolves to no usable AddressPools", externalNetwork.Name),
		}
	}

	return pools, nil
}

// poolRef pairs an AddressPool name with its derived AllocationPool
// name so the reconciler can attribute the allocation back to the
// AddressPool when filling Status.AddressPool.
type poolRef struct {
	AddressPool    string
	AllocationPool string
}

// ensureClaim creates or reads the AllocationClaim that backs this
// ServiceLoadBalancer. Returns the allocated address (empty until
// the claim succeeds), the AddressPool the address belongs to, a
// requeue hint when the claim hit pool exhaustion, and any
// transient error.
func (r *ServiceLoadBalancerReconciler) ensureClaim(ctx context.Context, resource *juneauv1alpha1.ServiceLoadBalancer, pools []poolRef) (string, string, bool, error) {
	claimName := serviceLoadBalancerClaimName(resource)

	poolRefs := make([]juneauv1alpha1.AllocationPoolReference, 0, len(pools))
	for _, p := range pools {
		poolRefs = append(poolRefs, juneauv1alpha1.AllocationPoolReference{Name: p.AllocationPool})
	}

	desiredSpec := juneauv1alpha1.AllocationClaimSpec{
		PoolRefs: poolRefs,
		ResourceRef: juneauv1alpha1.AllocationResourceReference{
			APIVersion: juneauv1alpha1.GroupVersion.String(),
			Kind:       serviceLoadBalancerKind,
			Namespace:  resource.Namespace,
			Name:       resource.Name,
		},
		Attribute: serviceLoadBalancerClaimAttr,
	}
	if resource.Spec.RequestedIP != "" {
		ip := resource.Spec.RequestedIP
		desiredSpec.RequestedIP = &ip
	}

	var existing juneauv1alpha1.AllocationClaim
	err := r.Get(ctx, client.ObjectKey{Name: claimName}, &existing)
	switch {
	case errors.IsNotFound(err):
		claim := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: claimName},
			Spec:       desiredSpec,
		}
		if createErr := r.Create(ctx, claim); createErr != nil && !errors.IsAlreadyExists(createErr) {
			return "", "", false, fmt.Errorf("create AllocationClaim: %w", createErr)
		}
		return "", "", false, nil
	case err != nil:
		return "", "", false, err
	}

	if existing.Status.Phase == juneauv1alpha1.AllocationClaimPhasePending {
		ready := meta.FindStatusCondition(existing.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady)
		if ready != nil && ready.Reason == allocationClaimReasonPending {
			return "", "", true, nil
		}
		return "", "", false, nil
	}

	if existing.Status.Phase == juneauv1alpha1.AllocationClaimPhaseAllocated && existing.Status.Value.IP != "" {
		return existing.Status.Value.IP, addressPoolForClaim(&existing, pools), false, nil
	}

	return "", "", false, nil
}

// addressPoolForClaim attributes the allocation back to one of the
// pools the claim was offered. The AllocationClaim status records
// pool index implicitly via PoolRefs ordering, so when the claim is
// allocated we fall back to the first pool unless future status
// fields make this unambiguous.
//
// The result is informational; consumers that need authoritative
// pool membership must re-resolve against the AllocationPool API.
func addressPoolForClaim(claim *juneauv1alpha1.AllocationClaim, pools []poolRef) string {
	if claim == nil || len(pools) == 0 {
		return ""
	}
	for _, p := range pools {
		if claimReferencesPool(claim, p.AllocationPool) {
			return p.AddressPool
		}
	}
	return pools[0].AddressPool
}

// buildDesiredStatus copies the fields that depend on the parent
// Service and EndpointSlices into the next Status so we don't keep
// stale port/advertisingNodes state around. Conditions are seeded
// from the existing status and overwritten as the reconcile
// progresses.
func buildDesiredStatus(resource *juneauv1alpha1.ServiceLoadBalancer, svc *corev1.Service, agg endpointSlicesAggregate) juneauv1alpha1.ServiceLoadBalancerStatus {
	advertising := append([]string(nil), agg.AdvertisingNodes...)
	desired := juneauv1alpha1.ServiceLoadBalancerStatus{
		ObservedGeneration:  resource.Generation,
		Phase:               resource.Status.Phase,
		VIP:                 resource.Status.VIP,
		AddressPool:         resource.Status.AddressPool,
		Ports:               portsFromServiceWithEndpoints(svc, agg),
		AdvertisingNodes:    advertising,
		BackendSummary:      summariseBackends(agg),
		AllocationClaimName: resource.Status.AllocationClaimName,
		Conditions:          append([]metav1.Condition(nil), resource.Status.Conditions...),
	}
	return desired
}

// summariseBackends reduces the EndpointSlice aggregate to the
// per-Service BackendSummary surfaced in status.
func summariseBackends(agg endpointSlicesAggregate) juneauv1alpha1.ServiceLoadBalancerBackendSummary {
	return juneauv1alpha1.ServiceLoadBalancerBackendSummary{
		TotalReady:      agg.TotalReady,
		LocalReadyNodes: int32(len(agg.AdvertisingNodes)),
	}
}

// syncServiceStatus mirrors the allocated VIP into the parent
// Service's status.loadBalancer.ingress field. The patch is
// idempotent: if the field already matches, the function returns
// early so we don't churn the resourceVersion of every Service on
// every reconcile.
func (r *ServiceLoadBalancerReconciler) syncServiceStatus(ctx context.Context, svc *corev1.Service, vip string) error {
	if vip == "" {
		return nil
	}
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP == vip {
			return nil
		}
	}

	original := svc.DeepCopy()
	svc.Status.LoadBalancer = corev1.LoadBalancerStatus{
		Ingress: []corev1.LoadBalancerIngress{{IP: vip}},
	}
	return r.Status().Patch(ctx, svc, client.MergeFrom(original))
}

// commitStatus persists the desired status on the SLB resource. It
// no-ops when the status would not change, which keeps watches from
// firing on every reconcile.
func (r *ServiceLoadBalancerReconciler) commitStatus(ctx context.Context, resource *juneauv1alpha1.ServiceLoadBalancer, desired juneauv1alpha1.ServiceLoadBalancerStatus) error {
	if reflect.DeepEqual(resource.Status, desired) {
		return nil
	}
	resource.Status = desired
	return r.Status().Update(ctx, resource)
}

// commitErrorStatus is the short-form path for cases where we want
// to surface a configuration error and stop without further work.
func (r *ServiceLoadBalancerReconciler) commitErrorStatus(ctx context.Context, resource *juneauv1alpha1.ServiceLoadBalancer, reason, message string) (ctrl.Result, error) {
	desired := juneauv1alpha1.ServiceLoadBalancerStatus{
		ObservedGeneration:  resource.Generation,
		Phase:               juneauv1alpha1.ServiceLoadBalancerPhaseError,
		VIP:                 resource.Status.VIP,
		AddressPool:         resource.Status.AddressPool,
		Ports:               resource.Status.Ports,
		AdvertisingNodes:    append([]string(nil), resource.Status.AdvertisingNodes...),
		BackendSummary:      resource.Status.BackendSummary,
		AllocationClaimName: resource.Status.AllocationClaimName,
		Conditions:          append([]metav1.Condition(nil), resource.Status.Conditions...),
	}
	meta.SetStatusCondition(&desired.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.ServiceLoadBalancerConditionAccepted,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: resource.Generation,
	})
	return ctrl.Result{RequeueAfter: serviceLoadBalancerRequeueAfter}, r.commitStatus(ctx, resource, desired)
}

// serviceLoadBalancerClaimName returns a deterministic name for the
// AllocationClaim backing this SLB. Stable naming lets a re-created
// SLB inherit the same address (subject to lease) and lets
// kubectl-juneau correlate without a side index.
func serviceLoadBalancerClaimName(resource *juneauv1alpha1.ServiceLoadBalancer) string {
	return allocationClaimName(
		serviceLoadBalancerClaimPrefix,
		schema.GroupVersionKind{
			Group:   juneauv1alpha1.GroupVersion.Group,
			Version: juneauv1alpha1.GroupVersion.Version,
			Kind:    serviceLoadBalancerKind,
		},
		resource.Namespace,
		resource.Name,
		serviceLoadBalancerClaimAttr,
	)
}

// SetupWithManager sets up the reconciler. The SLB controller
// watches its own resource (For), AllocationClaims that name an SLB
// resource (so claim status lands here), and Services in the same
// namespace (so port/spec changes trigger re-reconcile and Service
// status patches stick).
func (r *ServiceLoadBalancerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.ServiceLoadBalancer{}).
		Watches(
			&juneauv1alpha1.AllocationClaim{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
				if !ok {
					return nil
				}
				ref := claim.Spec.ResourceRef
				if ref.Kind != serviceLoadBalancerKind || ref.Name == "" {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name},
				}}
			}),
		).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				svc, ok := obj.(*corev1.Service)
				if !ok {
					return nil
				}
				if !isJuneauManagedLoadBalancerService(svc) {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: client.ObjectKey{Namespace: svc.Namespace, Name: ServiceLoadBalancerNameForService(svc.Name)},
				}}
			}),
		).
		// EndpointSlice → SLB reconcile: the upstream
		// kubernetes.io/service-name label encodes the parent Service
		// name, which (by deterministic naming) is also the SLB name.
		Watches(
			&discoveryv1.EndpointSlice{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				slice, ok := obj.(*discoveryv1.EndpointSlice)
				if !ok {
					return nil
				}
				svcName := slice.Labels[kubernetesServiceLabel]
				if svcName == "" {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: client.ObjectKey{Namespace: slice.Namespace, Name: ServiceLoadBalancerNameForService(svcName)},
				}}
			}),
		).
		Named("serviceloadbalancer").
		Complete(r)
}
