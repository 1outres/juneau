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
	"reflect"
	"time"

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

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	natGatewayReasonReconcileSucceeded = "ReconcileSucceeded"
	natGatewayReasonReconcileFailed    = "ReconcileFailed"
	natGatewayReasonNotReady           = "NotReady"
	natGatewayReasonMissingDependency  = "MissingDependency"

	natGatewayRequeueAfter = 100 * time.Millisecond
)

// NATGatewayReconciler reconciles a NATGateway object.
//
// The reconciler allocates a cluster-wide GatewayID via an AllocationClaim
// against the nat-gateway-id pool. The ID is published in
// status.gatewayID and is used by the data plane to look up per-node
// NAPT source IPs (via napt_src map).
type NATGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=natgateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=natgateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=natgateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworks,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete

func (r *NATGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.NATGateway
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get NATGateway", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
		// AllocationClaim has the NATGateway as its OwnerRef, so it
		// will be GC'd by Kubernetes once the NATGateway disappears.
		return ctrl.Result{}, nil
	}

	var vpc juneauloutresmev1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, resource.Status.GatewayID, metav1.ConditionFalse, natGatewayReasonMissingDependency, fmt.Sprintf("Vpc %q not found", resource.Spec.Vpc)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var externalNetwork juneauloutresmev1alpha1.ExternalNetwork
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.ExternalNetwork}, &externalNetwork); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, resource.Status.GatewayID, metav1.ConditionFalse, natGatewayReasonMissingDependency, fmt.Sprintf("ExternalNetwork %q not found", resource.Spec.ExternalNetwork)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if externalNetwork.Spec.Type != juneauloutresmev1alpha1.ExternalNetworkTypeBGP {
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.GatewayID, metav1.ConditionFalse, natGatewayReasonMissingDependency, fmt.Sprintf("ExternalNetwork %q must have type=bgp", resource.Spec.ExternalNetwork)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	gatewayID := resource.Status.GatewayID
	if gatewayID == 0 {
		claim, err := r.ensureNumberClaim(ctx, &resource)
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, gatewayID, metav1.ConditionFalse, natGatewayReasonReconcileFailed, fmt.Sprintf("failed to ensure gateway ID allocation claim: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if claim.Status.Phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.Number == 0 {
			if err := r.updateStatus(ctx, &resource, gatewayID, metav1.ConditionFalse, natGatewayReasonNotReady, "waiting for gateway ID allocation"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: natGatewayRequeueAfter}, nil
		}
		if claim.Status.Value.Number > uint64(^uint32(0)) {
			if err := r.updateStatus(ctx, &resource, gatewayID, metav1.ConditionFalse, natGatewayReasonReconcileFailed, fmt.Sprintf("allocated gateway ID %d exceeds supported range", claim.Status.Value.Number)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		gatewayID = uint32(claim.Status.Value.Number)
	}

	if err := r.updateStatus(ctx, &resource, gatewayID, metav1.ConditionTrue, natGatewayReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *NATGatewayReconciler) ensureNumberClaim(ctx context.Context, resource *juneauloutresmev1alpha1.NATGateway) (*juneauloutresmev1alpha1.AllocationClaim, error) {
	gvk := schema.GroupVersionKind{
		Group:   juneauloutresmev1alpha1.GroupVersion.Group,
		Version: juneauloutresmev1alpha1.GroupVersion.Version,
		Kind:    "NATGateway",
	}
	claim := newAllocationClaim(allocationPoolNATGatewayID, gvk, "", resource.Name, "status.gatewayID")
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = newAllocationClaim(allocationPoolNATGatewayID, gvk, "", resource.Name, "status.gatewayID").Spec
		return controllerutil.SetControllerReference(resource, claim, r.Scheme)
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

func (r *NATGatewayReconciler) updateStatus(
	ctx context.Context,
	resource *juneauloutresmev1alpha1.NATGateway,
	gatewayID uint32,
	ready metav1.ConditionStatus,
	reason, message string,
) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.GatewayID = gatewayID
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauloutresmev1alpha1.NATGatewayStatusReady,
		Status:             ready,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if updated.Status.ObservedGeneration == resource.Status.ObservedGeneration &&
		updated.Status.GatewayID == resource.Status.GatewayID &&
		reflect.DeepEqual(updated.Status.Conditions, resource.Status.Conditions) {
		return nil
	}

	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *NATGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.NATGateway{}).
		Watches(&juneauloutresmev1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToNATGateways)).
		Watches(&juneauloutresmev1alpha1.ExternalNetwork{}, handler.EnqueueRequestsFromMapFunc(r.mapExternalNetworkToNATGateways)).
		Named("natgateway").
		Complete(r)
}

func (r *NATGatewayReconciler) mapClaimToNATGateways(_ context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*juneauloutresmev1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "NATGateway" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}

func (r *NATGatewayReconciler) mapExternalNetworkToNATGateways(ctx context.Context, obj client.Object) []reconcile.Request {
	externalNetwork, ok := obj.(*juneauloutresmev1alpha1.ExternalNetwork)
	if !ok {
		return nil
	}

	var natGatewayList juneauloutresmev1alpha1.NATGatewayList
	if err := r.List(ctx, &natGatewayList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0)
	for _, ng := range natGatewayList.Items {
		if ng.Spec.ExternalNetwork == externalNetwork.Name {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: ng.Name}})
		}
	}
	return requests
}
