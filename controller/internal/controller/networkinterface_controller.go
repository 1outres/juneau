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
	"net"
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

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	conditionReasonAllocationFailed    = "AllocationFailed"
	conditionReasonSubnetNotFound      = "SubnetNotFound"
	conditionReasonInvalidSubnetCIDR   = "InvalidSubnetCIDR"
	conditionReasonWaitingForIface     = "WaitingForInterface"
	conditionReasonAllocationSucceeded = "AllocationSucceeded"
	conditionReasonInvalidRequestedIP  = "InvalidRequestedIP"
	conditionReasonRequestedIPInUse    = "RequestedIPInUse"
	conditionReasonSubnetExhausted     = "SubnetExhausted"
	conditionReasonDeleting            = "Deleting"
	conditionReasonAllocating          = "Allocating"

	networkInterfaceFinalizer = "networkinterface.juneau.loutres.me/allocation-claim"

	// networkInterfaceReleaseAfter is the grace period applied to the
	// backing AllocationClaim. Matches the legacy IPLease behaviour so
	// that a pod deleted and re-created with the same name keeps its IP.
	networkInterfaceReleaseAfter = time.Hour
)

// NetworkInterfaceReconciler reconciles a NetworkInterface object.
//
// IP allocation is delegated to an AllocationClaim that targets the
// per-subnet AllocationPool maintained by the Subnet controller. The
// reconciler owns the lifecycle of that claim and mirrors its outcome
// into NetworkInterface.status.
type NetworkInterfaceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NetworkInterfaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.NetworkInterface
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get NetworkInterface", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.handleDeletion(ctx, &resource)
	}

	if !controllerutil.ContainsFinalizer(&resource, networkInterfaceFinalizer) {
		controllerutil.AddFinalizer(&resource, networkInterfaceFinalizer)
		if err := r.Update(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	subnet, err := r.fetchSubnet(ctx, &resource)
	if err != nil {
		return ctrl.Result{}, err
	}
	if subnet == nil {
		return ctrl.Result{Requeue: true}, nil
	}

	_, cidr, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		if updateErr := r.updateAllocationFailureStatus(ctx, &resource, conditionReasonInvalidSubnetCIDR, err.Error()); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	address, allocReason, allocMessage, err := r.ensureClaim(ctx, &resource, subnet)
	if err != nil {
		return ctrl.Result{}, err
	}
	if address == "" {
		// Claim is not yet Allocated. Surface the underlying reason so
		// users can distinguish "still allocating" from "exhausted".
		if updateErr := r.updateAllocationFailureStatus(ctx, &resource, allocReason, allocMessage); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	addressNet := &net.IPNet{IP: net.ParseIP(address), Mask: cidr.Mask}
	if err := r.updateAllocatedStatus(ctx, &resource, claimNameForNetworkInterface(&resource), addressNet, subnet.Status.Gateway); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NetworkInterfaceReconciler) handleDeletion(ctx context.Context, resource *juneauv1alpha1.NetworkInterface) error {
	if err := r.updateStatus(ctx, resource, juneauv1alpha1.NetworkInterfacePhasePending,
		metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:  metav1.ConditionFalse,
			Reason:  conditionReasonDeleting,
			Message: "NetworkInterface is being deleted",
		},
		metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
			Status:  metav1.ConditionFalse,
			Reason:  conditionReasonDeleting,
			Message: "NetworkInterface is being deleted",
		},
	); err != nil {
		return err
	}

	if !controllerutil.ContainsFinalizer(resource, networkInterfaceFinalizer) {
		return nil
	}

	claimName := claimNameForNetworkInterface(resource)
	var claim juneauv1alpha1.AllocationClaim
	if err := r.Get(ctx, client.ObjectKey{Name: claimName}, &claim); err == nil {
		if err := r.Delete(ctx, &claim); err != nil && !errors.IsNotFound(err) {
			return err
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	controllerutil.RemoveFinalizer(resource, networkInterfaceFinalizer)
	return r.Update(ctx, resource)
}

func (r *NetworkInterfaceReconciler) fetchSubnet(ctx context.Context, resource *juneauv1alpha1.NetworkInterface) (*juneauv1alpha1.Subnet, error) {
	var subnet juneauv1alpha1.Subnet
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Subnet}, &subnet); err != nil {
		if errors.IsNotFound(err) {
			if err := r.updateStatus(ctx, resource, juneauv1alpha1.NetworkInterfacePhasePending,
				metav1.Condition{
					Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
					Status:  metav1.ConditionFalse,
					Reason:  conditionReasonAllocationFailed,
					Message: "Failed to allocate IP",
				},
				metav1.Condition{
					Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
					Status:  metav1.ConditionFalse,
					Reason:  conditionReasonSubnetNotFound,
					Message: err.Error(),
				},
			); err != nil {
				return nil, err
			}
			return nil, nil
		}

		_ = r.updateAllocationFailureStatus(ctx, resource, conditionReasonSubnetNotFound, err.Error())
		return nil, err
	}

	return &subnet, nil
}

// ensureClaim creates or updates the AllocationClaim that backs this
// NetworkInterface's IP. Returns the resolved address (empty when the
// claim is still pending) plus a reason/message pair to surface the
// current state on the NetworkInterface.
func (r *NetworkInterfaceReconciler) ensureClaim(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, subnet *juneauv1alpha1.Subnet) (string, string, string, error) {
	claimName := claimNameForNetworkInterface(resource)

	desiredSpec := juneauv1alpha1.AllocationClaimSpec{
		PoolRefs: []juneauv1alpha1.AllocationPoolReference{
			{Name: SubnetIPAllocationPoolName(subnet.Name)},
		},
		ResourceRef: juneauv1alpha1.AllocationResourceReference{
			APIVersion: juneauv1alpha1.GroupVersion.String(),
			Kind:       "NetworkInterface",
			Namespace:  resource.Namespace,
			Name:       resource.Name,
		},
		Attribute:    "status.address",
		ReleaseAfter: &metav1.Duration{Duration: networkInterfaceReleaseAfter},
	}
	if resource.Spec.Address != "" {
		ip := resource.Spec.Address
		desiredSpec.RequestedIP = &ip
	}

	var existing juneauv1alpha1.AllocationClaim
	getErr := r.Get(ctx, client.ObjectKey{Name: claimName}, &existing)
	switch {
	case errors.IsNotFound(getErr):
		claim := &juneauv1alpha1.AllocationClaim{
			ObjectMeta: metav1.ObjectMeta{Name: claimName},
			Spec:       desiredSpec,
		}
		if err := r.Create(ctx, claim); err != nil && !errors.IsAlreadyExists(err) {
			return "", conditionReasonAllocationFailed, fmt.Sprintf("create AllocationClaim: %v", err), err
		}
		return "", conditionReasonAllocating, "AllocationClaim is being created", nil
	case getErr != nil:
		return "", conditionReasonAllocationFailed, getErr.Error(), getErr
	}

	if existing.Status.Phase == juneauv1alpha1.AllocationClaimPhaseAllocated && existing.Status.Value.IP != "" {
		return existing.Status.Value.IP, "", "", nil
	}

	// Surface a more specific reason from the underlying claim when it
	// indicates exhaustion or an invalid requested IP.
	ready := meta.FindStatusCondition(existing.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady)
	switch {
	case ready == nil:
		return "", conditionReasonAllocating, "AllocationClaim has no Ready condition yet", nil
	case ready.Reason == allocationClaimReasonPending:
		return "", conditionReasonSubnetExhausted, ready.Message, nil
	case ready.Reason == allocationClaimReasonFailed:
		return "", conditionReasonAllocationFailed, ready.Message, nil
	}
	return "", conditionReasonAllocating, "Waiting for AllocationClaim to be allocated", nil
}

// claimNameForNetworkInterface composes the deterministic AllocationClaim
// name for a NetworkInterface. Reusing the helper keeps name generation
// consistent with other consumers (vpc, subnet, route table, elastic IP).
func claimNameForNetworkInterface(resource *juneauv1alpha1.NetworkInterface) string {
	return allocationClaimName(
		SubnetIPAllocationPoolName(resource.Spec.Subnet),
		schema.GroupVersionKind{Group: juneauv1alpha1.GroupVersion.Group, Version: juneauv1alpha1.GroupVersion.Version, Kind: "NetworkInterface"},
		resource.Namespace,
		resource.Name,
		"status.address",
	)
}

func (r *NetworkInterfaceReconciler) updateAllocatedStatus(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, claimName string, address *net.IPNet, gateway string) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.AllocationClaim = claimName
	updated.Status.Address = address.String()
	updated.Status.Routes = buildDefaultRoutes(gateway)
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.NetworkInterfaceStatusAllocated,
		Status:             metav1.ConditionTrue,
		Reason:             conditionReasonAllocationSucceeded,
		Message:            "IP allocated successfully: " + address.String(),
		ObservedGeneration: updated.Generation,
	})

	var nwepList juneauv1alpha1.NetworkEndpointList
	if err := r.List(ctx, &nwepList, client.InNamespace(resource.Namespace)); err != nil {
		_ = r.updateStatus(ctx, resource, juneauv1alpha1.NetworkInterfacePhaseAllocated,
			metav1.Condition{
				Type:               juneauv1alpha1.NetworkInterfaceStatusAllocated,
				Status:             metav1.ConditionTrue,
				Reason:             conditionReasonAllocationSucceeded,
				Message:            "IP allocated successfully: " + address.String(),
				ObservedGeneration: resource.Generation,
			},
			metav1.Condition{
				Type:               juneauv1alpha1.NetworkInterfaceStatusReady,
				Status:             metav1.ConditionFalse,
				Reason:             conditionReasonAllocationFailed,
				Message:            err.Error(),
				ObservedGeneration: resource.Generation,
			},
		)
		return err
	}

	hasMatchingEndpoint := false
	for _, ep := range nwepList.Items {
		if ep.Spec.PodRef == nil {
			continue
		}
		if ep.Spec.PodRef.Interface == resource.Spec.PodRef.Interface &&
			ep.Spec.PodRef.Name == resource.Spec.PodRef.Name &&
			ep.Spec.PodRef.UID == resource.Spec.PodRef.UID {
			hasMatchingEndpoint = true
			break
		}
	}
	if hasMatchingEndpoint {
		updated.Status.Phase = juneauv1alpha1.NetworkInterfacePhaseReady
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:             metav1.ConditionTrue,
			Reason:             conditionReasonWaitingForIface,
			Message:            "Interface is ready",
			ObservedGeneration: updated.Generation,
		})
	} else {
		updated.Status.Phase = juneauv1alpha1.NetworkInterfacePhaseAllocated
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:             metav1.ConditionFalse,
			Reason:             conditionReasonWaitingForIface,
			Message:            "Waiting for interface",
			ObservedGeneration: updated.Generation,
		})
	}

	return r.commitStatus(ctx, resource, updated.Status)
}

func buildDefaultRoutes(gateway string) []juneauv1alpha1.NetworkRoute {
	if gateway == "" {
		return nil
	}
	return []juneauv1alpha1.NetworkRoute{
		{
			Dst: "0.0.0.0/0",
			GW:  gateway,
		},
	}
}

func (r *NetworkInterfaceReconciler) updateStatus(
	ctx context.Context,
	resource *juneauv1alpha1.NetworkInterface,
	phase juneauv1alpha1.NetworkInterfacePhase,
	conditions ...metav1.Condition,
) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.Phase = phase
	for _, condition := range conditions {
		condition.ObservedGeneration = updated.Generation
		meta.SetStatusCondition(&updated.Status.Conditions, condition)
	}
	return r.commitStatus(ctx, resource, updated.Status)
}

func (r *NetworkInterfaceReconciler) updateAllocationFailureStatus(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, allocatedReason, allocatedMessage string) error {
	return r.updateStatus(ctx, resource, juneauv1alpha1.NetworkInterfacePhaseFailed,
		metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusReady,
			Status:  metav1.ConditionFalse,
			Reason:  conditionReasonAllocationFailed,
			Message: "Failed to allocate IP",
		},
		metav1.Condition{
			Type:    juneauv1alpha1.NetworkInterfaceStatusAllocated,
			Status:  metav1.ConditionFalse,
			Reason:  allocatedReason,
			Message: allocatedMessage,
		},
	)
}

func (r *NetworkInterfaceReconciler) commitStatus(ctx context.Context, resource *juneauv1alpha1.NetworkInterface, status juneauv1alpha1.NetworkInterfaceStatus) error {
	if resource.Status.ObservedGeneration == status.ObservedGeneration &&
		resource.Status.Phase == status.Phase &&
		resource.Status.AllocationClaim == status.AllocationClaim &&
		resource.Status.Address == status.Address &&
		reflect.DeepEqual(resource.Status.Routes, status.Routes) &&
		reflect.DeepEqual(resource.Status.Conditions, status.Conditions) {
		return nil
	}

	resource.Status = status
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkInterfaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.NetworkInterface{}).
		Owns(&juneauv1alpha1.NetworkEndpoint{}).
		Watches(
			&juneauv1alpha1.AllocationClaim{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
				if !ok {
					return nil
				}
				ref := claim.Spec.ResourceRef
				if ref.Kind != "NetworkInterface" || ref.Name == "" {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name},
				}}
			}),
		).
		Named("networkinterface").
		Complete(r)
}
