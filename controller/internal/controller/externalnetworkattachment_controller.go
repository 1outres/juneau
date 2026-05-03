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
	externalNetworkAttachmentConditionReady = "Ready"

	externalNetworkAttachmentReasonReady             = "Ready"
	externalNetworkAttachmentReasonAllocating        = "Allocating"
	externalNetworkAttachmentReasonNoAddress         = "NoAddressAvailable"
	externalNetworkAttachmentReasonMissingDependency = "MissingDependency"
	externalNetworkAttachmentReasonReconcileFailed   = "ReconcileFailed"
	externalNetworkAttachmentReasonInvalidPool       = "InvalidAddressPool"

	externalNetworkAttachmentRequeueAfter = 10 * time.Second
)

// ExternalNetworkAttachmentReconciler reconciles an ExternalNetworkAttachment.
//
// The reconciler allocates a per-(ExternalNetwork, Node) IP via an
// AllocationClaim against the AddressPools attached to the referenced
// ExternalNetwork. The IP is published in status.assignedIP and
// referenced by the daemon's NAPT reconciler. A per-node /32
// BGPAdvertisement is also installed so the assigned IP is announced
// only by the owning node's bgp-speaker.
type ExternalNetworkAttachmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworkattachments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworkattachments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworkattachments/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworks,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=bgpadvertisements,verbs=get;list;watch;create;update;patch;delete

func (r *ExternalNetworkAttachmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.ExternalNetworkAttachment
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get ExternalNetworkAttachment", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		// AllocationClaim and BGPAdvertisement are owned by the
		// ExternalNetworkAttachment; both are GC'd by Kubernetes
		// when the attachment is deleted.
		return ctrl.Result{}, nil
	}

	poolNames, err := r.resolvePoolNames(ctx, &resource)
	if err != nil {
		var reconcileErr *externalNetworkAttachmentReconcileError
		if stderrors.As(err, &reconcileErr) {
			if updateErr := r.updateErrorStatus(ctx, &resource, reconcileErr.reason, reconcileErr.message); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	address, requeue, err := r.ensureClaim(ctx, &resource, poolNames)
	if err != nil {
		return ctrl.Result{}, err
	}

	if requeue {
		if err := r.updatePendingStatus(ctx, &resource, "", externalNetworkAttachmentReasonNoAddress, "no available address in referenced AddressPools"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: externalNetworkAttachmentRequeueAfter}, nil
	}

	if address == "" {
		if err := r.updatePendingStatus(ctx, &resource, "", externalNetworkAttachmentReasonAllocating, "AllocationClaim is still allocating an address"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.ensureBGPAdvertisement(ctx, &resource, address); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.updateReadyStatus(ctx, &resource, address); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

type externalNetworkAttachmentReconcileError struct {
	reason  string
	message string
}

func (e *externalNetworkAttachmentReconcileError) Error() string {
	return e.message
}

func (r *ExternalNetworkAttachmentReconciler) resolvePoolNames(ctx context.Context, resource *juneauloutresmev1alpha1.ExternalNetworkAttachment) ([]string, error) {
	if strings.TrimSpace(resource.Spec.ExternalNetwork) == "" {
		return nil, &externalNetworkAttachmentReconcileError{
			reason:  externalNetworkAttachmentReasonMissingDependency,
			message: "spec.externalNetwork is empty",
		}
	}

	var externalNetwork juneauloutresmev1alpha1.ExternalNetwork
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.ExternalNetwork}, &externalNetwork); err != nil {
		if errors.IsNotFound(err) {
			return nil, &externalNetworkAttachmentReconcileError{
				reason:  externalNetworkAttachmentReasonMissingDependency,
				message: fmt.Sprintf("ExternalNetwork %q not found", resource.Spec.ExternalNetwork),
			}
		}
		return nil, err
	}

	if len(externalNetwork.Spec.AddressPools) == 0 {
		return nil, &externalNetworkAttachmentReconcileError{
			reason:  externalNetworkAttachmentReasonMissingDependency,
			message: fmt.Sprintf("ExternalNetwork %q has no AddressPools", externalNetwork.Name),
		}
	}

	poolNames := make([]string, 0, len(externalNetwork.Spec.AddressPools))
	for _, raw := range externalNetwork.Spec.AddressPools {
		poolName := strings.TrimSpace(raw)
		if poolName == "" {
			continue
		}

		var addressPool juneauloutresmev1alpha1.AddressPool
		if err := r.Get(ctx, client.ObjectKey{Name: poolName}, &addressPool); err != nil {
			if errors.IsNotFound(err) {
				return nil, &externalNetworkAttachmentReconcileError{
					reason:  externalNetworkAttachmentReasonMissingDependency,
					message: fmt.Sprintf("AddressPool %q not found", poolName),
				}
			}
			return nil, err
		}

		if addressPool.Spec.AdvertiseMode != juneauloutresmev1alpha1.AddressPoolAdvertiseModeBGP {
			return nil, &externalNetworkAttachmentReconcileError{
				reason:  externalNetworkAttachmentReasonInvalidPool,
				message: fmt.Sprintf("AddressPool %q advertiseMode must be bgp", addressPool.Name),
			}
		}

		poolNames = append(poolNames, AddressPoolAllocationPoolName(addressPool.Name))
	}

	if len(poolNames) == 0 {
		return nil, &externalNetworkAttachmentReconcileError{
			reason:  externalNetworkAttachmentReasonMissingDependency,
			message: fmt.Sprintf("ExternalNetwork %q resolves to no usable AddressPools", externalNetwork.Name),
		}
	}

	return poolNames, nil
}

func (r *ExternalNetworkAttachmentReconciler) ensureClaim(ctx context.Context, resource *juneauloutresmev1alpha1.ExternalNetworkAttachment, poolNames []string) (string, bool, error) {
	gvk := schema.GroupVersionKind{
		Group:   juneauloutresmev1alpha1.GroupVersion.Group,
		Version: juneauloutresmev1alpha1.GroupVersion.Version,
		Kind:    "ExternalNetworkAttachment",
	}
	claimName := allocationClaimName(poolNames[0], gvk, "", resource.Name, "status.assignedIP")

	poolRefs := make([]juneauloutresmev1alpha1.AllocationPoolReference, 0, len(poolNames))
	for _, name := range poolNames {
		poolRefs = append(poolRefs, juneauloutresmev1alpha1.AllocationPoolReference{Name: name})
	}

	desiredSpec := juneauloutresmev1alpha1.AllocationClaimSpec{
		PoolRefs: poolRefs,
		ResourceRef: juneauloutresmev1alpha1.AllocationResourceReference{
			APIVersion: juneauloutresmev1alpha1.GroupVersion.String(),
			Kind:       gvk.Kind,
			Namespace:  resource.Namespace,
			Name:       resource.Name,
		},
		Attribute: "status.assignedIP",
	}

	claim := &juneauloutresmev1alpha1.AllocationClaim{
		ObjectMeta: metav1.ObjectMeta{Name: claimName},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = desiredSpec
		return controllerutil.SetControllerReference(resource, claim, r.Scheme)
	})
	if err != nil {
		return "", false, fmt.Errorf("ensure AllocationClaim: %w", err)
	}

	if claim.Status.Phase == juneauloutresmev1alpha1.AllocationClaimPhasePending {
		ready := meta.FindStatusCondition(claim.Status.Conditions, juneauloutresmev1alpha1.AllocationClaimStatusReady)
		if ready != nil && ready.Reason == allocationClaimReasonPending {
			return "", true, nil
		}
		return "", false, nil
	}

	if claim.Status.Phase == juneauloutresmev1alpha1.AllocationClaimPhaseAllocated && claim.Status.Value.IP != "" {
		return claim.Status.Value.IP, false, nil
	}

	return "", false, nil
}

func (r *ExternalNetworkAttachmentReconciler) ensureBGPAdvertisement(ctx context.Context, resource *juneauloutresmev1alpha1.ExternalNetworkAttachment, address string) error {
	advName := externalNetworkAttachmentBGPAdvertisementName(resource)

	var externalNetwork juneauloutresmev1alpha1.ExternalNetwork
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.ExternalNetwork}, &externalNetwork); err != nil {
		return err
	}

	pools := make([]string, 0, len(externalNetwork.Spec.AddressPools))
	for _, p := range externalNetwork.Spec.AddressPools {
		p = strings.TrimSpace(p)
		if p != "" {
			pools = append(pools, p)
		}
	}

	adv := &juneauloutresmev1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: advName},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, adv, func() error {
		adv.Spec.AddressPools = pools
		adv.Spec.NodeName = resource.Spec.NodeName
		adv.Spec.Prefix = fmt.Sprintf("%s/32", address)
		return controllerutil.SetControllerReference(resource, adv, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("ensure BGPAdvertisement: %w", err)
	}
	return nil
}

func externalNetworkAttachmentBGPAdvertisementName(resource *juneauloutresmev1alpha1.ExternalNetworkAttachment) string {
	return fmt.Sprintf("ena-%s", resource.Name)
}

func (r *ExternalNetworkAttachmentReconciler) updatePendingStatus(ctx context.Context, resource *juneauloutresmev1alpha1.ExternalNetworkAttachment, address, reason, message string) error {
	return r.updateStatus(ctx, resource, address, metav1.Condition{
		Type:    externalNetworkAttachmentConditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
}

func (r *ExternalNetworkAttachmentReconciler) updateErrorStatus(ctx context.Context, resource *juneauloutresmev1alpha1.ExternalNetworkAttachment, reason, message string) error {
	return r.updateStatus(ctx, resource, resource.Status.AssignedIP, metav1.Condition{
		Type:    externalNetworkAttachmentConditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
}

func (r *ExternalNetworkAttachmentReconciler) updateReadyStatus(ctx context.Context, resource *juneauloutresmev1alpha1.ExternalNetworkAttachment, address string) error {
	return r.updateStatus(ctx, resource, address, metav1.Condition{
		Type:    externalNetworkAttachmentConditionReady,
		Status:  metav1.ConditionTrue,
		Reason:  externalNetworkAttachmentReasonReady,
		Message: fmt.Sprintf("ExternalNetworkAttachment ready, assignedIP=%s", address),
	})
}

func (r *ExternalNetworkAttachmentReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.ExternalNetworkAttachment, address string, condition metav1.Condition) error {
	updated := resource.Status
	updated.ObservedGeneration = resource.Generation
	updated.AssignedIP = address
	condition.ObservedGeneration = resource.Generation
	meta.SetStatusCondition(&updated.Conditions, condition)

	if reflect.DeepEqual(resource.Status, updated) {
		return nil
	}
	resource.Status = updated
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ExternalNetworkAttachmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.ExternalNetworkAttachment{}).
		Watches(&juneauloutresmev1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToAttachments)).
		Watches(&juneauloutresmev1alpha1.ExternalNetwork{}, handler.EnqueueRequestsFromMapFunc(r.mapExternalNetworkToAttachments)).
		Named("externalnetworkattachment").
		Complete(r)
}

func (r *ExternalNetworkAttachmentReconciler) mapClaimToAttachments(_ context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*juneauloutresmev1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "ExternalNetworkAttachment" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}

func (r *ExternalNetworkAttachmentReconciler) mapExternalNetworkToAttachments(ctx context.Context, obj client.Object) []reconcile.Request {
	externalNetwork, ok := obj.(*juneauloutresmev1alpha1.ExternalNetwork)
	if !ok {
		return nil
	}

	var attachmentList juneauloutresmev1alpha1.ExternalNetworkAttachmentList
	if err := r.List(ctx, &attachmentList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0)
	for i := range attachmentList.Items {
		if attachmentList.Items[i].Spec.ExternalNetwork == externalNetwork.Name {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: attachmentList.Items[i].Name}})
		}
	}
	return requests
}
