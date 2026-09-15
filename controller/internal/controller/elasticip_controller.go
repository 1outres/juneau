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

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	elasticIPConditionAllocated = "Allocated"
	elasticIPConditionAttached  = "Attached"

	elasticIPReasonReconcileSucceeded = "ReconcileSucceeded"
	elasticIPReasonAwaitingAttachment = "AwaitingAttachment"
	elasticIPReasonNoAddressAvailable = "NoAddressAvailable"
	elasticIPReasonMissingDependency  = "MissingDependency"
	elasticIPReasonInvalidAddressPool = "InvalidAddressPool"
	elasticIPReasonAttached           = "Attached"
	elasticIPReasonConflict           = "Conflict"
	elasticIPReasonAllocating         = "Allocating"
	elasticIPReasonWaitingForHandover = "WaitingForHandover"

	elasticIPReasonWaitingForNetworkInterfaces = "WaitingForNetworkInterfaces"

	elasticIPRequeueAfter = 10 * time.Second

	elasticIPFinalizer = "elasticip.juneau.loutres.me/allocation-claim"
)

type elasticIPReconcileError struct {
	reason  string
	message string
}

func (e *elasticIPReconcileError) Error() string {
	return e.message
}

// ElasticIPReconciler reconciles a ElasticIP object.
//
// Address allocation is delegated to an AllocationClaim that targets the
// AllocationPools backing the AddressPools attached to the referenced
// ExternalNetwork. The reconciler owns the lifecycle of that claim and
// mirrors its outcome into ElasticIP.status. For an arp ExternalNetwork it
// also owns an ARPAdvertisement that points the address at the node holding
// the attachment.
//
// The address is used either through one ElasticIPAttachment (NAT) or by
// one NetworkInterface that names the ElasticIP (direct). The reconciler
// decides which one and publishes it in status.attachment; see
// decideElasticIPUse.
type ElasticIPReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticips,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticips/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticips/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=externalnetworks,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=elasticipattachments,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=networkinterfaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=arpadvertisements,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ElasticIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.ElasticIP
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get ElasticIP", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.handleDeletion(ctx, &resource)
	}

	if !controllerutil.ContainsFinalizer(&resource, elasticIPFinalizer) {
		controllerutil.AddFinalizer(&resource, elasticIPFinalizer)
		if err := r.Update(ctx, &resource); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	return r.reconcileNormal(ctx, &resource)
}

// handleDeletion releases the address. While NetworkInterfaces still name
// the ElasticIP it releases nothing: one of them may still carry the
// address, and giving it back would let another ElasticIP take an address
// a live NIC holds. The advertisement stays for the same reason.
func (r *ElasticIPReconciler) handleDeletion(ctx context.Context, resource *juneauv1alpha1.ElasticIP) error {
	if !controllerutil.ContainsFinalizer(resource, elasticIPFinalizer) {
		return nil
	}

	interfaces, err := r.listNamingInterfaces(ctx, resource)
	if err != nil {
		return err
	}
	if len(interfaces) > 0 {
		allocated := metav1.ConditionFalse
		if resource.Status.Address != "" {
			allocated = metav1.ConditionTrue
		}
		return r.updateStatus(ctx, resource, resource.Status.Phase, resource.Status.Address,
			retainedElasticIPAttachment(resource.Status.Attachment, interfaces),
			metav1.Condition{
				Type:   elasticIPConditionAllocated,
				Status: allocated,
				Reason: elasticIPReasonWaitingForNetworkInterfaces,
				Message: fmt.Sprintf("ElasticIP is being deleted; it keeps its AllocationClaim until NetworkInterface %s that names it is gone",
					networkInterfaceNames(interfaces)),
			},
		)
	}

	if err := deleteARPAdvertisement(ctx, r.Client, elasticIPAdvertisementName(resource.Namespace, resource.Name)); err != nil {
		return err
	}

	claimName := elasticIPClaimName(resource)
	var claim juneauv1alpha1.AllocationClaim
	if err := r.Get(ctx, client.ObjectKey{Name: claimName}, &claim); err == nil {
		if err := r.Delete(ctx, &claim); err != nil && !errors.IsNotFound(err) {
			return err
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	controllerutil.RemoveFinalizer(resource, elasticIPFinalizer)
	return r.Update(ctx, resource)
}

func (r *ElasticIPReconciler) reconcileNormal(ctx context.Context, resource *juneauv1alpha1.ElasticIP) (ctrl.Result, error) {
	pools, err := r.resolvePoolRefs(ctx, resource)
	if err != nil {
		var reconcileErr *elasticIPReconcileError
		if stderrors.As(err, &reconcileErr) {
			if updateErr := r.updateErrorStatus(ctx, resource, reconcileErr.reason, reconcileErr.message); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	address, requeue, err := r.ensureClaim(ctx, resource, pools.allocationPoolNames)
	if err != nil {
		return ctrl.Result{}, err
	}

	attachments, err := listActiveElasticIPAttachments(ctx, r.Client, resource.Namespace, resource.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	interfaces, err := r.listNamingInterfaces(ctx, resource)
	if err != nil {
		return ctrl.Result{}, err
	}
	use := decideElasticIPUse(resource.Status.Attachment, attachments, interfaces)

	if err := r.reconcileAdvertisement(ctx, resource, pools, address, use.nodeName); err != nil {
		return ctrl.Result{}, err
	}

	if requeue {
		if err := r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhasePending, "", nil,
			metav1.Condition{
				Type:    elasticIPConditionAllocated,
				Status:  metav1.ConditionFalse,
				Reason:  elasticIPReasonNoAddressAvailable,
				Message: "no available address in referenced AddressPools",
			},
			metav1.Condition{
				Type:    elasticIPConditionAttached,
				Status:  metav1.ConditionFalse,
				Reason:  elasticIPReasonAwaitingAttachment,
				Message: "ElasticIP is not attached",
			},
		); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: elasticIPRequeueAfter}, nil
	}

	if address == "" {
		// Claim exists but has not yet reached Allocated. Treat as Pending.
		if err := r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhasePending, "", nil,
			metav1.Condition{
				Type:    elasticIPConditionAllocated,
				Status:  metav1.ConditionFalse,
				Reason:  elasticIPReasonAllocating,
				Message: "AllocationClaim is still allocating an address",
			},
			metav1.Condition{
				Type:    elasticIPConditionAttached,
				Status:  metav1.ConditionFalse,
				Reason:  elasticIPReasonAwaitingAttachment,
				Message: "ElasticIP is not attached",
			},
		); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, r.updateUseStatus(ctx, resource, address, use)
}

// updateUseStatus publishes what uses an allocated address.
func (r *ElasticIPReconciler) updateUseStatus(ctx context.Context, resource *juneauv1alpha1.ElasticIP, address string, use elasticIPUse) error {
	allocated := metav1.Condition{
		Type:    elasticIPConditionAllocated,
		Status:  metav1.ConditionTrue,
		Reason:  elasticIPReasonReconcileSucceeded,
		Message: "ElasticIP address allocated",
	}

	switch {
	case use.conflict != "":
		return r.updateErrorStatus(ctx, resource, elasticIPReasonConflict, use.conflict)
	case use.attachment != nil:
		return r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseAttached, address, use.attachment,
			allocated,
			metav1.Condition{
				Type:    elasticIPConditionAttached,
				Status:  metav1.ConditionTrue,
				Reason:  elasticIPReasonAttached,
				Message: fmt.Sprintf("ElasticIP is attached by %s %q", use.attachment.Kind, use.attachment.Name),
			},
		)
	case use.waitingFor != "":
		return r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseAvailable, address, nil,
			allocated,
			metav1.Condition{
				Type:    elasticIPConditionAttached,
				Status:  metav1.ConditionFalse,
				Reason:  elasticIPReasonWaitingForHandover,
				Message: use.waitingFor,
			},
		)
	default:
		return r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseAvailable, address, nil,
			allocated,
			metav1.Condition{
				Type:    elasticIPConditionAttached,
				Status:  metav1.ConditionFalse,
				Reason:  elasticIPReasonAwaitingAttachment,
				Message: "ElasticIP is not attached",
			},
		)
	}
}

// elasticIPPools is the address space behind the referenced ExternalNetwork,
// resolved once per reconcile: the network itself, so the advertisement can
// name it, and the AllocationPool names the claim draws from.
type elasticIPPools struct {
	externalNetwork     juneauv1alpha1.ExternalNetwork
	allocationPoolNames []string
}

// resolvePoolRefs returns the AllocationPool names that back the AddressPools
// attached to the referenced ExternalNetwork. Every pool must advertise in the
// mode the ExternalNetwork type asks for, so the address reaches the external
// network through the path the ExternalNetwork describes.
func (r *ElasticIPReconciler) resolvePoolRefs(ctx context.Context, resource *juneauv1alpha1.ElasticIP) (*elasticIPPools, error) {
	if strings.TrimSpace(resource.Spec.ExternalNetwork) == "" {
		return nil, &elasticIPReconcileError{
			reason:  elasticIPReasonMissingDependency,
			message: "spec.externalNetwork is empty",
		}
	}

	var externalNetwork juneauv1alpha1.ExternalNetwork
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.ExternalNetwork}, &externalNetwork); err != nil {
		if errors.IsNotFound(err) {
			return nil, &elasticIPReconcileError{
				reason:  elasticIPReasonMissingDependency,
				message: fmt.Sprintf("ExternalNetwork %q not found", resource.Spec.ExternalNetwork),
			}
		}
		return nil, err
	}

	if len(externalNetwork.Spec.AddressPools) == 0 {
		return nil, &elasticIPReconcileError{
			reason:  elasticIPReasonMissingDependency,
			message: fmt.Sprintf("ExternalNetwork %q has no AddressPools", externalNetwork.Name),
		}
	}

	advertiseMode, err := externalNetworkAdvertiseMode(externalNetwork.Spec.Type)
	if err != nil {
		return nil, &elasticIPReconcileError{
			reason:  elasticIPReasonInvalidAddressPool,
			message: fmt.Sprintf("ExternalNetwork %q: %v", externalNetwork.Name, err),
		}
	}

	pools := &elasticIPPools{
		externalNetwork:     externalNetwork,
		allocationPoolNames: make([]string, 0, len(externalNetwork.Spec.AddressPools)),
	}
	for _, raw := range externalNetwork.Spec.AddressPools {
		poolName := strings.TrimSpace(raw)
		if poolName == "" {
			continue
		}

		var addressPool juneauv1alpha1.AddressPool
		if err := r.Get(ctx, client.ObjectKey{Name: poolName}, &addressPool); err != nil {
			if errors.IsNotFound(err) {
				return nil, &elasticIPReconcileError{
					reason:  elasticIPReasonMissingDependency,
					message: fmt.Sprintf("AddressPool %q not found", poolName),
				}
			}
			return nil, err
		}

		if addressPool.Spec.AdvertiseMode != advertiseMode {
			return nil, &elasticIPReconcileError{
				reason: elasticIPReasonInvalidAddressPool,
				message: fmt.Sprintf(
					"AddressPool %q advertiseMode must be %s to match ExternalNetwork %q of type %s",
					addressPool.Name, advertiseMode, externalNetwork.Name, externalNetwork.Spec.Type,
				),
			}
		}

		pools.allocationPoolNames = append(pools.allocationPoolNames, AddressPoolAllocationPoolName(addressPool.Name))
	}

	if len(pools.allocationPoolNames) == 0 {
		return nil, &elasticIPReconcileError{
			reason:  elasticIPReasonMissingDependency,
			message: fmt.Sprintf("ExternalNetwork %q resolves to no usable AddressPools", externalNetwork.Name),
		}
	}

	return pools, nil
}

// reconcileAdvertisement keeps the ARPAdvertisement in step with the one node
// that answers for this address: the node of the ElasticIPAttachment or of
// the NetworkInterface that uses it. It is removed whenever no such node
// exists: an unallocated ElasticIP, one nothing uses, or one whose uses
// conflict. Leaving it behind would keep a node answering for an address it
// no longer holds.
func (r *ElasticIPReconciler) reconcileAdvertisement(
	ctx context.Context,
	resource *juneauv1alpha1.ElasticIP,
	pools *elasticIPPools,
	address string,
	nodeName string,
) error {
	name := elasticIPAdvertisementName(resource.Namespace, resource.Name)

	switch pools.externalNetwork.Spec.Type {
	case juneauv1alpha1.ExternalNetworkTypeBGP:
		return deleteARPAdvertisement(ctx, r.Client, name)
	case juneauv1alpha1.ExternalNetworkTypeARP:
		if address == "" || nodeName == "" {
			return deleteARPAdvertisement(ctx, r.Client, name)
		}
		return ensureARPAdvertisement(ctx, r.Client, arpAdvertisementSpec{
			Name:            name,
			ExternalNetwork: pools.externalNetwork.Name,
			Address:         address,
			NodeName:        nodeName,
		}, arpAdvertisementDeletedByFinalizer{})
	default:
		return fmt.Errorf("ExternalNetwork %q has unsupported type %q", pools.externalNetwork.Name, pools.externalNetwork.Spec.Type)
	}
}

func elasticIPAdvertisementName(namespace, name string) string {
	return fmt.Sprintf("eip-%s-%s", namespace, name)
}

// ensureClaim creates or updates the AllocationClaim that backs this
// ElasticIP. Returns (allocatedIP, requeue, err) where requeue indicates the
// claim is unable to find a free address and should be retried later.
func (r *ElasticIPReconciler) ensureClaim(ctx context.Context, resource *juneauv1alpha1.ElasticIP, poolNames []string) (string, bool, error) {
	claimName := elasticIPClaimName(resource)
	poolRefs := make([]juneauv1alpha1.AllocationPoolReference, 0, len(poolNames))
	for _, name := range poolNames {
		poolRefs = append(poolRefs, juneauv1alpha1.AllocationPoolReference{Name: name})
	}

	desiredSpec := juneauv1alpha1.AllocationClaimSpec{
		PoolRefs: poolRefs,
		ResourceRef: juneauv1alpha1.AllocationResourceReference{
			APIVersion: juneauv1alpha1.GroupVersion.String(),
			Kind:       "ElasticIP",
			Namespace:  resource.Namespace,
			Name:       resource.Name,
		},
		Attribute: "status.address",
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
		if err := r.Create(ctx, claim); err != nil && !errors.IsAlreadyExists(err) {
			return "", false, fmt.Errorf("create AllocationClaim: %w", err)
		}
		return "", false, nil
	case err != nil:
		return "", false, err
	}

	// Existing claim: status mirroring + diagnose pool exhaustion.
	if existing.Status.Phase == juneauv1alpha1.AllocationClaimPhasePending {
		ready := meta.FindStatusCondition(existing.Status.Conditions, juneauv1alpha1.AllocationClaimStatusReady)
		if ready != nil && ready.Reason == allocationClaimReasonPending {
			return "", true, nil
		}
		return "", false, nil
	}

	if existing.Status.Phase == juneauv1alpha1.AllocationClaimPhaseAllocated && existing.Status.Value.IP != "" {
		return existing.Status.Value.IP, false, nil
	}

	return "", false, nil
}

func elasticIPClaimName(resource *juneauv1alpha1.ElasticIP) string {
	return allocationClaimName(
		"elasticip",
		schema.GroupVersionKind{Group: juneauv1alpha1.GroupVersion.Group, Version: juneauv1alpha1.GroupVersion.Version, Kind: "ElasticIP"},
		resource.Namespace,
		resource.Name,
		"status.address",
	)
}

// listNamingInterfaces returns every NetworkInterface that names the
// ElasticIP in spec.elasticIP, including ones being deleted: until such an
// interface is gone it may still carry the address. The field index it
// reads is installed by the NetworkInterface controller.
func (r *ElasticIPReconciler) listNamingInterfaces(ctx context.Context, resource *juneauv1alpha1.ElasticIP) ([]juneauv1alpha1.NetworkInterface, error) {
	var interfaces juneauv1alpha1.NetworkInterfaceList
	if err := r.List(ctx, &interfaces,
		client.InNamespace(resource.Namespace),
		client.MatchingFields{networkInterfaceElasticIPIndex: resource.Name},
	); err != nil {
		return nil, fmt.Errorf("list the NetworkInterfaces that name ElasticIP %s/%s: %w", resource.Namespace, resource.Name, err)
	}
	return interfaces.Items, nil
}

func (r *ElasticIPReconciler) updateErrorStatus(ctx context.Context, resource *juneauv1alpha1.ElasticIP, reason, message string) error {
	return r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseError, resource.Status.Address, nil,
		metav1.Condition{
			Type:    elasticIPConditionAllocated,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: message,
		},
		metav1.Condition{
			Type:    elasticIPConditionAttached,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: message,
		},
	)
}

func (r *ElasticIPReconciler) updateStatus(
	ctx context.Context,
	resource *juneauv1alpha1.ElasticIP,
	phase juneauv1alpha1.ElasticIPPhase,
	address string,
	attachment *juneauv1alpha1.ElasticIPStatusAttachment,
	conditions ...metav1.Condition,
) error {
	updated := resource.Status
	updated.ObservedGeneration = resource.Generation
	updated.Phase = phase
	updated.Address = address
	updated.Attachment = attachment

	for _, condition := range conditions {
		condition.ObservedGeneration = resource.Generation
		meta.SetStatusCondition(&updated.Conditions, condition)
	}

	if reflect.DeepEqual(resource.Status, updated) {
		return nil
	}

	resource.Status = updated
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ElasticIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.ElasticIP{},
		"spec.externalNetwork",
		func(obj client.Object) []string {
			resource := obj.(*juneauv1alpha1.ElasticIP)
			if resource.Spec.ExternalNetwork == "" {
				return nil
			}
			return []string{resource.Spec.ExternalNetwork}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for ElasticIP.spec.externalNetwork: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.ElasticIP{}).
		Watches(
			&juneauv1alpha1.NetworkInterface{},
			handler.EnqueueRequestsFromMapFunc(mapNetworkInterfaceToElasticIP),
		).
		Watches(
			&juneauv1alpha1.ElasticIPAttachment{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				attachment, ok := obj.(*juneauv1alpha1.ElasticIPAttachment)
				if !ok {
					return nil
				}

				elasticIPName := strings.TrimSpace(attachment.Spec.ElasticIPRef.Name)
				if elasticIPName == "" {
					return nil
				}

				return []reconcile.Request{{
					NamespacedName: client.ObjectKey{Namespace: attachment.Namespace, Name: elasticIPName},
				}}
			}),
		).
		Watches(
			&juneauv1alpha1.AllocationClaim{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
				if !ok {
					return nil
				}
				ref := claim.Spec.ResourceRef
				if ref.Kind != "ElasticIP" || ref.Name == "" {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name},
				}}
			}),
		).
		Named("elasticip").
		Complete(r)
}
