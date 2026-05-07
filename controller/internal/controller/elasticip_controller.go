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
// mirrors its outcome into ElasticIP.status.
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
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete

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

func (r *ElasticIPReconciler) handleDeletion(ctx context.Context, resource *juneauv1alpha1.ElasticIP) error {
	if !controllerutil.ContainsFinalizer(resource, elasticIPFinalizer) {
		return nil
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
	poolNames, err := r.resolvePoolRefs(ctx, resource)
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

	address, requeue, err := r.ensureClaim(ctx, resource, poolNames)
	if err != nil {
		return ctrl.Result{}, err
	}

	if requeue {
		if err := r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhasePending, "", "",
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
		if err := r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhasePending, "", "",
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

	attachments, err := r.listActiveAttachments(ctx, resource)
	if err != nil {
		return ctrl.Result{}, err
	}

	switch len(attachments) {
	case 0:
		if err := r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseAvailable, address, "",
			metav1.Condition{
				Type:    elasticIPConditionAllocated,
				Status:  metav1.ConditionTrue,
				Reason:  elasticIPReasonReconcileSucceeded,
				Message: "ElasticIP address allocated",
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
	case 1:
		if err := r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseAttached, address, attachments[0].Name,
			metav1.Condition{
				Type:    elasticIPConditionAllocated,
				Status:  metav1.ConditionTrue,
				Reason:  elasticIPReasonReconcileSucceeded,
				Message: "ElasticIP address allocated",
			},
			metav1.Condition{
				Type:    elasticIPConditionAttached,
				Status:  metav1.ConditionTrue,
				Reason:  elasticIPReasonAttached,
				Message: fmt.Sprintf("ElasticIP is attached by %s", attachments[0].Name),
			},
		); err != nil {
			return ctrl.Result{}, err
		}
	default:
		if err := r.updateErrorStatus(ctx, resource, elasticIPReasonConflict, "multiple ElasticIPAttachments reference this ElasticIP"); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// resolvePoolRefs returns the AllocationPool names that back the AddressPools
// attached to the referenced ExternalNetwork. Only BGP-mode AddressPools are
// included. Errors from the shared resolver are translated into the
// ElasticIP-flavoured reason vocabulary so the existing status surface
// remains stable.
func (r *ElasticIPReconciler) resolvePoolRefs(ctx context.Context, resource *juneauv1alpha1.ElasticIP) ([]string, error) {
	pools, err := ResolveExternalNetworkBGPPools(ctx, r.Client, resource.Spec.ExternalNetwork)
	if err != nil {
		var resolveErr *ExternalNetworkResolveError
		if stderrors.As(err, &resolveErr) {
			return nil, &elasticIPReconcileError{
				reason:  resolveErr.Reason,
				message: resolveErr.Message,
			}
		}
		return nil, err
	}
	return pools, nil
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

func (r *ElasticIPReconciler) listActiveAttachments(ctx context.Context, resource *juneauv1alpha1.ElasticIP) ([]juneauv1alpha1.ElasticIPAttachment, error) {
	var attachments juneauv1alpha1.ElasticIPAttachmentList
	if err := r.List(ctx, &attachments, client.InNamespace(resource.Namespace)); err != nil {
		return nil, err
	}

	active := make([]juneauv1alpha1.ElasticIPAttachment, 0, len(attachments.Items))
	for i := range attachments.Items {
		attachment := attachments.Items[i]
		if attachment.Spec.ElasticIPRef.Name != resource.Name {
			continue
		}
		if attachment.DeletionTimestamp != nil {
			continue
		}
		active = append(active, attachment)
	}

	return active, nil
}

func (r *ElasticIPReconciler) updateErrorStatus(ctx context.Context, resource *juneauv1alpha1.ElasticIP, reason, message string) error {
	return r.updateStatus(ctx, resource, juneauv1alpha1.ElasticIPPhaseError, resource.Status.Address, "",
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
	attachmentName string,
	conditions ...metav1.Condition,
) error {
	updated := resource.Status
	updated.ObservedGeneration = resource.Generation
	updated.Phase = phase
	updated.Address = address
	updated.AttachmentName = attachmentName

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
