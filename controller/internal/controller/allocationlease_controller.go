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
	"reflect"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// AllocationLeaseReconciler reconciles a AllocationLease object.
//
// The AllocationClaim controller owns the lifecycle of the lease (creation,
// owner-deletion-timestamp updates). This controller is responsible only for
// reaping leases once their grace period has elapsed and for keeping the
// observed phase / expiresAt fields in sync.
type AllocationLeaseReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const (
	allocationLeaseReasonActive   = "Active"
	allocationLeaseReasonReleased = "Released"
	allocationLeaseReasonExpired  = "Expired"
)

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationleases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationleases/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationleases/finalizers,verbs=update

// Reconcile keeps the lease's observed phase aligned with its spec and
// removes the lease once OwnerDeletionTimestamp + TTLSeconds has elapsed.
func (r *AllocationLeaseReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	now := time.Now()

	var resource juneauloutresmev1alpha1.AllocationLease
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !resource.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	// Active: no owner deletion recorded yet.
	if resource.Spec.OwnerDeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, juneauloutresmev1alpha1.AllocationLeasePhaseActive, nil, metav1.ConditionTrue, allocationLeaseReasonActive, "lease backs an active claim"); err != nil {
			logger.Error(err, "unable to update AllocationLease status", "name", req.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	ttl := time.Duration(0)
	if resource.Spec.TTLSeconds != nil && *resource.Spec.TTLSeconds > 0 {
		ttl = time.Duration(*resource.Spec.TTLSeconds) * time.Second
	}
	expiresAt := resource.Spec.OwnerDeletionTimestamp.Add(ttl)
	expiresAtMeta := metav1.NewTime(expiresAt)

	if !now.Before(expiresAt) {
		// Mark Expired and delete. Status update is best-effort; the
		// delete is the load-bearing action.
		_ = r.updateStatus(ctx, &resource, juneauloutresmev1alpha1.AllocationLeasePhaseExpired, &expiresAtMeta, metav1.ConditionFalse, allocationLeaseReasonExpired, "TTL has elapsed")

		if err := r.Delete(ctx, &resource, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &resource.UID}}); err != nil {
			if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
				return ctrl.Result{}, nil
			}
			logger.Error(err, "unable to delete expired AllocationLease", "name", req.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.updateStatus(ctx, &resource, juneauloutresmev1alpha1.AllocationLeasePhaseReleased, &expiresAtMeta, metav1.ConditionFalse, allocationLeaseReasonReleased, "claim has been deleted; awaiting TTL"); err != nil {
		logger.Error(err, "unable to update AllocationLease status", "name", req.Name)
		return ctrl.Result{}, err
	}

	// Schedule a re-queue for when the lease will expire.
	return ctrl.Result{RequeueAfter: expiresAt.Sub(now) + time.Second}, nil
}

func (r *AllocationLeaseReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.AllocationLease, phase juneauloutresmev1alpha1.AllocationLeasePhase, expiresAt *metav1.Time, ready metav1.ConditionStatus, reason, message string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh juneauloutresmev1alpha1.AllocationLease
		if err := r.Get(ctx, client.ObjectKeyFromObject(resource), &fresh); err != nil {
			return err
		}

		updated := fresh.DeepCopy()
		updated.Status.ObservedGeneration = updated.Generation
		updated.Status.Phase = phase
		updated.Status.ExpiresAt = expiresAt
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               juneauloutresmev1alpha1.AllocationLeaseStatusReady,
			Status:             ready,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: updated.Generation,
		})

		if reflect.DeepEqual(fresh.Status, updated.Status) {
			resource.Status = updated.Status
			return nil
		}

		fresh.Status = updated.Status
		if err := r.Status().Update(ctx, &fresh); err != nil {
			return err
		}
		resource.Status = fresh.Status
		resource.ResourceVersion = fresh.ResourceVersion
		return nil
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *AllocationLeaseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.AllocationLease{}).
		Named("allocationlease").
		Complete(r)
}
