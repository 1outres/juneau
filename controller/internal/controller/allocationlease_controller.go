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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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

	// RetainWatchGVKs lists the kinds that spec.retainWhile may point at
	// and that this cluster serves. The controller watches each of them so
	// a lease reacts the moment the object it waits for goes away. Kinds
	// the cluster does not serve are left out; the periodic resync below
	// still checks leases that name them.
	RetainWatchGVKs []schema.GroupVersionKind
}

const (
	allocationLeaseReasonActive   = "Active"
	allocationLeaseReasonRetained = "Retained"
	allocationLeaseReasonReleased = "Released"
	allocationLeaseReasonExpired  = "Expired"

	// allocationLeaseRetainResyncInterval is how often a Retained lease
	// re-reads the object it waits for. The watch on that object covers
	// the common case, but the kind may be absent when the manager starts
	// and appear later, so the controller also compares the two states on
	// a slow, level-triggered cycle.
	allocationLeaseRetainResyncInterval = 5 * time.Minute

	// leaseRetainWhileIndex indexes leases by the object they wait for, so
	// a change to that object finds them without listing everything.
	leaseRetainWhileIndex = "spec.retainWhile"
)

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationleases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationleases/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationleases/finalizers,verbs=update
// +kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachines,verbs=get;list;watch

// Reconcile keeps the lease's observed phase aligned with its spec and
// removes the lease once its grace period has elapsed. The grace period
// starts at OwnerDeletionTimestamp, or at the moment the object named by
// spec.retainWhile disappeared when the lease has one.
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

	// Active: no owner deletion recorded yet. A retain reference does not
	// matter while the claim is alive; the claim itself holds the value.
	if resource.Spec.OwnerDeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, allocationLeaseStatus{
			phase:   juneauloutresmev1alpha1.AllocationLeasePhaseActive,
			ready:   metav1.ConditionTrue,
			reason:  allocationLeaseReasonActive,
			message: "lease backs an active claim",
		}); err != nil {
			logger.Error(err, "unable to update AllocationLease status", "name", req.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	ttlStartsAt := resource.Spec.OwnerDeletionTimestamp.Time
	var retainReleasedAt *metav1.Time

	if ref := resource.Spec.RetainWhile; ref != nil {
		exists, err := r.retainedObjectExists(ctx, ref)
		if err != nil {
			// Keep the reservation rather than risk handing the value to
			// somebody else because of a read that could not be answered.
			logger.Error(err, "unable to read the object an AllocationLease waits for", "name", req.Name, "retainWhile", retainReferenceKey(ref))
			return ctrl.Result{}, err
		}
		if exists {
			if err := r.updateStatus(ctx, &resource, allocationLeaseStatus{
				phase:   juneauloutresmev1alpha1.AllocationLeasePhaseRetained,
				ready:   metav1.ConditionFalse,
				reason:  allocationLeaseReasonRetained,
				message: fmt.Sprintf("claim has been deleted; %s still exists", retainReferenceKey(ref)),
			}); err != nil {
				logger.Error(err, "unable to update AllocationLease status", "name", req.Name)
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: allocationLeaseRetainResyncInterval}, nil
		}

		retainReleasedAt = resource.Status.RetainReleasedAt
		if retainReleasedAt == nil {
			observed := metav1.NewTime(now)
			retainReleasedAt = &observed
		}
		ttlStartsAt = retainReleasedAt.Time
	}

	ttl := time.Duration(0)
	if resource.Spec.TTLSeconds != nil && *resource.Spec.TTLSeconds > 0 {
		ttl = time.Duration(*resource.Spec.TTLSeconds) * time.Second
	}
	expiresAt := ttlStartsAt.Add(ttl)
	expiresAtMeta := metav1.NewTime(expiresAt)

	if !now.Before(expiresAt) {
		// Mark Expired and delete. Status update is best-effort; the
		// delete is the load-bearing action.
		_ = r.updateStatus(ctx, &resource, allocationLeaseStatus{
			phase:            juneauloutresmev1alpha1.AllocationLeasePhaseExpired,
			expiresAt:        &expiresAtMeta,
			retainReleasedAt: retainReleasedAt,
			ready:            metav1.ConditionFalse,
			reason:           allocationLeaseReasonExpired,
			message:          "TTL has elapsed",
		})

		if err := r.Delete(ctx, &resource, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &resource.UID}}); err != nil {
			if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
				return ctrl.Result{}, nil
			}
			logger.Error(err, "unable to delete expired AllocationLease", "name", req.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.updateStatus(ctx, &resource, allocationLeaseStatus{
		phase:            juneauloutresmev1alpha1.AllocationLeasePhaseReleased,
		expiresAt:        &expiresAtMeta,
		retainReleasedAt: retainReleasedAt,
		ready:            metav1.ConditionFalse,
		reason:           allocationLeaseReasonReleased,
		message:          "claim has been deleted; awaiting TTL",
	}); err != nil {
		logger.Error(err, "unable to update AllocationLease status", "name", req.Name)
		return ctrl.Result{}, err
	}

	// Schedule a re-queue for when the lease will expire.
	return ctrl.Result{RequeueAfter: expiresAt.Sub(now) + time.Second}, nil
}

// retainedObjectExists reports whether the object a lease waits for is still
// there. A kind this cluster does not serve counts as gone: no object of
// that kind can exist, so waiting for one would hold the value forever.
// Every other read failure is returned, which keeps the reservation until
// the answer is known.
func (r *AllocationLeaseReconciler) retainedObjectExists(ctx context.Context, ref *juneauloutresmev1alpha1.RetainReference) (bool, error) {
	var obj unstructured.Unstructured
	obj.SetGroupVersionKind(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind))

	err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &obj)
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	case meta.IsNoMatchError(err), runtime.IsNotRegisteredError(err):
		return false, nil
	default:
		return false, err
	}
}

// allocationLeaseStatus is the observed state a single reconcile pass wants
// to write. Grouping the fields keeps the writer honest: every pass states
// all of them, so a stale expiry or release time cannot survive a phase
// change.
type allocationLeaseStatus struct {
	phase            juneauloutresmev1alpha1.AllocationLeasePhase
	expiresAt        *metav1.Time
	retainReleasedAt *metav1.Time
	ready            metav1.ConditionStatus
	reason           string
	message          string
}

func (r *AllocationLeaseReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.AllocationLease, desired allocationLeaseStatus) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh juneauloutresmev1alpha1.AllocationLease
		if err := r.Get(ctx, client.ObjectKeyFromObject(resource), &fresh); err != nil {
			return err
		}

		updated := fresh.DeepCopy()
		updated.Status.ObservedGeneration = updated.Generation
		updated.Status.Phase = desired.phase
		updated.Status.ExpiresAt = desired.expiresAt
		updated.Status.RetainReleasedAt = desired.retainReleasedAt
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               juneauloutresmev1alpha1.AllocationLeaseStatusReady,
			Status:             desired.ready,
			Reason:             desired.reason,
			Message:            desired.message,
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
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauloutresmev1alpha1.AllocationLease{},
		leaseRetainWhileIndex,
		func(obj client.Object) []string {
			lease, ok := obj.(*juneauloutresmev1alpha1.AllocationLease)
			if !ok || lease.Spec.RetainWhile == nil {
				return nil
			}
			return []string{retainReferenceKey(lease.Spec.RetainWhile)}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for AllocationLease.spec.retainWhile: %w", err)
	}

	builder := ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.AllocationLease{}).
		Named("allocationlease")

	for _, gvk := range r.RetainWatchGVKs {
		retained := &unstructured.Unstructured{}
		retained.SetGroupVersionKind(gvk)
		builder = builder.Watches(retained, handler.EnqueueRequestsFromMapFunc(r.mapRetainedObjectToLeases(gvk)))
	}

	return builder.Complete(r)
}

// mapRetainedObjectToLeases enqueues every lease that waits for the given
// object. The GVK comes from the watch rather than from the event, so the
// key always matches the one the index was built with.
func (r *AllocationLeaseReconciler) mapRetainedObjectToLeases(gvk schema.GroupVersionKind) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		key := retainReferenceKey(&juneauloutresmev1alpha1.RetainReference{
			APIVersion: gvk.GroupVersion().String(),
			Kind:       gvk.Kind,
			Namespace:  obj.GetNamespace(),
			Name:       obj.GetName(),
		})

		var leases juneauloutresmev1alpha1.AllocationLeaseList
		if err := r.List(ctx, &leases, client.MatchingFields{leaseRetainWhileIndex: key}); err != nil {
			log.FromContext(ctx).Error(err, "unable to list AllocationLeases waiting for an object", "retainWhile", key)
			return nil
		}

		requests := make([]reconcile.Request, 0, len(leases.Items))
		for i := range leases.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(&leases.Items[i]),
			})
		}
		return requests
	}
}
