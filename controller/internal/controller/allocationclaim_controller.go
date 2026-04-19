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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// AllocationClaimReconciler reconciles a AllocationClaim object
type AllocationClaimReconciler struct {
	client.Client
	APIReader client.Reader
	Scheme    *runtime.Scheme
}

const (
	allocationClaimReasonAllocated = "Allocated"
	allocationClaimReasonPending   = "Pending"
	allocationClaimReasonFailed    = "AllocationFailed"
)

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the AllocationClaim object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *AllocationClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.AllocationClaim
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if allocationClaimReady(resource) {
		return ctrl.Result{}, nil
	}

	var pool juneauloutresmev1alpha1.AllocationPool
	if err := r.reader().Get(ctx, client.ObjectKey{Name: resource.Spec.PoolRef.Name}, &pool); err != nil {
		if err := r.updateStatus(ctx, &resource, juneauloutresmev1alpha1.AllocationClaimPhasePending, 0, metav1.ConditionFalse, allocationClaimReasonPending, fmt.Sprintf("pool %q not found", resource.Spec.PoolRef.Name)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.ensureOwnerExists(ctx, &resource); err != nil {
		if updateErr := r.updateStatus(ctx, &resource, juneauloutresmev1alpha1.AllocationClaimPhasePending, 0, metav1.ConditionFalse, allocationClaimReasonPending, err.Error()); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	if pool.Spec.Type != juneauloutresmev1alpha1.AllocationTypeNumber || pool.Spec.Number == nil {
		if err := r.updateStatus(ctx, &resource, juneauloutresmev1alpha1.AllocationClaimPhasePending, 0, metav1.ConditionFalse, allocationClaimReasonFailed, "only number pools are supported"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh juneauloutresmev1alpha1.AllocationClaim
		if err := r.reader().Get(ctx, req.NamespacedName, &fresh); err != nil {
			return err
		}
		if fresh.Status.Phase == juneauloutresmev1alpha1.AllocationClaimPhaseAllocated && fresh.Status.Value.Number != 0 {
			return nil
		}

		var freshPool juneauloutresmev1alpha1.AllocationPool
		if err := r.reader().Get(ctx, client.ObjectKey{Name: fresh.Spec.PoolRef.Name}, &freshPool); err != nil {
			return err
		}

		allocatedNumber, err := r.allocateNumber(ctx, &freshPool, &fresh)
		if err != nil {
			return r.updateStatus(ctx, &fresh, juneauloutresmev1alpha1.AllocationClaimPhasePending, 0, metav1.ConditionFalse, allocationClaimReasonFailed, err.Error())
		}
		freshPool.Status.AllocationVersion++
		freshPool.Status.LastAllocatedNumber = allocatedNumber
		if err := r.Status().Update(ctx, &freshPool); err != nil {
			return err
		}

		return r.updateStatus(ctx, &fresh, juneauloutresmev1alpha1.AllocationClaimPhaseAllocated, allocatedNumber, metav1.ConditionTrue, allocationClaimReasonAllocated, "")
	}); err != nil {
		logger.Error(err, "unable to allocate claim", "name", req.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *AllocationClaimReconciler) allocateNumber(ctx context.Context, pool *juneauloutresmev1alpha1.AllocationPool, claim *juneauloutresmev1alpha1.AllocationClaim) (uint64, error) {
	var claims juneauloutresmev1alpha1.AllocationClaimList
	if err := r.reader().List(ctx, &claims); err != nil {
		return 0, fmt.Errorf("failed to list claims for pool %q: %w", pool.Name, err)
	}

	used := map[uint64]string{}
	for _, existing := range claims.Items {
		if existing.Spec.PoolRef.Name != pool.Name {
			continue
		}
		if existing.Name == claim.Name {
			continue
		}
		if existing.Status.Phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated {
			continue
		}
		if existing.Status.Value.Number == 0 {
			continue
		}
		used[existing.Status.Value.Number] = existing.Name
	}

	if requested := claim.Spec.RequestedNumber; requested != nil {
		if *requested < pool.Spec.Number.Min || *requested > pool.Spec.Number.Max {
			return 0, fmt.Errorf("requested number %d is outside pool range", *requested)
		}
		if holder, exists := used[*requested]; exists {
			return 0, fmt.Errorf("requested number %d is already allocated by %q", *requested, holder)
		}
		return *requested, nil
	}

	for candidate := pool.Spec.Number.Min; candidate <= pool.Spec.Number.Max; candidate++ {
		if _, exists := used[candidate]; !exists {
			return candidate, nil
		}
	}

	return 0, fmt.Errorf("no numbers available in pool %q", pool.Name)
}

func (r *AllocationClaimReconciler) ensureOwnerExists(ctx context.Context, claim *juneauloutresmev1alpha1.AllocationClaim) error {
	gk := schema.FromAPIVersionAndKind(claim.Spec.ResourceRef.APIVersion, claim.Spec.ResourceRef.Kind)
	obj, err := r.Scheme.New(gk)
	if err != nil {
		return fmt.Errorf("failed to create owner object for %s %q: %w", claim.Spec.ResourceRef.Kind, claim.Spec.ResourceRef.Name, err)
	}
	owner, ok := obj.(client.Object)
	if !ok {
		return fmt.Errorf("owner type %s does not implement client.Object", claim.Spec.ResourceRef.Kind)
	}
	owner.SetName(claim.Spec.ResourceRef.Name)
	if err := r.reader().Get(ctx, client.ObjectKey{Name: claim.Spec.ResourceRef.Name}, owner); err != nil {
		return fmt.Errorf("owner %s %q not found", claim.Spec.ResourceRef.Kind, claim.Spec.ResourceRef.Name)
	}
	return nil
}

func (r *AllocationClaimReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *AllocationClaimReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.AllocationClaim, phase juneauloutresmev1alpha1.AllocationClaimPhase, number uint64, ready metav1.ConditionStatus, reason, message string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh juneauloutresmev1alpha1.AllocationClaim
		if err := r.Get(ctx, client.ObjectKeyFromObject(resource), &fresh); err != nil {
			return err
		}

		if allocationClaimReady(fresh) && phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated {
			resource.Status = fresh.Status
			return nil
		}

		updated := fresh.DeepCopy()
		updated.Status.ObservedGeneration = updated.Generation
		updated.Status.Phase = phase
		updated.Status.Value.Number = number
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               juneauloutresmev1alpha1.AllocationClaimStatusReady,
			Status:             ready,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: updated.Generation,
		})

		if updated.Status.ObservedGeneration == fresh.Status.ObservedGeneration && updated.Status.Phase == fresh.Status.Phase && updated.Status.Value.Number == fresh.Status.Value.Number && reflect.DeepEqual(updated.Status.Conditions, fresh.Status.Conditions) {
			resource.Status = updated.Status
			return nil
		}

		fresh.Status = updated.Status
		if err := r.Status().Update(ctx, &fresh); err != nil {
			return err
		}
		resource.Status = fresh.Status
		resource.ObjectMeta.ResourceVersion = fresh.ObjectMeta.ResourceVersion
		return nil
	})
}

func allocationClaimReady(resource juneauloutresmev1alpha1.AllocationClaim) bool {
	if resource.Status.Phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated || resource.Status.Value.Number == 0 {
		return false
	}
	ready := meta.FindStatusCondition(resource.Status.Conditions, juneauloutresmev1alpha1.AllocationClaimStatusReady)
	if ready == nil {
		return false
	}
	return ready.Status == metav1.ConditionTrue && ready.ObservedGeneration == resource.Generation
}

// SetupWithManager sets up the controller with the Manager.
func (r *AllocationClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.APIReader = mgr.GetAPIReader()
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauloutresmev1alpha1.AllocationClaim{},
		"spec.poolRef.name",
		func(obj client.Object) []string {
			claim := obj.(*juneauloutresmev1alpha1.AllocationClaim)
			if claim.Spec.PoolRef.Name == "" {
				return nil
			}
			return []string{claim.Spec.PoolRef.Name}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for AllocationClaim.spec.poolRef.name: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.AllocationClaim{}).
		Named("allocationclaim").
		Complete(r)
}
