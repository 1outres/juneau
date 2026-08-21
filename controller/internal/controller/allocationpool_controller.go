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
	"net/netip"
	"reflect"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// AllocationPoolReconciler reconciles a AllocationPool object
type AllocationPoolReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const (
	allocationPoolReasonSucceeded = "ReconcileSucceeded"
	allocationPoolReasonInvalid   = "Invalid"
)

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationpools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationpools/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationpools/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *AllocationPoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.AllocationPool
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if resource.DeletionTimestamp.IsZero() {
		if msg := validateAllocationPoolForStatus(&resource); msg != "" {
			if err := r.updateStatus(ctx, &resource, metav1.ConditionFalse, allocationPoolReasonInvalid, msg); err != nil {
				logger.Error(err, "unable to update AllocationPool status", "name", req.Name)
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
	}

	if err := r.updateStatus(ctx, &resource, metav1.ConditionTrue, allocationPoolReasonSucceeded, ""); err != nil {
		logger.Error(err, "unable to update AllocationPool status", "name", req.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *AllocationPoolReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.AllocationPool, ready metav1.ConditionStatus, reason, message string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh juneauloutresmev1alpha1.AllocationPool
		if err := r.Get(ctx, client.ObjectKeyFromObject(resource), &fresh); err != nil {
			return err
		}

		updated := fresh.DeepCopy()
		updated.Status.AllocationVersion = fresh.Status.AllocationVersion
		updated.Status.LastAllocatedNumber = fresh.Status.LastAllocatedNumber
		updated.Status.LastAllocatedIP = fresh.Status.LastAllocatedIP
		updated.Status.ObservedGeneration = updated.Generation
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               juneauloutresmev1alpha1.AllocationPoolStatusReady,
			Status:             ready,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: updated.Generation,
		})

		if updated.Status.ObservedGeneration == fresh.Status.ObservedGeneration &&
			updated.Status.AllocationVersion == fresh.Status.AllocationVersion &&
			updated.Status.LastAllocatedNumber == fresh.Status.LastAllocatedNumber &&
			updated.Status.LastAllocatedIP == fresh.Status.LastAllocatedIP &&
			reflect.DeepEqual(updated.Status.Conditions, fresh.Status.Conditions) {
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

// validateAllocationPoolForStatus mirrors the webhook validation but produces
// a single human-readable message for status reporting. Returns an empty
// string when the pool is valid.
func validateAllocationPoolForStatus(pool *juneauloutresmev1alpha1.AllocationPool) string {
	switch pool.Spec.Type {
	case juneauloutresmev1alpha1.AllocationTypeNumber:
		if pool.Spec.Number == nil {
			return "spec.number is required for type=number"
		}
		if pool.Spec.Number.Min > pool.Spec.Number.Max {
			return "number.min must be less than or equal to number.max"
		}
	case juneauloutresmev1alpha1.AllocationTypeIP:
		if pool.Spec.IP == nil {
			return "spec.ip is required for type=ip"
		}
		if len(pool.Spec.IP.CIDRs) == 0 && len(pool.Spec.IP.Ranges) == 0 {
			return "spec.ip.cidrs or spec.ip.ranges must contain at least one entry"
		}
		for _, raw := range pool.Spec.IP.CIDRs {
			if _, err := netip.ParsePrefix(raw); err != nil {
				return "invalid CIDR: " + raw
			}
		}
		if _, err := parseRangeCandidates(pool.Spec.IP.Ranges); err != nil {
			return err.Error()
		}
		for _, raw := range pool.Spec.IP.Excluded {
			if _, err := netip.ParseAddr(raw); err != nil {
				return "invalid excluded IP: " + raw
			}
		}
	}
	return ""
}

// SetupWithManager sets up the controller with the Manager.
func (r *AllocationPoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.AllocationPool{}).
		Named("allocationpool").
		Complete(r)
}
