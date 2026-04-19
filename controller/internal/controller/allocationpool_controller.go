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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
// TODO(user): Modify the Reconcile function to compare the state specified by
// the AllocationPool object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *AllocationPoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.AllocationPool
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if resource.ObjectMeta.DeletionTimestamp.IsZero() {
		if resource.Spec.Type == juneauloutresmev1alpha1.AllocationTypeNumber && resource.Spec.Number != nil && resource.Spec.Number.Min > resource.Spec.Number.Max {
			if err := r.updateStatus(ctx, &resource, metav1.ConditionFalse, allocationPoolReasonInvalid, "number.min must be less than or equal to number.max"); err != nil {
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
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:    juneauloutresmev1alpha1.AllocationPoolStatusReady,
		Status:  ready,
		Reason:  reason,
		Message: message,
	})

	if updated.Status.ObservedGeneration == resource.Status.ObservedGeneration && reflect.DeepEqual(updated.Status.Conditions, resource.Status.Conditions) {
		return nil
	}

	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *AllocationPoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.AllocationPool{}).
		Named("allocationpool").
		Complete(r)
}
