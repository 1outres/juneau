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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	vpcReasonReconcileSucceeded = "ReconcileSucceeded"
)

// VpcReconciler reconciles a Vpc object
type VpcReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *VpcReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.Vpc
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Vpc", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if err := r.updateReadyCondition(ctx, &resource, metav1.ConditionTrue, vpcReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VpcReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.Vpc{}).
		Named("vpc").
		Complete(r)
}

func (r *VpcReconciler) updateReadyCondition(ctx context.Context, vpc *juneauv1alpha1.Vpc, status metav1.ConditionStatus, reason, message string) error {
	vpc.Status.ObservedGeneration = vpc.Generation
	meta.SetStatusCondition(&vpc.Status.Conditions, metav1.Condition{
		Type:    juneauv1alpha1.VpcStatusReady,
		Status:  status,
		Reason:  reason,
		Message: message,
	})
	return r.Status().Update(ctx, vpc)
}
