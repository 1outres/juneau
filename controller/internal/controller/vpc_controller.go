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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	vpcReasonDeleting           = "Deleting"
	vpcReasonRouteTableNotReady = "MainRouteTableNotReady"
	vpcReasonRouteTableMissing  = "MainRouteTableMissing"
	vpcReasonReconcileFailed    = "ReconcileFailed"
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
		if err := r.updateStatus(ctx, &resource, resource.Status.MainRouteTable, metav1.ConditionFalse, vpcReasonDeleting, "VPC is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	routeTable := &juneauv1alpha1.RouteTable{}
	routeTable.SetName(resource.Name)

	op, err := ctrl.CreateOrUpdate(ctx, r.Client, routeTable, func() error {
		routeTable.Spec.Vpc = resource.Name
		return nil
	})
	if err != nil {
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.MainRouteTable, metav1.ConditionFalse, vpcReasonReconcileFailed, "failed to reconcile main route table"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	mainRouteTableName := routeTable.Name
	if err := r.updateMainRouteTableStatus(ctx, &resource, mainRouteTableName); err != nil {
		return ctrl.Result{}, err
	}

	if op != controllerutil.OperationResultNone {
		return ctrl.Result{Requeue: true}, nil
	}

	var mainRouteTable juneauv1alpha1.RouteTable
	if err := r.Get(ctx, client.ObjectKey{Name: mainRouteTableName}, &mainRouteTable); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, mainRouteTableName, metav1.ConditionFalse, vpcReasonRouteTableMissing, fmt.Sprintf("main route table %q not found", mainRouteTableName)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		if updateErr := r.updateStatus(ctx, &resource, mainRouteTableName, metav1.ConditionFalse, vpcReasonReconcileFailed, "failed to fetch main route table"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	mainRouteTableReady := meta.FindStatusCondition(mainRouteTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
	if mainRouteTableReady == nil {
		if err := r.updateStatus(ctx, &resource, mainRouteTableName, metav1.ConditionFalse, vpcReasonRouteTableNotReady, fmt.Sprintf("main route table %q has no Ready condition", mainRouteTableName)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if mainRouteTableReady.Status != metav1.ConditionTrue {
		message := mainRouteTableReady.Message
		if message == "" {
			message = fmt.Sprintf("reason=%s status=%s", mainRouteTableReady.Reason, mainRouteTableReady.Status)
		}
		if err := r.updateStatus(ctx, &resource, mainRouteTableName, metav1.ConditionFalse, vpcReasonRouteTableNotReady, fmt.Sprintf("main route table %q is not ready: %s", mainRouteTableName, message)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.updateStatus(ctx, &resource, mainRouteTableName, metav1.ConditionTrue, vpcReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VpcReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.Vpc{}).
		Watches(&juneauv1alpha1.RouteTable{}, handler.EnqueueRequestsFromMapFunc(r.mapRouteTableToVpcs)).
		Named("vpc").
		Complete(r)
}

func (r *VpcReconciler) updateStatus(ctx context.Context, vpc *juneauv1alpha1.Vpc, mainRouteTable string, status metav1.ConditionStatus, reason, message string) error {
	updated := vpc.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.MainRouteTable = mainRouteTable
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:    juneauv1alpha1.VpcStatusReady,
		Status:  status,
		Reason:  reason,
		Message: message,
	})

	if updated.Status.ObservedGeneration == vpc.Status.ObservedGeneration &&
		updated.Status.MainRouteTable == vpc.Status.MainRouteTable &&
		reflect.DeepEqual(updated.Status.Conditions, vpc.Status.Conditions) {
		return nil
	}

	vpc.Status = updated.Status
	return r.Status().Update(ctx, vpc)
}

func (r *VpcReconciler) updateMainRouteTableStatus(ctx context.Context, vpc *juneauv1alpha1.Vpc, mainRouteTable string) error {
	if vpc.Status.MainRouteTable == mainRouteTable {
		return nil
	}

	updated := vpc.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.MainRouteTable = mainRouteTable

	if updated.Status.ObservedGeneration == vpc.Status.ObservedGeneration &&
		updated.Status.MainRouteTable == vpc.Status.MainRouteTable &&
		reflect.DeepEqual(updated.Status.Conditions, vpc.Status.Conditions) {
		return nil
	}

	vpc.Status = updated.Status
	return r.Status().Update(ctx, vpc)
}

func (r *VpcReconciler) mapRouteTableToVpcs(ctx context.Context, obj client.Object) []reconcile.Request {
	routeTable, ok := obj.(*juneauv1alpha1.RouteTable)
	if !ok || routeTable.Spec.Vpc == "" {
		return nil
	}

	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: routeTable.Spec.Vpc}}}
}
