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

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	transitGatewayReasonDeleting           = "Deleting"
	transitGatewayReasonReconcileFailed    = "ReconcileFailed"
	transitGatewayReasonReconcileSucceeded = "ReconcileSucceeded"
	transitGatewayReasonRouteTableMissing  = "DefaultRouteTableMissing"
	transitGatewayReasonRouteTableNotReady = "DefaultRouteTableNotReady"
)

// TransitGatewayReconciler reconciles a TransitGateway object.
//
// The gateway owns one TransitGatewayRouteTable that carries its own
// name, the same way a Vpc owns its main RouteTable. Everything else
// about the gateway lives in the attachments and the route tables that
// point back at it.
type TransitGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgatewayroutetables,verbs=get;list;watch;create;update;patch;delete

func (r *TransitGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.TransitGateway
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get TransitGateway", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, resource.Status.DefaultRouteTable, metav1.ConditionFalse, transitGatewayReasonDeleting, "transit gateway is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	routeTable := &juneauloutresmev1alpha1.TransitGatewayRouteTable{}
	routeTable.SetName(resource.Name)

	op, err := ctrl.CreateOrUpdate(ctx, r.Client, routeTable, func() error {
		routeTable.Spec.TransitGateway = resource.Name
		return controllerutil.SetControllerReference(&resource, routeTable, r.Scheme)
	})
	if err != nil {
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.DefaultRouteTable, metav1.ConditionFalse, transitGatewayReasonReconcileFailed, "failed to reconcile default route table"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	defaultRouteTableName := routeTable.Name
	if op != controllerutil.OperationResultNone {
		return ctrl.Result{Requeue: true}, nil
	}

	var defaultRouteTable juneauloutresmev1alpha1.TransitGatewayRouteTable
	if err := r.Get(ctx, client.ObjectKey{Name: defaultRouteTableName}, &defaultRouteTable); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, defaultRouteTableName, metav1.ConditionFalse, transitGatewayReasonRouteTableMissing, fmt.Sprintf("default route table %q not found", defaultRouteTableName)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		if updateErr := r.updateStatus(ctx, &resource, defaultRouteTableName, metav1.ConditionFalse, transitGatewayReasonReconcileFailed, "failed to fetch default route table"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	ready := meta.FindStatusCondition(defaultRouteTable.Status.Conditions, juneauloutresmev1alpha1.TransitGatewayRouteTableStatusReady)
	if ready == nil {
		if err := r.updateStatus(ctx, &resource, defaultRouteTableName, metav1.ConditionFalse, transitGatewayReasonRouteTableNotReady, fmt.Sprintf("default route table %q has no Ready condition", defaultRouteTableName)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if ready.Status != metav1.ConditionTrue {
		message := ready.Message
		if message == "" {
			message = fmt.Sprintf("reason=%s status=%s", ready.Reason, ready.Status)
		}
		if err := r.updateStatus(ctx, &resource, defaultRouteTableName, metav1.ConditionFalse, transitGatewayReasonRouteTableNotReady, fmt.Sprintf("default route table %q is not ready: %s", defaultRouteTableName, message)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.updateStatus(ctx, &resource, defaultRouteTableName, metav1.ConditionTrue, transitGatewayReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *TransitGatewayReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.TransitGateway, defaultRouteTable string, ready metav1.ConditionStatus, reason, message string) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.DefaultRouteTable = defaultRouteTable
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauloutresmev1alpha1.TransitGatewayStatusReady,
		Status:             ready,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if updated.Status.ObservedGeneration == resource.Status.ObservedGeneration &&
		updated.Status.DefaultRouteTable == resource.Status.DefaultRouteTable &&
		reflect.DeepEqual(updated.Status.Conditions, resource.Status.Conditions) {
		return nil
	}

	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *TransitGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.TransitGateway{}).
		Watches(&juneauloutresmev1alpha1.TransitGatewayRouteTable{}, handler.EnqueueRequestsFromMapFunc(r.mapRouteTableToTransitGateways)).
		Named("transitgateway").
		Complete(r)
}

func (r *TransitGatewayReconciler) mapRouteTableToTransitGateways(ctx context.Context, obj client.Object) []reconcile.Request {
	_ = ctx
	routeTable, ok := obj.(*juneauloutresmev1alpha1.TransitGatewayRouteTable)
	if !ok || routeTable.Spec.TransitGateway == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: routeTable.Spec.TransitGateway}}}
}
