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
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const (
	transitGatewayAttachmentReasonDeleting              = "Deleting"
	transitGatewayAttachmentReasonReconcileFailed       = "ReconcileFailed"
	transitGatewayAttachmentReasonReconcileSucceeded    = "ReconcileSucceeded"
	transitGatewayAttachmentReasonNotReady              = "NotReady"
	transitGatewayAttachmentReasonTransitGatewayMissing = "TransitGatewayNotFound"
	transitGatewayAttachmentReasonVpcNotFound           = "VpcNotFound"
	transitGatewayAttachmentReasonRouteTableNotFound    = "RouteTableNotFound"
	transitGatewayAttachmentReasonRouteTableForeign     = "RouteTableForeign"

	transitGatewayAttachmentRequeueAfter = 100 * time.Millisecond
)

// TransitGatewayAttachmentReconciler reconciles a
// TransitGatewayAttachment object.
//
// The attachment holds no data-plane state of its own. It publishes the
// Subnets of the attached Vpc as status.prefixes; the
// TransitGatewayRouteTable reconciler turns those prefixes into
// propagated routes, and the RouteTable reconciler uses the attachment
// to find which transit route table a Vpc looks up in.
type TransitGatewayAttachmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgatewayattachments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgatewayattachments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgatewayattachments/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=transitgatewayroutetables,verbs=get;list;watch

func (r *TransitGatewayAttachmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.TransitGatewayAttachment
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get TransitGatewayAttachment", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, resource.Status.Prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonDeleting, "transit gateway attachment is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	prefixes := resource.Status.Prefixes

	var transitGateway juneauloutresmev1alpha1.TransitGateway
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.TransitGateway}, &transitGateway); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonTransitGatewayMissing, fmt.Sprintf("TransitGateway %q not found", resource.Spec.TransitGateway)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		if updateErr := r.updateStatus(ctx, &resource, prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonReconcileFailed, fmt.Sprintf("failed to get TransitGateway %q", resource.Spec.TransitGateway)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	var vpc juneauloutresmev1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonVpcNotFound, fmt.Sprintf("Vpc %q not found", resource.Spec.Vpc)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		if updateErr := r.updateStatus(ctx, &resource, prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonReconcileFailed, fmt.Sprintf("failed to get Vpc %q", resource.Spec.Vpc)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}
	if vpc.Status.VpcID == 0 {
		if err := r.updateStatus(ctx, &resource, prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonNotReady, fmt.Sprintf("Vpc %q has not yet been assigned a vpcID", resource.Spec.Vpc)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: transitGatewayAttachmentRequeueAfter}, nil
	}

	// Both the association and every propagation must live on the same
	// gateway. A route table from another gateway would be programmed
	// with prefixes that its own attachments never agreed to carry.
	for _, routeTableName := range resource.Spec.RouteTables() {
		var routeTable juneauloutresmev1alpha1.TransitGatewayRouteTable
		if err := r.Get(ctx, client.ObjectKey{Name: routeTableName}, &routeTable); err != nil {
			if errors.IsNotFound(err) {
				if updateErr := r.updateStatus(ctx, &resource, prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonRouteTableNotFound, fmt.Sprintf("TransitGatewayRouteTable %q not found", routeTableName)); updateErr != nil {
					return ctrl.Result{}, updateErr
				}
				return ctrl.Result{}, nil
			}
			if updateErr := r.updateStatus(ctx, &resource, prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonReconcileFailed, fmt.Sprintf("failed to get TransitGatewayRouteTable %q", routeTableName)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if routeTable.Spec.TransitGateway != resource.Spec.TransitGateway {
			if err := r.updateStatus(ctx, &resource, prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonRouteTableForeign, fmt.Sprintf("TransitGatewayRouteTable %q belongs to TransitGateway %q, not %q", routeTableName, routeTable.Spec.TransitGateway, resource.Spec.TransitGateway)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
	}

	prefixes, err := r.collectPrefixes(ctx, resource.Spec.Vpc)
	if err != nil {
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.Prefixes, metav1.ConditionFalse, transitGatewayAttachmentReasonReconcileFailed, fmt.Sprintf("failed to list subnets for Vpc %q", resource.Spec.Vpc)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	if err := r.updateStatus(ctx, &resource, prefixes, metav1.ConditionTrue, transitGatewayAttachmentReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// collectPrefixes lists the Subnets of the attached Vpc, sorted by CIDR
// so repeated reconciles publish the same status.
func (r *TransitGatewayAttachmentReconciler) collectPrefixes(ctx context.Context, vpcName string) ([]juneauloutresmev1alpha1.TransitGatewayAttachmentPrefix, error) {
	var subnets juneauloutresmev1alpha1.SubnetList
	if err := r.List(ctx, &subnets, client.MatchingFields{"spec.vpc": vpcName}); err != nil {
		return nil, err
	}

	prefixes := make([]juneauloutresmev1alpha1.TransitGatewayAttachmentPrefix, 0, len(subnets.Items))
	for i := range subnets.Items {
		prefixes = append(prefixes, juneauloutresmev1alpha1.TransitGatewayAttachmentPrefix{
			CIDR:   subnets.Items[i].Spec.CIDR,
			Subnet: subnets.Items[i].Name,
		})
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].CIDR < prefixes[j].CIDR })
	if len(prefixes) == 0 {
		return nil, nil
	}
	return prefixes, nil
}

func (r *TransitGatewayAttachmentReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.TransitGatewayAttachment, prefixes []juneauloutresmev1alpha1.TransitGatewayAttachmentPrefix, ready metav1.ConditionStatus, reason, message string) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.Prefixes = prefixes
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauloutresmev1alpha1.TransitGatewayAttachmentStatusReady,
		Status:             ready,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if updated.Status.ObservedGeneration == resource.Status.ObservedGeneration &&
		reflect.DeepEqual(updated.Status.Prefixes, resource.Status.Prefixes) &&
		reflect.DeepEqual(updated.Status.Conditions, resource.Status.Conditions) {
		return nil
	}

	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *TransitGatewayAttachmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.TransitGatewayAttachment{}).
		Watches(&juneauloutresmev1alpha1.TransitGateway{}, handler.EnqueueRequestsFromMapFunc(r.mapTransitGatewayToAttachments)).
		Watches(&juneauloutresmev1alpha1.TransitGatewayRouteTable{}, handler.EnqueueRequestsFromMapFunc(r.mapRouteTableToAttachments)).
		Watches(&juneauloutresmev1alpha1.Vpc{}, handler.EnqueueRequestsFromMapFunc(r.mapVpcToAttachments)).
		Watches(&juneauloutresmev1alpha1.Subnet{}, handler.EnqueueRequestsFromMapFunc(r.mapSubnetToAttachments)).
		Named("transitgatewayattachment").
		Complete(r)
}

func (r *TransitGatewayAttachmentReconciler) mapTransitGatewayToAttachments(ctx context.Context, obj client.Object) []reconcile.Request {
	transitGateway, ok := obj.(*juneauloutresmev1alpha1.TransitGateway)
	if !ok {
		return nil
	}
	return r.attachmentsMatching(ctx, func(spec *juneauloutresmev1alpha1.TransitGatewayAttachmentSpec) bool {
		return spec.TransitGateway == transitGateway.Name
	})
}

func (r *TransitGatewayAttachmentReconciler) mapRouteTableToAttachments(ctx context.Context, obj client.Object) []reconcile.Request {
	routeTable, ok := obj.(*juneauloutresmev1alpha1.TransitGatewayRouteTable)
	if !ok {
		return nil
	}
	return r.attachmentsMatching(ctx, func(spec *juneauloutresmev1alpha1.TransitGatewayAttachmentSpec) bool {
		for _, name := range spec.RouteTables() {
			if name == routeTable.Name {
				return true
			}
		}
		return false
	})
}

func (r *TransitGatewayAttachmentReconciler) mapVpcToAttachments(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*juneauloutresmev1alpha1.Vpc)
	if !ok {
		return nil
	}
	return r.attachmentsMatching(ctx, func(spec *juneauloutresmev1alpha1.TransitGatewayAttachmentSpec) bool {
		return spec.Vpc == vpc.Name
	})
}

func (r *TransitGatewayAttachmentReconciler) mapSubnetToAttachments(ctx context.Context, obj client.Object) []reconcile.Request {
	subnet, ok := obj.(*juneauloutresmev1alpha1.Subnet)
	if !ok || subnet.Spec.Vpc == "" {
		return nil
	}
	return r.attachmentsMatching(ctx, func(spec *juneauloutresmev1alpha1.TransitGatewayAttachmentSpec) bool {
		return spec.Vpc == subnet.Spec.Vpc
	})
}

func (r *TransitGatewayAttachmentReconciler) attachmentsMatching(ctx context.Context, match func(*juneauloutresmev1alpha1.TransitGatewayAttachmentSpec) bool) []reconcile.Request {
	var attachmentList juneauloutresmev1alpha1.TransitGatewayAttachmentList
	if err := r.List(ctx, &attachmentList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(attachmentList.Items))
	for i := range attachmentList.Items {
		if !match(&attachmentList.Items[i].Spec) {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: attachmentList.Items[i].Name}})
	}
	return requests
}
