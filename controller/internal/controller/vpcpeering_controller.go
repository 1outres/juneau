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
	"net"
	"reflect"
	"sort"
	"strings"
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
	vpcPeeringReasonDeleting           = "Deleting"
	vpcPeeringReasonReconcileFailed    = "ReconcileFailed"
	vpcPeeringReasonReconcileSucceeded = "ReconcileSucceeded"
	vpcPeeringReasonNotReady           = "NotReady"
	vpcPeeringReasonVpcNotFound        = "VpcNotFound"
	vpcPeeringReasonCIDRConflict       = "CIDRConflict"

	vpcPeeringRequeueAfter = 100 * time.Millisecond
)

// VpcPeeringReconciler reconciles a VpcPeering object.
//
// The peering carries no data-plane state of its own: it publishes a
// single Ready condition that RouteTables consult before they resolve a
// via.type=vpcPeering route. Ready therefore means "both Vpcs exist, are
// allocated, and their Subnets do not collide".
type VpcPeeringReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcpeerings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcpeerings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcpeerings/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets,verbs=get;list;watch

func (r *VpcPeeringReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.VpcPeering
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get VpcPeering", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, metav1.ConditionFalse, vpcPeeringReasonDeleting, "VPC peering is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	for _, vpcName := range []string{resource.Spec.Requester.Vpc, resource.Spec.Accepter.Vpc} {
		var vpc juneauloutresmev1alpha1.Vpc
		if err := r.Get(ctx, client.ObjectKey{Name: vpcName}, &vpc); err != nil {
			if errors.IsNotFound(err) {
				if updateErr := r.updateStatus(ctx, &resource, metav1.ConditionFalse, vpcPeeringReasonVpcNotFound, fmt.Sprintf("Vpc %q not found", vpcName)); updateErr != nil {
					return ctrl.Result{}, updateErr
				}
				return ctrl.Result{}, nil
			}
			if updateErr := r.updateStatus(ctx, &resource, metav1.ConditionFalse, vpcPeeringReasonReconcileFailed, fmt.Sprintf("failed to get Vpc %q", vpcName)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if vpc.Status.VpcID == 0 {
			if err := r.updateStatus(ctx, &resource, metav1.ConditionFalse, vpcPeeringReasonNotReady, fmt.Sprintf("Vpc %q has not yet been assigned a vpcID", vpcName)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: vpcPeeringRequeueAfter}, nil
		}
	}

	// The webhook already rejects a peering that would create an
	// overlap, but two Subnets can still be admitted concurrently on
	// either side. Re-check here so the conflict surfaces on status
	// instead of reaching the data plane.
	conflicts, err := r.conflictingSubnets(ctx, resource.Spec.Requester.Vpc, resource.Spec.Accepter.Vpc)
	if err != nil {
		if updateErr := r.updateStatus(ctx, &resource, metav1.ConditionFalse, vpcPeeringReasonReconcileFailed, "failed to list subnets for peered VPCs"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}
	if len(conflicts) > 0 {
		if err := r.updateStatus(ctx, &resource, metav1.ConditionFalse, vpcPeeringReasonCIDRConflict, strings.Join(conflicts, "; ")); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.updateStatus(ctx, &resource, metav1.ConditionTrue, vpcPeeringReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// conflictingSubnets returns one message per pair of Subnets whose CIDRs
// overlap across the two Vpcs. The result is sorted so repeated
// reconciles publish the same message.
func (r *VpcPeeringReconciler) conflictingSubnets(ctx context.Context, requester, accepter string) ([]string, error) {
	requesterSubnets, err := r.listVpcSubnets(ctx, requester)
	if err != nil {
		return nil, err
	}
	accepterSubnets, err := r.listVpcSubnets(ctx, accepter)
	if err != nil {
		return nil, err
	}

	var conflicts []string
	for i := range requesterSubnets {
		a := &requesterSubnets[i]
		_, aCIDR, err := net.ParseCIDR(a.Spec.CIDR)
		if err != nil {
			continue
		}
		for j := range accepterSubnets {
			b := &accepterSubnets[j]
			_, bCIDR, err := net.ParseCIDR(b.Spec.CIDR)
			if err != nil {
				continue
			}
			if !ipNetsOverlap(aCIDR, bCIDR) {
				continue
			}
			conflicts = append(conflicts, fmt.Sprintf("Subnet %q (CIDR %q) in Vpc %q overlaps with Subnet %q (CIDR %q) in Vpc %q",
				a.Name, a.Spec.CIDR, requester, b.Name, b.Spec.CIDR, accepter))
		}
	}
	sort.Strings(conflicts)
	return conflicts, nil
}

func (r *VpcPeeringReconciler) listVpcSubnets(ctx context.Context, vpcName string) ([]juneauloutresmev1alpha1.Subnet, error) {
	var subnets juneauloutresmev1alpha1.SubnetList
	if err := r.List(ctx, &subnets, client.MatchingFields{"spec.vpc": vpcName}); err != nil {
		return nil, err
	}
	return subnets.Items, nil
}

func ipNetsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func (r *VpcPeeringReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.VpcPeering, ready metav1.ConditionStatus, reason, message string) error {
	updated := resource.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauloutresmev1alpha1.VpcPeeringStatusReady,
		Status:             ready,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if updated.Status.ObservedGeneration == resource.Status.ObservedGeneration &&
		reflect.DeepEqual(updated.Status.Conditions, resource.Status.Conditions) {
		return nil
	}

	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

// SetupWithManager sets up the controller with the Manager.
func (r *VpcPeeringReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.VpcPeering{}).
		Watches(&juneauloutresmev1alpha1.Vpc{}, handler.EnqueueRequestsFromMapFunc(r.mapVpcToVpcPeerings)).
		Watches(&juneauloutresmev1alpha1.Subnet{}, handler.EnqueueRequestsFromMapFunc(r.mapSubnetToVpcPeerings)).
		Named("vpcpeering").
		Complete(r)
}

func (r *VpcPeeringReconciler) mapVpcToVpcPeerings(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*juneauloutresmev1alpha1.Vpc)
	if !ok {
		return nil
	}
	return r.peeringsOfVpc(ctx, vpc.Name)
}

func (r *VpcPeeringReconciler) mapSubnetToVpcPeerings(ctx context.Context, obj client.Object) []reconcile.Request {
	subnet, ok := obj.(*juneauloutresmev1alpha1.Subnet)
	if !ok || subnet.Spec.Vpc == "" {
		return nil
	}
	return r.peeringsOfVpc(ctx, subnet.Spec.Vpc)
}

func (r *VpcPeeringReconciler) peeringsOfVpc(ctx context.Context, vpcName string) []reconcile.Request {
	var peeringList juneauloutresmev1alpha1.VpcPeeringList
	if err := r.List(ctx, &peeringList); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(peeringList.Items))
	for i := range peeringList.Items {
		if !peeringList.Items[i].Spec.Connects(vpcName) {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: peeringList.Items[i].Name}})
	}
	return requests
}
