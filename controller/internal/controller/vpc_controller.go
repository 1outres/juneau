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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// vpcEndpointIPAllocationPoolPrefix prefixes the auto-generated
// AllocationPool name that backs VpcEndpoint VIP assignment for a Vpc.
// Distinct from the Subnet ("subnet-ip-…") namespace so the two never
// collide.
const vpcEndpointIPAllocationPoolPrefix = "vpc-endpoint-ip-"

// VpcEndpointIPAllocationPoolName returns the AllocationPool name that backs
// the VpcEndpoint VIPs of the given Vpc. Exported so the VpcEndpoint
// reconciler can reference it without duplicating the naming rule.
func VpcEndpointIPAllocationPoolName(vpcName string) string {
	return vpcEndpointIPAllocationPoolPrefix + vpcName
}

const (
	vpcReasonDeleting              = "Deleting"
	vpcReasonRouteTableNotReady    = "MainRouteTableNotReady"
	vpcReasonRouteTableMissing     = "MainRouteTableMissing"
	vpcReasonNotReady              = "NotReady"
	vpcReasonReconcileFailed       = "ReconcileFailed"
	vpcReasonReconcileSucceeded    = "ReconcileSucceeded"
	vpcReasonProviderSubnetMissing = "ProviderSubnetMissing"
	vpcReasonProviderSubnetForeign = "ProviderSubnetForeign"

	defaultVpcName = "default"
)

// VpcReconciler reconciles a Vpc object
type VpcReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=vpcs/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=servicenatattachments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

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

	if !resource.DeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, resource.Status.MainRouteTable, resource.Status.VpcID, metav1.ConditionFalse, vpcReasonDeleting, "VPC is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	vpcID := resource.Status.VpcID
	if resource.Name == defaultVpcName {
		vpcID = 1
	} else if vpcID == 0 {
		claim, err := r.ensureNumberClaim(ctx, &resource, allocationPoolVpcID, schema.GroupVersionKind{Group: juneauv1alpha1.GroupVersion.Group, Version: juneauv1alpha1.GroupVersion.Version, Kind: "Vpc"}, "status.vpcID")
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, resource.Status.MainRouteTable, vpcID, metav1.ConditionFalse, vpcReasonReconcileFailed, fmt.Sprintf("failed to ensure VPC ID allocation claim: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if claim.Status.Phase != juneauv1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.Number == 0 {
			if err := r.updateStatus(ctx, &resource, resource.Status.MainRouteTable, vpcID, metav1.ConditionFalse, vpcReasonNotReady, "waiting for VPC ID allocation"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
		}
		if claim.Status.Value.Number > uint64(^uint32(0)) {
			if err := r.updateStatus(ctx, &resource, resource.Status.MainRouteTable, vpcID, metav1.ConditionFalse, vpcReasonReconcileFailed, fmt.Sprintf("allocated VPC ID %d exceeds supported range", claim.Status.Value.Number)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		vpcID = uint32(claim.Status.Value.Number)
	}

	routeTable := &juneauv1alpha1.RouteTable{}
	routeTable.SetName(resource.Name)

	op, err := ctrl.CreateOrUpdate(ctx, r.Client, routeTable, func() error {
		routeTable.Spec.Vpc = resource.Name
		return controllerutil.SetControllerReference(&resource, routeTable, r.Scheme)
	})
	if err != nil {
		// Users and GitOps are told to apply the main RouteTable
		// themselves, so both writers can target it at once. Losing that
		// race is normal: the next reconcile adopts the object, and
		// there is nothing the user could fix, so the Ready condition
		// must not flicker.
		if isOptimisticConcurrencyLoss(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		if updateErr := r.updateStatus(ctx, &resource, resource.Status.MainRouteTable, vpcID, metav1.ConditionFalse, vpcReasonReconcileFailed, "failed to reconcile main route table"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	mainRouteTableName := routeTable.Name
	if err := r.updateMainRouteTableStatus(ctx, &resource, mainRouteTableName, vpcID); err != nil {
		return ctrl.Result{}, err
	}

	if op != controllerutil.OperationResultNone {
		return ctrl.Result{Requeue: true}, nil
	}

	var mainRouteTable juneauv1alpha1.RouteTable
	if err := r.Get(ctx, client.ObjectKey{Name: mainRouteTableName}, &mainRouteTable); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionFalse, vpcReasonRouteTableMissing, fmt.Sprintf("main route table %q not found", mainRouteTableName)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		if updateErr := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionFalse, vpcReasonReconcileFailed, "failed to fetch main route table"); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	mainRouteTableReady := meta.FindStatusCondition(mainRouteTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
	if mainRouteTableReady == nil {
		if err := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionFalse, vpcReasonRouteTableNotReady, fmt.Sprintf("main route table %q has no Ready condition", mainRouteTableName)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if mainRouteTableReady.Status != metav1.ConditionTrue {
		message := mainRouteTableReady.Message
		if message == "" {
			message = fmt.Sprintf("reason=%s status=%s", mainRouteTableReady.Reason, mainRouteTableReady.Status)
		}
		if err := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionFalse, vpcReasonRouteTableNotReady, fmt.Sprintf("main route table %q is not ready: %s", mainRouteTableName, message)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// When the Vpc opts in to the cross-Vpc provider role, the
	// referenced Subnet must exist and be owned by this Vpc. The check
	// lives here (not in the admission webhook) so that a Vpc and its
	// NAT-source Subnet can be applied together without admission
	// rejecting the Vpc on the grounds that the Subnet "doesn't exist
	// yet". The Subnet watcher re-reconciles the Vpc when the Subnet
	// finally appears.
	if resource.Spec.Service.IsProvider() {
		subnetName := resource.Spec.Service.ProviderSubnet()
		var subnet juneauv1alpha1.Subnet
		switch err := r.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); {
		case errors.IsNotFound(err):
			if updateErr := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionFalse, vpcReasonProviderSubnetMissing, fmt.Sprintf("spec.service.provider.natSourceSubnet %q does not exist", subnetName)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		case err != nil:
			if updateErr := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionFalse, vpcReasonReconcileFailed, fmt.Sprintf("failed to fetch provider Subnet %q: %v", subnetName, err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		case subnet.Spec.Vpc != resource.Name:
			if updateErr := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionFalse, vpcReasonProviderSubnetForeign, fmt.Sprintf("spec.service.provider.natSourceSubnet %q is owned by Vpc %q, not %q", subnetName, subnet.Spec.Vpc, resource.Name)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
	}

	if err := r.ensureEndpointIPAllocationPool(ctx, &resource); err != nil {
		if updateErr := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionFalse, vpcReasonReconcileFailed, fmt.Sprintf("failed to reconcile endpoint IP allocation pool: %v", err)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	// Every Vpc owns the ServiceNATAttachments rooted at it. When the
	// Vpc opts in to the cross-Vpc provider role
	// (spec.service.provider.natSourceSubnet), we eagerly allocate one
	// SNAT IP per Node so cross-Vpc flows are ready as soon as a
	// caller Vpc opts in. When the role is dropped, the cleanup pass
	// in ensureServiceNATAttachments tears the attachments down.
	if err := r.ensureServiceNATAttachments(ctx, &resource); err != nil {
		if updateErr := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionFalse, vpcReasonReconcileFailed, fmt.Sprintf("failed to reconcile ServiceNATAttachments: %v", err)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	if err := r.updateStatus(ctx, &resource, mainRouteTableName, vpcID, metav1.ConditionTrue, vpcReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// ensureEndpointIPAllocationPool maintains the per-Vpc AllocationPool that
// AllocationClaims for VpcEndpoint VIPs target. The pool is owned by the Vpc
// so it is GC'd automatically, and it is removed as soon as
// spec.endpointPool is dropped. Nothing is excluded: unlike a Subnet pool an
// endpoint pool holds no gateway and no DNS address.
func (r *VpcReconciler) ensureEndpointIPAllocationPool(ctx context.Context, vpc *juneauv1alpha1.Vpc) error {
	name := VpcEndpointIPAllocationPoolName(vpc.Name)

	if !vpc.Spec.EndpointPool.Configured() {
		pool := &juneauv1alpha1.AllocationPool{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if err := r.Delete(ctx, pool); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("delete AllocationPool: %w", err)
		}
		return nil
	}

	desiredSpec := juneauv1alpha1.AllocationPoolSpec{
		Type:     juneauv1alpha1.AllocationTypeIP,
		Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
		IP: &juneauv1alpha1.AllocationPoolIPSpec{
			CIDRs: vpc.Spec.EndpointPool.Cidrs(),
		},
	}

	var existing juneauv1alpha1.AllocationPool
	getErr := r.Get(ctx, client.ObjectKey{Name: name}, &existing)
	switch {
	case errors.IsNotFound(getErr):
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       desiredSpec,
		}
		if err := controllerutil.SetControllerReference(vpc, pool, r.Scheme); err != nil {
			return fmt.Errorf("set owner reference: %w", err)
		}
		if err := r.Create(ctx, pool); err != nil && !errors.IsAlreadyExists(err) {
			return fmt.Errorf("create AllocationPool: %w", err)
		}
		return nil
	case getErr != nil:
		return fmt.Errorf("get AllocationPool: %w", getErr)
	}

	updated := existing.DeepCopy()
	if err := controllerutil.SetControllerReference(vpc, updated, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference: %w", err)
	}
	updated.Spec = desiredSpec
	if reflect.DeepEqual(existing.Spec, updated.Spec) &&
		reflect.DeepEqual(existing.OwnerReferences, updated.OwnerReferences) {
		return nil
	}
	return r.Update(ctx, updated)
}

// ensureServiceNATAttachments reconciles the per-(Node, this-Vpc)
// ServiceNATAttachment fan-out. When the Vpc opts in to the
// cross-Vpc provider role it ensures one attachment per Node;
// otherwise the desired set is empty and the cleanup pass tears down
// any leftover attachments owned by this Vpc. Existing attachments
// for Nodes that have left the cluster are deleted regardless so SNAT
// IP allocations don't leak.
func (r *VpcReconciler) ensureServiceNATAttachments(ctx context.Context, vpc *juneauv1alpha1.Vpc) error {
	desired := make(map[string]struct{})

	if vpc.Spec.Service.IsProvider() {
		var nodes corev1.NodeList
		if err := r.List(ctx, &nodes); err != nil {
			return fmt.Errorf("list Nodes: %w", err)
		}
		for i := range nodes.Items {
			nodeName := nodes.Items[i].Name
			attachmentName := serviceNATAttachmentName(nodeName, vpc.Name)
			desired[attachmentName] = struct{}{}

			attachment := &juneauv1alpha1.ServiceNATAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: attachmentName},
			}
			_, err := controllerutil.CreateOrUpdate(ctx, r.Client, attachment, func() error {
				// Spec is immutable per the webhook, so only set on
				// create (when the resource has no UID yet).
				if attachment.UID == "" {
					attachment.Spec = juneauv1alpha1.ServiceNATAttachmentSpec{
						NodeName: nodeName,
						Vpc:      vpc.Name,
					}
				}
				return controllerutil.SetControllerReference(vpc, attachment, r.Scheme)
			})
			if err != nil {
				return fmt.Errorf("ensure ServiceNATAttachment %q: %w", attachmentName, err)
			}
		}
	}

	var attachments juneauv1alpha1.ServiceNATAttachmentList
	if err := r.List(ctx, &attachments); err != nil {
		return fmt.Errorf("list ServiceNATAttachments: %w", err)
	}
	for i := range attachments.Items {
		attachment := &attachments.Items[i]
		if !metav1.IsControlledBy(attachment, vpc) {
			continue
		}
		if _, kept := desired[attachment.Name]; kept {
			continue
		}
		if !attachment.DeletionTimestamp.IsZero() {
			continue
		}
		if err := r.Delete(ctx, attachment); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("delete stale ServiceNATAttachment %q: %w", attachment.Name, err)
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VpcReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.Vpc{}).
		Owns(&juneauv1alpha1.ServiceNATAttachment{}).
		Watches(&juneauv1alpha1.RouteTable{}, handler.EnqueueRequestsFromMapFunc(r.mapRouteTableToVpcs)).
		Watches(&juneauv1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToVpcs)).
		Watches(&juneauv1alpha1.Subnet{}, handler.EnqueueRequestsFromMapFunc(r.mapSubnetToProviderVpcs)).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.mapNodeToProviderVpcs)).
		Named("vpc").
		Complete(r)
}

func (r *VpcReconciler) ensureNumberClaim(ctx context.Context, vpc *juneauv1alpha1.Vpc, poolName string, gvk schema.GroupVersionKind, attribute string) (*juneauv1alpha1.AllocationClaim, error) {
	claim := newAllocationClaim(poolName, gvk, "", vpc.Name, attribute)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = newAllocationClaim(poolName, gvk, "", vpc.Name, attribute).Spec
		return controllerutil.SetControllerReference(vpc, claim, r.Scheme)
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

func isOptimisticConcurrencyLoss(err error) bool {
	return errors.IsAlreadyExists(err) || errors.IsConflict(err)
}

func (r *VpcReconciler) updateStatus(ctx context.Context, vpc *juneauv1alpha1.Vpc, mainRouteTable string, vpcID uint32, status metav1.ConditionStatus, reason, message string) error {
	updated := vpc.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.MainRouteTable = mainRouteTable
	updated.Status.VpcID = vpcID
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.VpcStatusReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if updated.Status.ObservedGeneration == vpc.Status.ObservedGeneration &&
		updated.Status.MainRouteTable == vpc.Status.MainRouteTable &&
		updated.Status.VpcID == vpc.Status.VpcID &&
		reflect.DeepEqual(updated.Status.Conditions, vpc.Status.Conditions) {
		return nil
	}

	vpc.Status = updated.Status
	return r.Status().Update(ctx, vpc)
}

func (r *VpcReconciler) updateMainRouteTableStatus(ctx context.Context, vpc *juneauv1alpha1.Vpc, mainRouteTable string, vpcID uint32) error {
	if vpc.Status.MainRouteTable == mainRouteTable && vpc.Status.VpcID == vpcID {
		return nil
	}

	updated := vpc.DeepCopy()
	updated.Status.ObservedGeneration = updated.Generation
	updated.Status.MainRouteTable = mainRouteTable
	updated.Status.VpcID = vpcID

	if updated.Status.ObservedGeneration == vpc.Status.ObservedGeneration &&
		updated.Status.MainRouteTable == vpc.Status.MainRouteTable &&
		updated.Status.VpcID == vpc.Status.VpcID &&
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

func (r *VpcReconciler) mapClaimToVpcs(ctx context.Context, obj client.Object) []reconcile.Request {
	_ = ctx
	claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "Vpc" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}

// mapSubnetToProviderVpcs enqueues every Vpc whose
// spec.service.provider.natSourceSubnet names the changed Subnet, so
// the Vpc's Ready condition (ProviderSubnetMissing /
// ProviderSubnetForeign) is reevaluated as soon as the Subnet is
// created, deleted, or its ownership changes.
func (r *VpcReconciler) mapSubnetToProviderVpcs(ctx context.Context, obj client.Object) []reconcile.Request {
	subnet, ok := obj.(*juneauv1alpha1.Subnet)
	if !ok {
		return nil
	}
	var list juneauv1alpha1.VpcList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.Service.ProviderSubnet() == subnet.Name {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: list.Items[i].Name}})
		}
	}
	return reqs
}

// mapNodeToProviderVpcs enqueues every Vpc that has opted in to the
// cross-Vpc provider role whenever a Node is added, removed, or
// labelled. Each provider Vpc owns its own per-Node
// ServiceNATAttachment fan-out, so all of them must reconcile when
// the Node set changes.
func (r *VpcReconciler) mapNodeToProviderVpcs(ctx context.Context, _ client.Object) []reconcile.Request {
	var list juneauv1alpha1.VpcList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.Service.IsProvider() {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: list.Items[i].Name}})
		}
	}
	return reqs
}
