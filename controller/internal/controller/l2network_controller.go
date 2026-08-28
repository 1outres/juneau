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
	"net/netip"
	"reflect"
	"time"

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
	"github.com/1outres/juneau/controller/internal/podnetwork"
)

const (
	// DefaultL2NetworkMTU is the MTU an L2Network gets when it asks for
	// none: a 1500-byte underlay minus the 50 bytes VXLAN adds.
	DefaultL2NetworkMTU int32 = 1450

	// MinL2NetworkMTU and MaxL2NetworkMTU bound the MTU an L2Network may
	// carry. They mirror the bounds the CRD schema puts on spec.mtu.
	MinL2NetworkMTU int32 = 576
	MaxL2NetworkMTU int32 = 9000

	l2NetworkReasonDeleting           = "Deleting"
	l2NetworkReasonVpcNotFound        = "VpcNotFound"
	l2NetworkReasonVpcNotReady        = "VpcNotReady"
	l2NetworkReasonNotReady           = "NotReady"
	l2NetworkReasonReconcileFailed    = "ReconcileFailed"
	l2NetworkReasonNotImplemented     = "NotImplemented"
	l2NetworkReasonReconcileSucceeded = "ReconcileSucceeded"
)

// L2NetworkReconciler reconciles a L2Network object.
//
// It hands the segment a VNI, an address pool when the segment declares
// a CIDR, and a gateway identity when it declares a gateway. It holds no
// finalizer: a segment can go away while NICs still sit on it, exactly
// as a Subnet can.
type L2NetworkReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// DefaultMTU is the MTU handed to an L2Network that does not ask for
	// one. Zero means DefaultL2NetworkMTU.
	DefaultMTU int32
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=l2networks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=l2networks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=l2networks/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationpools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *L2NetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.L2Network
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get L2Network", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, resource.Status, metav1.ConditionFalse, l2NetworkReasonDeleting, "l2network is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	ready, err := r.vpcIsReady(ctx, &resource)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ready {
		return ctrl.Result{}, nil
	}

	desired := resource.Status.DeepCopy()

	if desired.VNI == 0 {
		claim, err := r.ensureNumberClaim(ctx, &resource, allocationPoolSubnetVNI, l2NetworkGVK(), "status.vni")
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, l2NetworkReasonReconcileFailed, fmt.Sprintf("failed to ensure VNI allocation claim: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if claim.Status.Phase != juneauv1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.Number == 0 {
			if err := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, l2NetworkReasonNotReady, "waiting for VNI allocation"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
		}
		if claim.Status.Value.Number > 0xFFFFFF {
			if err := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, l2NetworkReasonNotImplemented, fmt.Sprintf("allocated VNI %d exceeds supported range", claim.Status.Value.Number)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		desired.VNI = uint32(claim.Status.Value.Number)
	}

	desired.MTU = r.effectiveMTU(&resource)

	gateway, err := podnetwork.L2NetworkGatewayAddress(&resource)
	if err != nil {
		if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, l2NetworkReasonReconcileFailed, err.Error()); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}
	desired.Gateway = gateway

	// The gateway MAC is picked once and kept for as long as the gateway
	// exists, so attached workloads never have to relearn it. A segment
	// that drops its gateway drops the MAC with it: advertising a MAC
	// with no address behind it would be a lie.
	switch {
	case desired.Gateway == "":
		desired.GatewayMAC = ""
	case desired.GatewayMAC == "":
		mac, err := newLAA()
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, l2NetworkReasonReconcileFailed, "failed to generate gateway MAC address"); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		desired.GatewayMAC = mac.String()
	}

	if resource.Spec.CIDR != "" {
		if err := r.ensureIPAllocationPool(ctx, &resource, desired.Gateway); err != nil {
			if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, l2NetworkReasonReconcileFailed, fmt.Sprintf("failed to ensure IP allocation pool: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
	}

	aclRef, err := r.resolveNetworkACL(ctx, &resource)
	if err != nil {
		if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, l2NetworkReasonReconcileFailed, fmt.Sprintf("failed to resolve NetworkACL: %v", err)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}
	desired.NetworkACL = aclRef

	if err := r.updateStatus(ctx, &resource, *desired, metav1.ConditionTrue, l2NetworkReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// vpcIsReady waits for the owning Vpc, writing the reason onto the
// L2Network so users see why the segment is not coming up.
func (r *L2NetworkReconciler) vpcIsReady(ctx context.Context, resource *juneauv1alpha1.L2Network) (bool, error) {
	var vpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			return false, r.updateStatus(ctx, resource, resource.Status, metav1.ConditionFalse, l2NetworkReasonVpcNotFound, fmt.Sprintf("referenced VPC %q not found", resource.Spec.Vpc))
		}
		if updateErr := r.updateStatus(ctx, resource, resource.Status, metav1.ConditionFalse, l2NetworkReasonReconcileFailed, fmt.Sprintf("failed to fetch referenced VPC %q", resource.Spec.Vpc)); updateErr != nil {
			return false, updateErr
		}
		return false, err
	}

	vpcReady := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
	if vpcReady == nil {
		return false, r.updateStatus(ctx, resource, resource.Status, metav1.ConditionFalse, l2NetworkReasonVpcNotReady, fmt.Sprintf("referenced VPC %q has no Ready condition", resource.Spec.Vpc))
	}
	if vpcReady.Status != metav1.ConditionTrue {
		message := vpcReady.Message
		if message == "" {
			message = fmt.Sprintf("reason=%s status=%s", vpcReady.Reason, vpcReady.Status)
		}
		return false, r.updateStatus(ctx, resource, resource.Status, metav1.ConditionFalse, l2NetworkReasonVpcNotReady, fmt.Sprintf("referenced VPC %q is not ready: %s", resource.Spec.Vpc, message))
	}

	return true, nil
}

// resolveNetworkACL produces the NetworkACLRef the daemon reads from
// status.networkACL when it programs the gateway port of the segment.
//
// A named ACL that is not there yet, and one that has not been handed
// an ACLID, both come back as a ref with ACLID 0. The daemon reads that
// as "no ACL programmed", and the user sees in status that the
// reference is dangling rather than being told nothing at all.
func (r *L2NetworkReconciler) resolveNetworkACL(ctx context.Context, resource *juneauv1alpha1.L2Network) (*juneauv1alpha1.NetworkACLRef, error) {
	if resource.Spec.NetworkACL == "" {
		return nil, nil
	}

	var acl juneauv1alpha1.NetworkACL
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.NetworkACL}, &acl); err != nil {
		if errors.IsNotFound(err) {
			return &juneauv1alpha1.NetworkACLRef{Name: resource.Spec.NetworkACL}, nil
		}
		return nil, err
	}

	return &juneauv1alpha1.NetworkACLRef{
		Name:           acl.Name,
		ACLID:          acl.Status.ACLID,
		RulesetVersion: acl.Status.RulesetVersion,
	}, nil
}

// effectiveMTU is the MTU the segment ends up with: what it asked for,
// or the cluster-wide default the operator set on the controller.
func (r *L2NetworkReconciler) effectiveMTU(resource *juneauv1alpha1.L2Network) int32 {
	if resource.Spec.MTU != nil {
		return *resource.Spec.MTU
	}
	if r.DefaultMTU != 0 {
		return r.DefaultMTU
	}
	return DefaultL2NetworkMTU
}

// ensureIPAllocationPool maintains the per-L2Network AllocationPool that
// AllocationClaims for NIC addresses target. The pool is owned by the
// L2Network so it is GC'd with it.
//
// Only the gateway is excluded. A Subnet also holds back `.2` and `.3`
// for its virtual services, but an L2Network runs none: reserving
// addresses would only get in the way of whoever runs their own DHCP
// server on the segment.
func (r *L2NetworkReconciler) ensureIPAllocationPool(ctx context.Context, resource *juneauv1alpha1.L2Network, gateway string) error {
	prefix, err := netip.ParsePrefix(resource.Spec.CIDR)
	if err != nil {
		return fmt.Errorf("parse l2network CIDR: %w", err)
	}
	prefix = prefix.Masked()

	excluded, err := computeL2NetworkExcluded(prefix, gateway)
	if err != nil {
		return err
	}

	desiredSpec := juneauv1alpha1.AllocationPoolSpec{
		Type:     juneauv1alpha1.AllocationTypeIP,
		Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
		IP: &juneauv1alpha1.AllocationPoolIPSpec{
			CIDRs:    []string{resource.Spec.CIDR},
			Excluded: excluded,
		},
	}

	name := podnetwork.L2NetworkAllocationPoolName(resource.Name)
	var existing juneauv1alpha1.AllocationPool
	getErr := r.Get(ctx, client.ObjectKey{Name: name}, &existing)
	switch {
	case errors.IsNotFound(getErr):
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       desiredSpec,
		}
		if err := controllerutil.SetControllerReference(resource, pool, r.Scheme); err != nil {
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
	if err := controllerutil.SetControllerReference(resource, updated, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference: %w", err)
	}
	updated.Spec = desiredSpec
	if reflect.DeepEqual(existing.Spec, updated.Spec) &&
		reflect.DeepEqual(existing.OwnerReferences, updated.OwnerReferences) {
		return nil
	}
	return r.Update(ctx, updated)
}

// computeL2NetworkExcluded returns the addresses the per-L2Network pool
// must hold back. That is the gateway and nothing else; a segment
// without a gateway holds back nothing. The network and broadcast
// addresses are skipped by the allocator itself.
//
// A gateway the prefix cannot hold is an error rather than an address
// left out of the list: handing that address to a workload would put two
// owners on it.
func computeL2NetworkExcluded(prefix netip.Prefix, gateway string) ([]string, error) {
	if gateway == "" {
		return nil, nil
	}
	addr, err := netip.ParseAddr(gateway)
	if err != nil {
		return nil, fmt.Errorf("parse gateway address %q: %w", gateway, err)
	}
	if !prefix.Contains(addr) || !addressIsUsableInPrefix(addr, prefix) {
		return nil, fmt.Errorf("gateway address %q is not a usable address of %q", gateway, prefix)
	}
	return []string{addr.String()}, nil
}

func (r *L2NetworkReconciler) ensureNumberClaim(ctx context.Context, resource *juneauv1alpha1.L2Network, poolName string, gvk schema.GroupVersionKind, attribute string) (*juneauv1alpha1.AllocationClaim, error) {
	claim := newAllocationClaim(poolName, gvk, "", resource.Name, attribute)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = newAllocationClaim(poolName, gvk, "", resource.Name, attribute).Spec
		return controllerutil.SetControllerReference(resource, claim, r.Scheme)
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

// updateStatus writes the desired L2NetworkStatus to the apiserver,
// after folding in ObservedGeneration and the Ready condition. The full
// status travels as a value so every reconcile branch states exactly
// what it means to publish.
func (r *L2NetworkReconciler) updateStatus(ctx context.Context, resource *juneauv1alpha1.L2Network, desired juneauv1alpha1.L2NetworkStatus, status metav1.ConditionStatus, reason, message string) error {
	updated := resource.DeepCopy()
	updated.Status = desired
	updated.Status.Conditions = resource.Status.Conditions // start from existing conditions to preserve transition times
	updated.Status.ObservedGeneration = updated.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.L2NetworkStatusReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if reflect.DeepEqual(updated.Status, resource.Status) {
		return nil
	}

	resource.Status = updated.Status
	return r.Status().Update(ctx, resource)
}

func l2NetworkGVK() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   juneauv1alpha1.GroupVersion.Group,
		Version: juneauv1alpha1.GroupVersion.Version,
		Kind:    "L2Network",
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *L2NetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.L2Network{},
		"spec.vpc",
		func(obj client.Object) []string {
			l2 := obj.(*juneauv1alpha1.L2Network)
			if l2.Spec.Vpc == "" {
				return nil
			}
			return []string{l2.Spec.Vpc}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for L2Network.spec.vpc: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.L2Network{}).
		Owns(&juneauv1alpha1.AllocationPool{}).
		Watches(&juneauv1alpha1.Vpc{}, handler.EnqueueRequestsFromMapFunc(r.mapVpcToL2Networks)).
		Watches(&juneauv1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToL2Networks)).
		Watches(&juneauv1alpha1.NetworkACL{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkACLToL2Networks)).
		Named("l2network").
		Complete(r)
}

func (r *L2NetworkReconciler) mapVpcToL2Networks(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}

	var list juneauv1alpha1.L2NetworkList
	if err := r.List(ctx, &list, client.MatchingFields{"spec.vpc": vpc.Name}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: list.Items[i].Name}})
	}
	return requests
}

// mapNetworkACLToL2Networks fans a NetworkACL change out to the
// segments that name it, so an ACLID allocation or a rulesetVersion
// bump reaches status.networkACL without waiting for an unrelated
// L2Network event.
func (r *L2NetworkReconciler) mapNetworkACLToL2Networks(ctx context.Context, obj client.Object) []reconcile.Request {
	acl, ok := obj.(*juneauv1alpha1.NetworkACL)
	if !ok {
		return nil
	}

	var list juneauv1alpha1.L2NetworkList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.NetworkACL != acl.Name {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: list.Items[i].Name}})
	}
	return requests
}

func (r *L2NetworkReconciler) mapClaimToL2Networks(ctx context.Context, obj client.Object) []reconcile.Request {
	_ = ctx
	claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "L2Network" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}
