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
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/addressrange"
)

// AddressPoolReconciler reconciles AddressPool resources.
//
// AddressPool is the user-facing CRD that declares an advertise mode (BGP /
// ARP) and a set of addresses. Behind the scenes the reconciler maintains a
// 1:1 AllocationPool (`addr-<name>`) so that ElasticIP, NATGateway and
// future consumers can allocate addresses through the shared
// AllocationClaim framework. The advertise mode itself is consumed by
// other components (BGP speaker, future ARP responder); this reconciler
// only translates the address list into the allocation framework.
type AddressPoolReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const (
	// addressPoolAllocationPoolPrefix prefixes the auto-generated
	// AllocationPool name. Distinct from subnet-derived AllocationPool
	// names ("subnet-ip-…") so the two namespaces never collide.
	addressPoolAllocationPoolPrefix = "addr-"
)

// AddressPoolAllocationPoolName returns the AllocationPool name that backs
// the given AddressPool. Exported for use by ElasticIP and other consumers
// that need to reference the underlying allocation pool.
func AddressPoolAllocationPoolName(addressPoolName string) string {
	return addressPoolAllocationPoolPrefix + addressPoolName
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=addresspools/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationpools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationleases,verbs=get;list;watch

// Reconcile keeps the AllocationPool that backs an AddressPool in sync
// with the user-declared CIDR list.
func (r *AddressPoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var addressPool juneauv1alpha1.AddressPool
	if err := r.Get(ctx, req.NamespacedName, &addressPool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// AddressPool deletion is handled by the AllocationPool's OwnerRef GC,
	// so no finalizer is required here.
	if !addressPool.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if err := r.ensureAllocationPool(ctx, &addressPool); err != nil {
		logger.Error(err, "unable to ensure backing AllocationPool", "addressPool", req.Name)
		return ctrl.Result{}, err
	}

	if err := r.updateStatus(ctx, &addressPool); err != nil {
		logger.Error(err, "unable to update AddressPool status", "addressPool", req.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *AddressPoolReconciler) ensureAllocationPool(ctx context.Context, addressPool *juneauv1alpha1.AddressPool) error {
	name := AddressPoolAllocationPoolName(addressPool.Name)

	ipSpec, err := allocationPoolIPSpec(addressPool)
	if err != nil {
		return err
	}
	desiredSpec := juneauv1alpha1.AllocationPoolSpec{
		Type:     juneauv1alpha1.AllocationTypeIP,
		Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
		IP:       ipSpec,
	}

	var existing juneauv1alpha1.AllocationPool
	err = r.Get(ctx, client.ObjectKey{Name: name}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       desiredSpec,
		}
		if err := controllerutil.SetControllerReference(addressPool, pool, r.Scheme); err != nil {
			return fmt.Errorf("set owner reference: %w", err)
		}
		if err := r.Create(ctx, pool); err != nil {
			if apierrors.IsAlreadyExists(err) {
				// Lost a race with another reconcile pass; re-run.
				return nil
			}
			return fmt.Errorf("create AllocationPool: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("get AllocationPool: %w", err)
	}

	// Update path: confirm the OwnerRef and address space are aligned with
	// the current AddressPool state.
	updated := existing.DeepCopy()
	if err := controllerutil.SetControllerReference(addressPool, updated, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference: %w", err)
	}
	updated.Spec = desiredSpec

	if reflect.DeepEqual(existing.Spec, updated.Spec) &&
		reflect.DeepEqual(existing.OwnerReferences, updated.OwnerReferences) {
		return nil
	}
	return r.Update(ctx, updated)
}

// allocationPoolIPSpec translates the user-declared addresses into the shape
// the allocation framework understands. BGP pools declare CIDRs, ARP pools
// declare start-end ranges; an address that does not match its advertise mode
// is an error rather than a value the reconciler guesses at.
func allocationPoolIPSpec(addressPool *juneauv1alpha1.AddressPool) (*juneauv1alpha1.AllocationPoolIPSpec, error) {
	switch addressPool.Spec.AdvertiseMode {
	case juneauv1alpha1.AddressPoolAdvertiseModeBGP:
		return &juneauv1alpha1.AllocationPoolIPSpec{
			CIDRs: append([]string(nil), addressPool.Spec.Addresses...),
		}, nil
	case juneauv1alpha1.AddressPoolAdvertiseModeARP:
		var ranges []juneauv1alpha1.AllocationPoolIPRange
		for _, address := range addressPool.Spec.Addresses {
			start, end, err := addressrange.ParseIPv4Range(address)
			if err != nil {
				return nil, fmt.Errorf("address %q: %w", address, err)
			}
			ranges = append(ranges, juneauv1alpha1.AllocationPoolIPRange{
				Start: start.String(),
				End:   end.String(),
			})
		}
		return &juneauv1alpha1.AllocationPoolIPSpec{Ranges: ranges}, nil
	}
	return nil, fmt.Errorf("unsupported advertiseMode %q", addressPool.Spec.AdvertiseMode)
}

// updateStatus writes the address counts. Nothing is written when the counts
// are already current, so the claim and lease events that do not change them
// cost no API call.
func (r *AddressPoolReconciler) updateStatus(ctx context.Context, addressPool *juneauv1alpha1.AddressPool) error {
	ipSpec, err := allocationPoolIPSpec(addressPool)
	if err != nil {
		return err
	}

	var claims juneauv1alpha1.AllocationClaimList
	if err := r.List(ctx, &claims); err != nil {
		return fmt.Errorf("list AllocationClaims: %w", err)
	}
	var leases juneauv1alpha1.AllocationLeaseList
	if err := r.List(ctx, &leases); err != nil {
		return fmt.Errorf("list AllocationLeases: %w", err)
	}
	poolName := AddressPoolAllocationPoolName(addressPool.Name)
	used := usedPoolIPs(poolName, "", "", claims.Items, leases.Items)

	counts, err := countPoolAddresses(ipSpec, used)
	if err != nil {
		return err
	}

	desired := juneauv1alpha1.AddressPoolStatus{
		ObservedGeneration: addressPool.Generation,
		TotalAddresses:     counts.total,
		AllocatedAddresses: counts.allocated,
		AvailableAddresses: counts.available,
	}
	if addressPool.Status == desired {
		return nil
	}
	updated := addressPool.DeepCopy()
	updated.Status = desired
	return r.Status().Update(ctx, updated)
}

// addressPoolForAllocationPool maps a claim or lease to the AddressPool that
// backs the pool it points at. Pools that are not backed by an AddressPool
// map to nothing.
func addressPoolForAllocationPool(poolName string) (string, bool) {
	name, ok := strings.CutPrefix(poolName, addressPoolAllocationPoolPrefix)
	return name, ok && name != ""
}

func requestsForAllocationClaim(_ context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
	if !ok {
		return nil
	}
	var requests []reconcile.Request
	for _, ref := range claim.Spec.PoolRefs {
		if name, ok := addressPoolForAllocationPool(ref.Name); ok {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
		}
	}
	return requests
}

func requestsForAllocationLease(_ context.Context, obj client.Object) []reconcile.Request {
	lease, ok := obj.(*juneauv1alpha1.AllocationLease)
	if !ok {
		return nil
	}
	name, ok := addressPoolForAllocationPool(lease.Spec.PoolRef.Name)
	if !ok {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: name}}}
}

// SetupWithManager sets up the controller with the Manager.
func (r *AddressPoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Status writes do not bump the generation, so this keeps the
		// controller from reconciling on its own status updates.
		For(&juneauv1alpha1.AddressPool{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&juneauv1alpha1.AllocationPool{}).
		Watches(&juneauv1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(requestsForAllocationClaim)).
		Watches(&juneauv1alpha1.AllocationLease{}, handler.EnqueueRequestsFromMapFunc(requestsForAllocationLease)).
		Named("addresspool").
		Complete(r)
}
