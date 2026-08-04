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
	"errors"
	"fmt"
	"net/netip"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// AllocationClaimReconciler reconciles a AllocationClaim object
type AllocationClaimReconciler struct {
	client.Client
	APIReader client.Reader
	Scheme    *runtime.Scheme
}

const (
	allocationClaimReasonAllocated = "Allocated"
	allocationClaimReasonPending   = "Pending"
	allocationClaimReasonFailed    = "AllocationFailed"

	allocationClaimFinalizer = "allocationclaim.juneau.loutres.me/lease"
)

// errAllPoolsExhausted indicates that no candidate pool has free capacity for
// this claim. It is treated as a transient Pending state, not an error.
var errAllPoolsExhausted = errors.New("no value available in any candidate pool")

// errPoolNotFound indicates that at least one referenced AllocationPool does
// not yet exist. Like errAllPoolsExhausted, it is transient: the claim is
// re-queued when a pool watch fires (creation or spec change), and proceeds
// once the pool object materializes.
var errPoolNotFound = errors.New("referenced allocation pool does not exist")

// allocationResult is the outcome of an allocation attempt against a single pool.
type allocationResult struct {
	poolName string
	number   uint64
	ip       string
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *AllocationClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.AllocationClaim
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !resource.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.handleDeletion(ctx, &resource)
	}

	if !controllerutil.ContainsFinalizer(&resource, allocationClaimFinalizer) {
		// Tolerate races with concurrent reconciles (manager-dispatched +
		// manually invoked) by retrying on Conflict; the only mutation is
		// adding our finalizer, which is idempotent once present.
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var fresh juneauloutresmev1alpha1.AllocationClaim
			if err := r.Get(ctx, req.NamespacedName, &fresh); err != nil {
				return err
			}
			if controllerutil.ContainsFinalizer(&fresh, allocationClaimFinalizer) {
				resource = fresh
				return nil
			}
			controllerutil.AddFinalizer(&fresh, allocationClaimFinalizer)
			if err := r.Update(ctx, &fresh); err != nil {
				return err
			}
			resource = fresh
			return nil
		}); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	if allocationClaimReady(resource) {
		return ctrl.Result{}, r.reconcileLease(ctx, &resource)
	}

	if len(resource.Spec.PoolRefs) == 0 {
		if err := r.updateStatusFailed(ctx, &resource, "spec.poolRefs is empty"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.ensureOwnerExists(ctx, &resource); err != nil {
		if updateErr := r.updateStatusFailed(ctx, &resource, err.Error()); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh juneauloutresmev1alpha1.AllocationClaim
		if err := r.reader().Get(ctx, req.NamespacedName, &fresh); err != nil {
			return err
		}
		if allocationClaimReady(fresh) {
			return nil
		}

		result, freshPool, err := r.allocate(ctx, &fresh)
		if err != nil {
			if errors.Is(err, errAllPoolsExhausted) || errors.Is(err, errPoolNotFound) {
				return r.updateStatusPending(ctx, &fresh, err.Error())
			}
			return r.updateStatusFailed(ctx, &fresh, err.Error())
		}

		// Record the value in a backing AllocationLease before marking the
		// claim Allocated. If lease creation races with another claim that
		// took the same value, return an error so the outer retry loop
		// re-runs allocate() and picks a different value.
		if err := r.ensureLease(ctx, &fresh, freshPool, result); err != nil {
			return err
		}

		freshPool.Status.AllocationVersion++
		freshPool.Status.LastAllocatedNumber = result.number
		if result.ip != "" {
			freshPool.Status.LastAllocatedIP = result.ip
		}
		if err := r.Status().Update(ctx, freshPool); err != nil {
			return err
		}

		return r.updateStatusAllocated(ctx, &fresh, result)
	}); err != nil {
		logger.Error(err, "unable to allocate claim", "name", req.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// handleDeletion processes the finalizer when an AllocationClaim is being
// deleted. When ReleaseAfter is set the lease is kept and marked Released;
// otherwise the lease is removed alongside the claim.
func (r *AllocationClaimReconciler) handleDeletion(ctx context.Context, claim *juneauloutresmev1alpha1.AllocationClaim) error {
	if !controllerutil.ContainsFinalizer(claim, allocationClaimFinalizer) {
		return nil
	}

	leaseName := leaseNameFor(claim)
	var lease juneauloutresmev1alpha1.AllocationLease
	if err := r.Get(ctx, client.ObjectKey{Name: leaseName}, &lease); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
	} else if leaseOwnedByClaim(&lease, claim) {
		if claim.Spec.ReleaseAfter != nil && claim.Spec.ReleaseAfter.Duration > 0 {
			now := metav1.Now()
			ttl := int32(claim.Spec.ReleaseAfter.Seconds())
			if lease.Spec.OwnerDeletionTimestamp == nil || lease.Spec.TTLSeconds == nil || *lease.Spec.TTLSeconds != ttl {
				lease.Spec.OwnerDeletionTimestamp = &now
				lease.Spec.TTLSeconds = &ttl
				if err := r.Update(ctx, &lease); err != nil {
					return err
				}
			}
		} else {
			if err := r.Delete(ctx, &lease); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}

	controllerutil.RemoveFinalizer(claim, allocationClaimFinalizer)
	return r.Update(ctx, claim)
}

// ensureLease creates or revives the AllocationLease that backs an allocated
// claim. The lease is owned by the AllocationPool so that pool deletion GCs
// the lease, while claim deletion is handled explicitly via the finalizer.
//
// Concurrent reconciles (the manager-dispatched controller running alongside
// a manually invoked Reconcile in tests, or simply two queued events) may
// both try to create the same lease. AlreadyExists is treated as success —
// a second pass through ensureLease will see the lease and fall into the
// update branch.
func (r *AllocationClaimReconciler) ensureLease(ctx context.Context, claim *juneauloutresmev1alpha1.AllocationClaim, pool *juneauloutresmev1alpha1.AllocationPool, result allocationResult) error {
	leaseName := leaseNameFor(claim)
	claimRef := juneauloutresmev1alpha1.AllocationLeaseClaimReference{Name: claim.Name, UID: string(claim.UID)}

	var existing juneauloutresmev1alpha1.AllocationLease
	if err := r.Get(ctx, client.ObjectKey{Name: leaseName}, &existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		lease := &juneauloutresmev1alpha1.AllocationLease{
			ObjectMeta: metav1.ObjectMeta{Name: leaseName},
			Spec: juneauloutresmev1alpha1.AllocationLeaseSpec{
				PoolRef:  juneauloutresmev1alpha1.AllocationPoolReference{Name: pool.Name},
				Value:    juneauloutresmev1alpha1.AllocationValue{Number: result.number, IP: result.ip},
				ClaimRef: claimRef,
			},
		}
		if err := controllerutil.SetControllerReference(pool, lease, r.Scheme); err != nil {
			return err
		}
		if err := r.Create(ctx, lease); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return nil
			}
			return err
		}
		return nil
	}

	// The reuse key still belongs to a live claim, so the value allocated
	// here is not recorded as a lease. It stays reserved by the claim's own
	// status for as long as the claim exists, and the holder keeps the
	// reservation that outlives it.
	if leaseHeldByOtherClaim(&existing, claim) {
		return nil
	}

	// Existing lease: clear OwnerDeletionTimestamp so that re-attached claims
	// (same identity, recreated after deletion) become Active again.
	desired := existing.DeepCopy()
	desired.Spec.PoolRef = juneauloutresmev1alpha1.AllocationPoolReference{Name: pool.Name}
	desired.Spec.Value = juneauloutresmev1alpha1.AllocationValue{Number: result.number, IP: result.ip}
	desired.Spec.ClaimRef = claimRef
	desired.Spec.OwnerDeletionTimestamp = nil
	desired.Spec.TTLSeconds = nil
	if reflect.DeepEqual(existing.Spec, desired.Spec) {
		return nil
	}
	return r.Update(ctx, desired)
}

// allocate iterates the claim's PoolRefs in order and returns the first
// successful allocation. The pool object that produced the result is also
// returned so the caller can update its status. Before scanning pools the
// allocator looks up the AllocationLease named after the claim's reuse key
// and, if the claim may take it, re-uses its value (this is what allows a
// claim deleted with ReleaseAfter and then re-created to inherit its prior
// allocation).
func (r *AllocationClaimReconciler) allocate(ctx context.Context, claim *juneauloutresmev1alpha1.AllocationClaim) (allocationResult, *juneauloutresmev1alpha1.AllocationPool, error) {
	held, err := r.getLease(ctx, leaseNameFor(claim))
	if err != nil {
		return allocationResult{}, nil, err
	}

	// A lease that another live claim holds is off limits: its value has to
	// count as used, so it must not be excluded as "this claim's own lease".
	selfLeaseName := leaseNameFor(claim)
	if held != nil && leaseHeldByOtherClaim(held, claim) {
		selfLeaseName = ""
		held = nil
	}

	if held != nil {
		if reused, pool, ok, err := r.reuseLease(ctx, claim, held); err != nil {
			return allocationResult{}, nil, err
		} else if ok {
			return reused, pool, nil
		}
	}

	var firstMissingPool string
	for _, ref := range claim.Spec.PoolRefs {
		var pool juneauloutresmev1alpha1.AllocationPool
		if err := r.reader().Get(ctx, client.ObjectKey{Name: ref.Name}, &pool); err != nil {
			if apierrors.IsNotFound(err) {
				if firstMissingPool == "" {
					firstMissingPool = ref.Name
				}
				continue
			}
			return allocationResult{}, nil, err
		}

		switch pool.Spec.Type {
		case juneauloutresmev1alpha1.AllocationTypeNumber:
			n, err := r.allocateNumber(ctx, &pool, claim, selfLeaseName)
			if err != nil {
				if errors.Is(err, errAllPoolsExhausted) {
					continue
				}
				return allocationResult{}, nil, err
			}
			return allocationResult{poolName: pool.Name, number: n}, &pool, nil
		case juneauloutresmev1alpha1.AllocationTypeIP:
			ip, err := r.allocateIP(ctx, &pool, claim, selfLeaseName)
			if err != nil {
				if errors.Is(err, errAllPoolsExhausted) {
					continue
				}
				return allocationResult{}, nil, err
			}
			return allocationResult{poolName: pool.Name, ip: ip}, &pool, nil
		default:
			return allocationResult{}, nil, fmt.Errorf("pool %q has unsupported type %q", pool.Name, pool.Spec.Type)
		}
	}
	if firstMissingPool != "" {
		return allocationResult{}, nil, fmt.Errorf("%w: %s", errPoolNotFound, firstMissingPool)
	}
	return allocationResult{}, nil, errAllPoolsExhausted
}

func (r *AllocationClaimReconciler) allocateNumber(ctx context.Context, pool *juneauloutresmev1alpha1.AllocationPool, claim *juneauloutresmev1alpha1.AllocationClaim, selfLeaseName string) (uint64, error) {
	if pool.Spec.Number == nil {
		return 0, fmt.Errorf("pool %q is type=number but spec.number is nil", pool.Name)
	}

	used, err := r.collectUsedNumbers(ctx, pool.Name, claim.Name, selfLeaseName)
	if err != nil {
		return 0, err
	}

	if requested := claim.Spec.RequestedNumber; requested != nil {
		if *requested < pool.Spec.Number.Min || *requested > pool.Spec.Number.Max {
			return 0, fmt.Errorf("requested number %d is outside pool %q range", *requested, pool.Name)
		}
		if holder, exists := used[*requested]; exists {
			return 0, fmt.Errorf("requested number %d is already allocated by %q", *requested, holder)
		}
		return *requested, nil
	}

	for candidate := pool.Spec.Number.Min; candidate <= pool.Spec.Number.Max; candidate++ {
		if _, exists := used[candidate]; !exists {
			return candidate, nil
		}
	}
	return 0, errAllPoolsExhausted
}

func (r *AllocationClaimReconciler) allocateIP(ctx context.Context, pool *juneauloutresmev1alpha1.AllocationPool, claim *juneauloutresmev1alpha1.AllocationClaim, selfLeaseName string) (string, error) {
	if pool.Spec.IP == nil {
		return "", fmt.Errorf("pool %q is type=ip but spec.ip is nil", pool.Name)
	}

	candidatePrefixes, err := parsePrefixes(pool.Spec.IP.CIDRs)
	if err != nil {
		return "", fmt.Errorf("pool %q has invalid CIDRs: %w", pool.Name, err)
	}

	if claim.Spec.AllocationFilter != nil && len(claim.Spec.AllocationFilter.CIDRs) > 0 {
		filterPrefixes, err := parsePrefixes(claim.Spec.AllocationFilter.CIDRs)
		if err != nil {
			return "", fmt.Errorf("claim %q has invalid allocationFilter: %w", claim.Name, err)
		}
		candidatePrefixes = intersectPrefixes(candidatePrefixes, filterPrefixes)
		if len(candidatePrefixes) == 0 {
			return "", errAllPoolsExhausted
		}
	}

	used, err := r.collectUsedIPs(ctx, pool.Name, claim.Name, selfLeaseName)
	if err != nil {
		return "", err
	}
	for _, raw := range pool.Spec.IP.Excluded {
		if addr, err := netip.ParseAddr(raw); err == nil {
			used[addr] = "excluded"
		}
	}

	if requested := claim.Spec.RequestedIP; requested != nil {
		addr, err := netip.ParseAddr(*requested)
		if err != nil {
			return "", fmt.Errorf("requested IP %q is invalid: %w", *requested, err)
		}
		if !addrInPrefixes(addr, candidatePrefixes) {
			return "", fmt.Errorf("requested IP %q is outside pool %q candidate space", *requested, pool.Name)
		}
		if holder, exists := used[addr]; exists {
			return "", fmt.Errorf("requested IP %q is already allocated by %q", *requested, holder)
		}
		return addr.String(), nil
	}

	for _, prefix := range candidatePrefixes {
		for addr := firstUsableAddr(prefix); prefix.Contains(addr); addr = addr.Next() {
			if !isUsableInPrefix(addr, prefix) {
				continue
			}
			if _, exists := used[addr]; exists {
				continue
			}
			return addr.String(), nil
		}
	}
	return "", errAllPoolsExhausted
}

func (r *AllocationClaimReconciler) collectUsedNumbers(ctx context.Context, poolName, selfClaimName, selfLeaseName string) (map[uint64]string, error) {
	var claims juneauloutresmev1alpha1.AllocationClaimList
	if err := r.reader().List(ctx, &claims); err != nil {
		return nil, fmt.Errorf("failed to list claims for pool %q: %w", poolName, err)
	}
	used := make(map[uint64]string, len(claims.Items))
	for _, existing := range claims.Items {
		if existing.Name == selfClaimName {
			continue
		}
		if !claimReferencesPool(&existing, poolName) {
			continue
		}
		if existing.Status.Phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated {
			continue
		}
		if existing.Status.Value.Number == 0 {
			continue
		}
		used[existing.Status.Value.Number] = existing.Name
	}

	// Leases for the same pool keep values reserved across claim deletion.
	var leases juneauloutresmev1alpha1.AllocationLeaseList
	if err := r.reader().List(ctx, &leases); err != nil {
		return nil, fmt.Errorf("failed to list leases for pool %q: %w", poolName, err)
	}
	for _, lease := range leases.Items {
		if lease.Spec.PoolRef.Name != poolName {
			continue
		}
		// Skip the lease that this claim itself owns.
		if lease.Name == selfLeaseName {
			continue
		}
		if lease.Spec.Value.Number == 0 {
			continue
		}
		if _, exists := used[lease.Spec.Value.Number]; !exists {
			used[lease.Spec.Value.Number] = "lease/" + lease.Name
		}
	}
	return used, nil
}

func (r *AllocationClaimReconciler) collectUsedIPs(ctx context.Context, poolName, selfClaimName, selfLeaseName string) (map[netip.Addr]string, error) {
	var claims juneauloutresmev1alpha1.AllocationClaimList
	if err := r.reader().List(ctx, &claims); err != nil {
		return nil, fmt.Errorf("failed to list claims for pool %q: %w", poolName, err)
	}
	used := make(map[netip.Addr]string, len(claims.Items))
	for _, existing := range claims.Items {
		if existing.Name == selfClaimName {
			continue
		}
		if !claimReferencesPool(&existing, poolName) {
			continue
		}
		if existing.Status.Phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated {
			continue
		}
		if existing.Status.Value.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(existing.Status.Value.IP)
		if err != nil {
			continue
		}
		used[addr] = existing.Name
	}

	var leases juneauloutresmev1alpha1.AllocationLeaseList
	if err := r.reader().List(ctx, &leases); err != nil {
		return nil, fmt.Errorf("failed to list leases for pool %q: %w", poolName, err)
	}
	for _, lease := range leases.Items {
		if lease.Spec.PoolRef.Name != poolName {
			continue
		}
		if lease.Name == selfLeaseName {
			continue
		}
		if lease.Spec.Value.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(lease.Spec.Value.IP)
		if err != nil {
			continue
		}
		if _, exists := used[addr]; !exists {
			used[addr] = "lease/" + lease.Name
		}
	}
	return used, nil
}

// reconcileLease brings the lease of an already allocated claim back to its
// desired state. Only the holder is written: the pool and the value are
// immutable once the lease exists, and the claim keeps the value it already
// reports in status.
//
// A lease that records another claim is never touched, not even when it is
// Released, so a claim that had to allocate around a held reuse key keeps
// the value it got. A lease with no holder at all is one written before the
// field existed, and this claim adopts it.
func (r *AllocationClaimReconciler) reconcileLease(ctx context.Context, claim *juneauloutresmev1alpha1.AllocationClaim) error {
	lease, err := r.getLease(ctx, leaseNameFor(claim))
	if err != nil || lease == nil {
		return err
	}
	if lease.Spec.ClaimRef.Name != "" && !leaseOwnedByClaim(lease, claim) {
		return nil
	}

	desired := lease.DeepCopy()
	desired.Spec.ClaimRef = juneauloutresmev1alpha1.AllocationLeaseClaimReference{Name: claim.Name, UID: string(claim.UID)}
	if reflect.DeepEqual(lease.Spec, desired.Spec) {
		return nil
	}
	return r.Update(ctx, desired)
}

// getLease reads an AllocationLease by name, returning nil when it does not
// exist.
func (r *AllocationClaimReconciler) getLease(ctx context.Context, name string) (*juneauloutresmev1alpha1.AllocationLease, error) {
	var lease juneauloutresmev1alpha1.AllocationLease
	if err := r.reader().Get(ctx, client.ObjectKey{Name: name}, &lease); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &lease, nil
}

// reuseLease returns the value already recorded on a lease the claim may
// take, so the claim inherits the prior allocation instead of running the
// allocator. This is the mechanism that lets a claim deleted with
// ReleaseAfter and then re-created under the same reuse key keep its value.
func (r *AllocationClaimReconciler) reuseLease(ctx context.Context, claim *juneauloutresmev1alpha1.AllocationClaim, lease *juneauloutresmev1alpha1.AllocationLease) (allocationResult, *juneauloutresmev1alpha1.AllocationPool, bool, error) {
	// Verify the lease still references one of the claim's candidate pools.
	if !claimReferencesPool(claim, lease.Spec.PoolRef.Name) {
		return allocationResult{}, nil, false, nil
	}

	var pool juneauloutresmev1alpha1.AllocationPool
	if err := r.reader().Get(ctx, client.ObjectKey{Name: lease.Spec.PoolRef.Name}, &pool); err != nil {
		if apierrors.IsNotFound(err) {
			return allocationResult{}, nil, false, nil
		}
		return allocationResult{}, nil, false, err
	}

	return allocationResult{
		poolName: pool.Name,
		number:   lease.Spec.Value.Number,
		ip:       lease.Spec.Value.IP,
	}, &pool, true, nil
}

func (r *AllocationClaimReconciler) ensureOwnerExists(ctx context.Context, claim *juneauloutresmev1alpha1.AllocationClaim) error {
	gk := schema.FromAPIVersionAndKind(claim.Spec.ResourceRef.APIVersion, claim.Spec.ResourceRef.Kind)
	obj, err := r.Scheme.New(gk)
	if err != nil {
		return fmt.Errorf("failed to create owner object for %s %q: %w", claim.Spec.ResourceRef.Kind, claim.Spec.ResourceRef.Name, err)
	}
	owner, ok := obj.(client.Object)
	if !ok {
		return fmt.Errorf("owner type %s does not implement client.Object", claim.Spec.ResourceRef.Kind)
	}
	owner.SetName(claim.Spec.ResourceRef.Name)
	if claim.Spec.ResourceRef.Namespace != "" {
		owner.SetNamespace(claim.Spec.ResourceRef.Namespace)
	}
	key := client.ObjectKey{Name: claim.Spec.ResourceRef.Name, Namespace: claim.Spec.ResourceRef.Namespace}
	if err := r.reader().Get(ctx, key, owner); err != nil {
		return fmt.Errorf("owner %s %q not found", claim.Spec.ResourceRef.Kind, claim.Spec.ResourceRef.Name)
	}
	return nil
}

func (r *AllocationClaimReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *AllocationClaimReconciler) updateStatusAllocated(ctx context.Context, resource *juneauloutresmev1alpha1.AllocationClaim, result allocationResult) error {
	return r.updateStatus(ctx, resource, juneauloutresmev1alpha1.AllocationClaimPhaseAllocated, result, metav1.ConditionTrue, allocationClaimReasonAllocated, "")
}

func (r *AllocationClaimReconciler) updateStatusPending(ctx context.Context, resource *juneauloutresmev1alpha1.AllocationClaim, message string) error {
	return r.updateStatus(ctx, resource, juneauloutresmev1alpha1.AllocationClaimPhasePending, allocationResult{}, metav1.ConditionFalse, allocationClaimReasonPending, message)
}

func (r *AllocationClaimReconciler) updateStatusFailed(ctx context.Context, resource *juneauloutresmev1alpha1.AllocationClaim, message string) error {
	return r.updateStatus(ctx, resource, juneauloutresmev1alpha1.AllocationClaimPhasePending, allocationResult{}, metav1.ConditionFalse, allocationClaimReasonFailed, message)
}

func (r *AllocationClaimReconciler) updateStatus(ctx context.Context, resource *juneauloutresmev1alpha1.AllocationClaim, phase juneauloutresmev1alpha1.AllocationClaimPhase, result allocationResult, ready metav1.ConditionStatus, reason, message string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh juneauloutresmev1alpha1.AllocationClaim
		if err := r.Get(ctx, client.ObjectKeyFromObject(resource), &fresh); err != nil {
			return err
		}

		if allocationClaimReady(fresh) && phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated {
			resource.Status = fresh.Status
			return nil
		}

		updated := fresh.DeepCopy()
		updated.Status.ObservedGeneration = updated.Generation
		updated.Status.Phase = phase
		if phase == juneauloutresmev1alpha1.AllocationClaimPhaseAllocated {
			updated.Status.Value = juneauloutresmev1alpha1.AllocationValue{
				Number: result.number,
				IP:     result.ip,
			}
		} else {
			updated.Status.Value = juneauloutresmev1alpha1.AllocationValue{}
		}
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               juneauloutresmev1alpha1.AllocationClaimStatusReady,
			Status:             ready,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: updated.Generation,
		})

		if updated.Status.ObservedGeneration == fresh.Status.ObservedGeneration &&
			updated.Status.Phase == fresh.Status.Phase &&
			updated.Status.Value == fresh.Status.Value &&
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

func allocationClaimReady(resource juneauloutresmev1alpha1.AllocationClaim) bool {
	if resource.Status.Phase != juneauloutresmev1alpha1.AllocationClaimPhaseAllocated {
		return false
	}
	if resource.Status.Value.Number == 0 && resource.Status.Value.IP == "" {
		return false
	}
	ready := meta.FindStatusCondition(resource.Status.Conditions, juneauloutresmev1alpha1.AllocationClaimStatusReady)
	if ready == nil {
		return false
	}
	return ready.Status == metav1.ConditionTrue && ready.ObservedGeneration == resource.Generation
}

const claimPoolRefIndex = "spec.poolRefs.name"

// SetupWithManager sets up the controller with the Manager.
func (r *AllocationClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.APIReader = mgr.GetAPIReader()
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauloutresmev1alpha1.AllocationClaim{},
		claimPoolRefIndex,
		func(obj client.Object) []string {
			claim := obj.(*juneauloutresmev1alpha1.AllocationClaim)
			out := make([]string, 0, len(claim.Spec.PoolRefs))
			for _, ref := range claim.Spec.PoolRefs {
				if ref.Name == "" {
					continue
				}
				out = append(out, ref.Name)
			}
			return out
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for AllocationClaim.spec.poolRefs.name: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.AllocationClaim{}).
		Watches(
			&juneauloutresmev1alpha1.AllocationPool{},
			handler.EnqueueRequestsFromMapFunc(r.mapPoolToClaims),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Watches(
			&juneauloutresmev1alpha1.AllocationLease{},
			handler.EnqueueRequestsFromMapFunc(r.mapLeaseToClaims),
			builder.WithPredicates(leaseDeletionPredicate),
		).
		Named("allocationclaim").
		Complete(r)
}

// mapPoolToClaims enqueues every AllocationClaim that references the given
// pool. Triggered when a pool is created (a previously not-found claim can
// finally allocate) or its spec changes (for example, capacity grew).
func (r *AllocationClaimReconciler) mapPoolToClaims(ctx context.Context, obj client.Object) []reconcile.Request {
	pool, ok := obj.(*juneauloutresmev1alpha1.AllocationPool)
	if !ok {
		return nil
	}
	return r.claimsReferencingPool(ctx, pool.Name)
}

// mapLeaseToClaims enqueues every AllocationClaim that references the lease's
// pool, used when the lease is deleted so claims waiting on capacity can
// retry. Lease creation/update is intentionally ignored (capacity only
// decreases on those events; the next claim Reconcile will see the lease via
// the API reader).
func (r *AllocationClaimReconciler) mapLeaseToClaims(ctx context.Context, obj client.Object) []reconcile.Request {
	lease, ok := obj.(*juneauloutresmev1alpha1.AllocationLease)
	if !ok {
		return nil
	}
	if lease.Spec.PoolRef.Name == "" {
		return nil
	}
	return r.claimsReferencingPool(ctx, lease.Spec.PoolRef.Name)
}

func (r *AllocationClaimReconciler) claimsReferencingPool(ctx context.Context, poolName string) []reconcile.Request {
	var claims juneauloutresmev1alpha1.AllocationClaimList
	if err := r.List(ctx, &claims, client.MatchingFields{claimPoolRefIndex: poolName}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(claims.Items))
	for i := range claims.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&claims.Items[i]),
		})
	}
	return requests
}

// leaseDeletionPredicate forwards only Delete events so the watch stays
// quiet during ordinary lease lifecycle (create/update by the claim
// reconciler itself).
var leaseDeletionPredicate = predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return false },
	UpdateFunc:  func(event.UpdateEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
	DeleteFunc:  func(event.DeleteEvent) bool { return true },
}

// parsePrefixes parses a list of CIDR strings into netip.Prefix values.
// netip.Prefix.Masked() is applied so that prefixes like "10.0.0.5/24" are
// normalised to their network form ("10.0.0.0/24") before iteration.
func parsePrefixes(raws []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raws))
	for _, raw := range raws {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// intersectPrefixes returns the entries from filter that are fully covered by
// at least one prefix in candidates. Filter prefixes that are not subsets of
// the candidate space are dropped (the consumer cannot allocate outside the
// pool's CIDRs).
func intersectPrefixes(candidates, filter []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(filter))
	for _, f := range filter {
		for _, c := range candidates {
			if c.Bits() <= f.Bits() && c.Contains(f.Addr()) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func addrInPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// firstUsableAddr returns the first iteration anchor for a prefix. For /31
// and /32 (and IPv6 /127, /128) every address is usable, so we start at the
// network address. For wider prefixes we skip the network address itself.
func firstUsableAddr(p netip.Prefix) netip.Addr {
	bits := p.Bits()
	switch p.Addr().BitLen() {
	case 32:
		if bits >= 31 {
			return p.Addr()
		}
	case 128:
		if bits >= 127 {
			return p.Addr()
		}
	}
	return p.Addr().Next()
}

// isUsableInPrefix returns false for the broadcast/all-ones address in IPv4
// prefixes wider than /31 (and the equivalent for IPv6 wider than /127).
func isUsableInPrefix(addr netip.Addr, p netip.Prefix) bool {
	bits := p.Bits()
	switch addr.BitLen() {
	case 32:
		if bits >= 31 {
			return true
		}
		return addr != lastAddrInPrefix(p)
	case 128:
		if bits >= 127 {
			return true
		}
		return addr != lastAddrInPrefix(p)
	}
	return true
}

// lastAddrInPrefix returns the broadcast (all-ones) address of the prefix.
func lastAddrInPrefix(p netip.Prefix) netip.Addr {
	addr := p.Masked().Addr()
	bits := p.Bits()
	bs := addr.As16()
	totalBits := addr.BitLen()
	hostBits := totalBits - bits
	for i := 15; hostBits > 0 && i >= 0; i-- {
		flip := hostBits
		if flip > 8 {
			flip = 8
		}
		bs[i] |= byte(1<<flip - 1)
		hostBits -= flip
	}
	if addr.Is4() {
		return netip.AddrFrom4([4]byte{bs[12], bs[13], bs[14], bs[15]})
	}
	return netip.AddrFrom16(bs)
}
