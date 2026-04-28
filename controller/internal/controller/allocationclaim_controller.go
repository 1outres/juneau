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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

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
)

// errAllPoolsExhausted indicates that no candidate pool has free capacity for
// this claim. It is treated as a transient Pending state, not an error.
var errAllPoolsExhausted = errors.New("no value available in any candidate pool")

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

	if allocationClaimReady(resource) {
		return ctrl.Result{}, nil
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
			if errors.Is(err, errAllPoolsExhausted) {
				return r.updateStatusPending(ctx, &fresh, err.Error())
			}
			return r.updateStatusFailed(ctx, &fresh, err.Error())
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

// allocate iterates the claim's PoolRefs in order and returns the first
// successful allocation. The pool object that produced the result is also
// returned so the caller can update its status.
func (r *AllocationClaimReconciler) allocate(ctx context.Context, claim *juneauloutresmev1alpha1.AllocationClaim) (allocationResult, *juneauloutresmev1alpha1.AllocationPool, error) {
	var firstPoolErr error
	for _, ref := range claim.Spec.PoolRefs {
		var pool juneauloutresmev1alpha1.AllocationPool
		if err := r.reader().Get(ctx, client.ObjectKey{Name: ref.Name}, &pool); err != nil {
			if firstPoolErr == nil {
				firstPoolErr = fmt.Errorf("pool %q not found", ref.Name)
			}
			continue
		}

		switch pool.Spec.Type {
		case juneauloutresmev1alpha1.AllocationTypeNumber:
			n, err := r.allocateNumber(ctx, &pool, claim)
			if err != nil {
				if errors.Is(err, errAllPoolsExhausted) {
					continue
				}
				return allocationResult{}, nil, err
			}
			return allocationResult{poolName: pool.Name, number: n}, &pool, nil
		case juneauloutresmev1alpha1.AllocationTypeIP:
			ip, err := r.allocateIP(ctx, &pool, claim)
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
	if firstPoolErr != nil {
		return allocationResult{}, nil, firstPoolErr
	}
	return allocationResult{}, nil, errAllPoolsExhausted
}

func (r *AllocationClaimReconciler) allocateNumber(ctx context.Context, pool *juneauloutresmev1alpha1.AllocationPool, claim *juneauloutresmev1alpha1.AllocationClaim) (uint64, error) {
	if pool.Spec.Number == nil {
		return 0, fmt.Errorf("pool %q is type=number but spec.number is nil", pool.Name)
	}

	used, err := r.collectUsedNumbers(ctx, pool.Name, claim.Name)
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

func (r *AllocationClaimReconciler) allocateIP(ctx context.Context, pool *juneauloutresmev1alpha1.AllocationPool, claim *juneauloutresmev1alpha1.AllocationClaim) (string, error) {
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

	used, err := r.collectUsedIPs(ctx, pool.Name, claim.Name)
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

func (r *AllocationClaimReconciler) collectUsedNumbers(ctx context.Context, poolName, selfName string) (map[uint64]string, error) {
	var claims juneauloutresmev1alpha1.AllocationClaimList
	if err := r.reader().List(ctx, &claims); err != nil {
		return nil, fmt.Errorf("failed to list claims for pool %q: %w", poolName, err)
	}
	used := make(map[uint64]string, len(claims.Items))
	for _, existing := range claims.Items {
		if existing.Name == selfName {
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
	return used, nil
}

func (r *AllocationClaimReconciler) collectUsedIPs(ctx context.Context, poolName, selfName string) (map[netip.Addr]string, error) {
	var claims juneauloutresmev1alpha1.AllocationClaimList
	if err := r.reader().List(ctx, &claims); err != nil {
		return nil, fmt.Errorf("failed to list claims for pool %q: %w", poolName, err)
	}
	used := make(map[netip.Addr]string, len(claims.Items))
	for _, existing := range claims.Items {
		if existing.Name == selfName {
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
	return used, nil
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
		resource.ObjectMeta.ResourceVersion = fresh.ObjectMeta.ResourceVersion
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
		Named("allocationclaim").
		Complete(r)
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
