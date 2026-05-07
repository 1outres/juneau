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
	"crypto/rand"
	"fmt"
	"net"
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
)

const (
	// subnetIPAllocationPoolPrefix prefixes the auto-generated AllocationPool
	// name that backs Pod IP assignment for a Subnet. Distinct from the
	// AddressPool-derived ("addr-…") namespace so the two never collide.
	subnetIPAllocationPoolPrefix = "subnet-ip-"
)

// SubnetIPAllocationPoolName returns the AllocationPool name that backs the
// given Subnet. Exported so the NetworkInterface reconciler can reference
// it without duplicating the naming rule.
func SubnetIPAllocationPoolName(subnetName string) string {
	return subnetIPAllocationPoolPrefix + subnetName
}

const (
	subnetReasonDeleting           = "Deleting"
	subnetReasonVpcNotFound        = "VpcNotFound"
	subnetReasonVpcNotReady        = "VpcNotReady"
	subnetReasonNotReady           = "NotReady"
	subnetReasonReconcileFailed    = "ReconcileFailed"
	subnetReasonNotImplemented     = "NotImplemented"
	subnetReasonReconcileSucceeded = "ReconcileSucceeded"
)

// SubnetReconciler reconciles a Subnet object
type SubnetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=subnets/finalizers,verbs=update
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=allocationclaims/status,verbs=get;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *SubnetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauv1alpha1.Subnet
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get Subnet", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.DeletionTimestamp.IsZero() {
		if err := r.updateStatus(ctx, &resource, resource.Status, metav1.ConditionFalse, subnetReasonDeleting, "subnet is being deleted"); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	var vpc juneauv1alpha1.Vpc
	if err := r.Get(ctx, client.ObjectKey{Name: resource.Spec.Vpc}, &vpc); err != nil {
		if errors.IsNotFound(err) {
			if updateErr := r.updateStatus(ctx, &resource, resource.Status, metav1.ConditionFalse, subnetReasonVpcNotFound, fmt.Sprintf("referenced VPC %q not found", resource.Spec.Vpc)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, nil
		}
		if updateErr := r.updateStatus(ctx, &resource, resource.Status, metav1.ConditionFalse, subnetReasonReconcileFailed, fmt.Sprintf("failed to fetch referenced VPC %q", resource.Spec.Vpc)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	vpcReady := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
	if vpcReady == nil {
		if err := r.updateStatus(ctx, &resource, resource.Status, metav1.ConditionFalse, subnetReasonVpcNotReady, fmt.Sprintf("referenced VPC %q has no Ready condition", resource.Spec.Vpc)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if vpcReady.Status != metav1.ConditionTrue {
		message := vpcReady.Message
		if message == "" {
			message = fmt.Sprintf("reason=%s status=%s", vpcReady.Reason, vpcReady.Status)
		}
		if err := r.updateStatus(ctx, &resource, resource.Status, metav1.ConditionFalse, subnetReasonVpcNotReady, fmt.Sprintf("referenced VPC %q is not ready: %s", resource.Spec.Vpc, message)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	desired := resource.Status.DeepCopy()

	// Every Subnet — including the bootstrap "default" — claims its
	// VNI from the cluster-wide subnet-vni AllocationPool. The pool's
	// Min is set above SubnetVNIUnderlay so the data plane's reserved
	// VNI (currently 1, see VNI_UNDERLAY in maps.h / SubnetVNIUnderlay
	// in subnet_types.go) is guaranteed never to collide with a user-
	// facing Subnet.
	if desired.VNI == 0 {
		claim, err := r.ensureNumberClaim(ctx, &resource, allocationPoolSubnetVNI, schema.GroupVersionKind{Group: juneauv1alpha1.GroupVersion.Group, Version: juneauv1alpha1.GroupVersion.Version, Kind: "Subnet"}, "status.vni")
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, subnetReasonReconcileFailed, fmt.Sprintf("failed to ensure VNI allocation claim: %v", err)); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		if claim.Status.Phase != juneauv1alpha1.AllocationClaimPhaseAllocated || claim.Status.Value.Number == 0 {
			if err := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, subnetReasonNotReady, "waiting for VNI allocation"); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
		}
		if claim.Status.Value.Number > 0xFFFFFF {
			if err := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, subnetReasonNotImplemented, fmt.Sprintf("allocated VNI %d exceeds supported range", claim.Status.Value.Number)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		desired.VNI = uint32(claim.Status.Value.Number)
	}

	_, cidr, err := net.ParseCIDR(resource.Spec.CIDR)
	if err != nil {
		if err := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, subnetReasonReconcileFailed, fmt.Sprintf("failed to parse CIDR %q", resource.Spec.CIDR)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	desired.Gateway = nextGateway(cidr)

	if desired.GatewayMAC == "" {
		randMac, err := newLAA()
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, subnetReasonReconcileFailed, "failed to generate gateway MAC address"); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}

		desired.GatewayMAC = randMac.String()
	}

	// DNS VIP is the second usable address in the prefix (.2). Stays
	// empty when the prefix is too small for a `.2` (e.g. /31 or /32),
	// which leaves the rest of the data plane to skip the virtual DNS
	// service for that Subnet entirely.
	desired.DNS = nextDNSAddress(cidr)

	if desired.DNS != "" && desired.DNSMAC == "" {
		dnsMac, err := newLAA()
		if err != nil {
			if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, subnetReasonReconcileFailed, "failed to generate DNS MAC address"); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
			return ctrl.Result{}, err
		}
		desired.DNSMAC = dnsMac.String()
	}
	if desired.DNS == "" {
		// Keep status consistent: never advertise a DNSMAC without a DNS IP.
		desired.DNSMAC = ""
	}

	if err := r.ensureIPAllocationPool(ctx, &resource, desired.Gateway, desired.DNS); err != nil {
		if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, subnetReasonReconcileFailed, fmt.Sprintf("failed to ensure IP allocation pool: %v", err)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	aclRef, err := r.resolveNetworkACL(ctx, &resource)
	if err != nil {
		if updateErr := r.updateStatus(ctx, &resource, *desired, metav1.ConditionFalse, subnetReasonReconcileFailed, fmt.Sprintf("failed to resolve NetworkACL: %v", err)); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}
	desired.NetworkACL = aclRef

	if err := r.updateStatus(ctx, &resource, *desired, metav1.ConditionTrue, subnetReasonReconcileSucceeded, ""); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// resolveNetworkACL produces the SubnetNetworkACLRef the daemon
// consumes from status.networkACL. The webhook already enforces same-
// Vpc and existence at admission time, but the ACL may be allocated
// asynchronously (status.aclID == 0 until the AllocationClaim resolves)
// and may be deleted after admission while the Subnet still references
// it. Both cases are surfaced as a non-nil ref with ACLID==0 so the
// daemon can distinguish "no ACL configured" from "ACL configured but
// not yet ready" — the daemon treats both as "do not enforce" but
// users can see the dangling reference in status.
func (r *SubnetReconciler) resolveNetworkACL(ctx context.Context, subnet *juneauv1alpha1.Subnet) (*juneauv1alpha1.SubnetNetworkACLRef, error) {
	if subnet.Spec.NetworkACL == "" {
		return nil, nil
	}

	var acl juneauv1alpha1.NetworkACL
	if err := r.Get(ctx, client.ObjectKey{Name: subnet.Spec.NetworkACL}, &acl); err != nil {
		if errors.IsNotFound(err) {
			return &juneauv1alpha1.SubnetNetworkACLRef{Name: subnet.Spec.NetworkACL}, nil
		}
		return nil, err
	}

	return &juneauv1alpha1.SubnetNetworkACLRef{
		Name:           acl.Name,
		ACLID:          acl.Status.ACLID,
		RulesetVersion: acl.Status.RulesetVersion,
	}, nil
}

// ensureIPAllocationPool maintains the per-subnet AllocationPool that
// AllocationClaims for Pod IPs target. The pool is owned by the Subnet so
// it is GC'd automatically. The excluded list reserves the gateway plus
// the per-Subnet virtual service slot (DNS at `.2`) and a future-proofing
// slot at `.3`, trimmed to addresses that actually fall inside the prefix.
func (r *SubnetReconciler) ensureIPAllocationPool(ctx context.Context, subnet *juneauv1alpha1.Subnet, gateway, dns string) error {
	prefix, err := netip.ParsePrefix(subnet.Spec.CIDR)
	if err != nil {
		return fmt.Errorf("parse subnet CIDR: %w", err)
	}
	prefix = prefix.Masked()

	excluded := computeSubnetExcluded(prefix, gateway, dns)

	desiredSpec := juneauv1alpha1.AllocationPoolSpec{
		Type:     juneauv1alpha1.AllocationTypeIP,
		Strategy: juneauv1alpha1.AllocationStrategyFirstFit,
		IP: &juneauv1alpha1.AllocationPoolIPSpec{
			CIDRs:    []string{subnet.Spec.CIDR},
			Excluded: excluded,
		},
	}

	name := SubnetIPAllocationPoolName(subnet.Name)
	var existing juneauv1alpha1.AllocationPool
	getErr := r.Get(ctx, client.ObjectKey{Name: name}, &existing)
	switch {
	case errors.IsNotFound(getErr):
		pool := &juneauv1alpha1.AllocationPool{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       desiredSpec,
		}
		if err := controllerutil.SetControllerReference(subnet, pool, r.Scheme); err != nil {
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
	if err := controllerutil.SetControllerReference(subnet, updated, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference: %w", err)
	}
	updated.Spec = desiredSpec
	if reflect.DeepEqual(existing.Spec, updated.Spec) &&
		reflect.DeepEqual(existing.OwnerReferences, updated.OwnerReferences) {
		return nil
	}
	return r.Update(ctx, updated)
}

// computeSubnetExcluded returns the address strings that the per-subnet
// AllocationPool must exclude. The reservation set is:
//
//   - .1 (gateway, passed in as `gateway` so we honour whatever the
//     reconciler computed instead of hard-coding the offset).
//   - .2 (per-Subnet virtual DNS resolver IP, passed in as `dns`).
//   - .3 (held for additional virtual services we may expose in the
//     future; reserving it now avoids handing it out as a Pod IP and
//     having to migrate later).
//
// Addresses that fall outside the prefix's usable range are dropped.
// Network and broadcast addresses are automatically skipped by the IP
// allocator and need not be listed.
func computeSubnetExcluded(prefix netip.Prefix, gateway, dns string) []string {
	if !prefix.IsValid() {
		return nil
	}
	out := make([]string, 0, 3)
	seen := make(map[netip.Addr]struct{}, 3)

	add := func(addr netip.Addr) {
		if !addr.IsValid() || !prefix.Contains(addr) {
			return
		}
		if !addressIsUsableInPrefix(addr, prefix) {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr.String())
	}

	if gw, err := netip.ParseAddr(gateway); err == nil {
		add(gw)
	}
	if dnsAddr, err := netip.ParseAddr(dns); err == nil {
		add(dnsAddr)
	}

	// .3 is currently unassigned but reserved for a future virtual
	// service. Keep it out of the Pod IP pool so we never have to
	// reclaim it from a running workload.
	cursor := prefix.Addr().Next() // .1
	cursor = cursor.Next()         // .2
	cursor = cursor.Next()         // .3
	add(cursor)

	return out
}

// addressIsUsableInPrefix mirrors the IP allocator's view of which
// addresses are eligible (not the network or broadcast address for /29 and
// wider IPv4 prefixes).
func addressIsUsableInPrefix(addr netip.Addr, p netip.Prefix) bool {
	if addr == p.Addr() {
		// Network address is never usable for prefixes that have a
		// distinct network address (i.e. prefixes wider than /31).
		bits := p.Bits()
		switch addr.BitLen() {
		case 32:
			if bits >= 31 {
				return true
			}
		case 128:
			if bits >= 127 {
				return true
			}
		}
		return false
	}
	bits := p.Bits()
	switch addr.BitLen() {
	case 32:
		if bits >= 31 {
			return true
		}
	case 128:
		if bits >= 127 {
			return true
		}
	}
	return addr != lastAddrInPrefix(p)
}

// SetupWithManager sets up the controller with the Manager.
func (r *SubnetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauv1alpha1.Subnet{},
		"spec.vpc",
		func(obj client.Object) []string {
			subnet := obj.(*juneauv1alpha1.Subnet)
			if subnet.Spec.Vpc == "" {
				return nil
			}
			return []string{subnet.Spec.Vpc}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for Subnet.spec.vpc: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauv1alpha1.Subnet{}).
		Watches(&juneauv1alpha1.Vpc{}, handler.EnqueueRequestsFromMapFunc(r.mapVpcToSubnets)).
		Watches(&juneauv1alpha1.AllocationClaim{}, handler.EnqueueRequestsFromMapFunc(r.mapClaimToSubnets)).
		Watches(&juneauv1alpha1.NetworkACL{}, handler.EnqueueRequestsFromMapFunc(r.mapNetworkACLToSubnets)).
		Named("subnet").
		Complete(r)
}

func (r *SubnetReconciler) ensureNumberClaim(ctx context.Context, subnet *juneauv1alpha1.Subnet, poolName string, gvk schema.GroupVersionKind, attribute string) (*juneauv1alpha1.AllocationClaim, error) {
	claim := newAllocationClaim(poolName, gvk, "", subnet.Name, attribute)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, claim, func() error {
		claim.Spec = newAllocationClaim(poolName, gvk, "", subnet.Name, attribute).Spec
		return controllerutil.SetControllerReference(subnet, claim, r.Scheme)
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

func (r *SubnetReconciler) mapVpcToSubnets(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}

	var subnetList juneauv1alpha1.SubnetList
	if err := r.List(ctx, &subnetList, client.MatchingFields{"spec.vpc": vpc.Name}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(subnetList.Items))
	for _, subnet := range subnetList.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: subnet.Name}})
	}
	return requests
}

func (r *SubnetReconciler) mapClaimToSubnets(ctx context.Context, obj client.Object) []reconcile.Request {
	_ = ctx
	claim, ok := obj.(*juneauv1alpha1.AllocationClaim)
	if !ok || claim.Spec.ResourceRef.Kind != "Subnet" || claim.Spec.ResourceRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.ResourceRef.Name}}}
}

// mapNetworkACLToSubnets fans NetworkACL changes (status.aclID
// allocation, status.rulesetVersion bumps) out to Subnets that
// reference the ACL so they re-resolve their status.networkACL view.
func (r *SubnetReconciler) mapNetworkACLToSubnets(ctx context.Context, obj client.Object) []reconcile.Request {
	acl, ok := obj.(*juneauv1alpha1.NetworkACL)
	if !ok {
		return nil
	}
	var subnets juneauv1alpha1.SubnetList
	if err := r.List(ctx, &subnets); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(subnets.Items))
	for i := range subnets.Items {
		s := &subnets.Items[i]
		if s.Spec.NetworkACL != acl.Name {
			continue
		}
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: s.Name}})
	}
	return reqs
}

// updateStatus writes the desired SubnetStatus to the apiserver, after
// folding in ObservedGeneration and the Ready condition. The full status
// is passed in as a value so every reconcile branch carries an explicit,
// auditable view of what status it intends to publish — adding new fields
// (DNS, DNSMAC, ...) does not require touching every call site.
func (r *SubnetReconciler) updateStatus(ctx context.Context, subnet *juneauv1alpha1.Subnet, desired juneauv1alpha1.SubnetStatus, status metav1.ConditionStatus, reason, message string) error {
	updated := subnet.DeepCopy()
	updated.Status = desired
	updated.Status.Conditions = subnet.Status.Conditions // start from existing conditions to preserve transition times
	updated.Status.ObservedGeneration = updated.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.SubnetStatusReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: updated.Generation,
	})

	if updated.Status.ObservedGeneration == subnet.Status.ObservedGeneration &&
		updated.Status.VNI == subnet.Status.VNI &&
		updated.Status.Gateway == subnet.Status.Gateway &&
		updated.Status.GatewayMAC == subnet.Status.GatewayMAC &&
		updated.Status.DNS == subnet.Status.DNS &&
		updated.Status.DNSMAC == subnet.Status.DNSMAC &&
		reflect.DeepEqual(updated.Status.NetworkACL, subnet.Status.NetworkACL) &&
		reflect.DeepEqual(updated.Status.Conditions, subnet.Status.Conditions) {
		return nil
	}

	subnet.Status = updated.Status
	return r.Status().Update(ctx, subnet)
}

func nextGateway(cidr *net.IPNet) string {
	ip := cidr.IP.Mask(cidr.Mask).To4()
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	return ip.String()
}

// nextDNSAddress returns the per-Subnet virtual DNS resolver IP — the
// second usable address in the prefix, conventionally `.2`. The empty
// string is returned when the prefix is too narrow for a `.2` to fall
// within its usable range (e.g. /31 or /32, where there is no room for
// anything beyond the gateway / point-to-point endpoints). Callers
// treat empty as "this Subnet has no virtual DNS service".
func nextDNSAddress(cidr *net.IPNet) string {
	if cidr == nil || cidr.IP.To4() == nil {
		return ""
	}
	prefix, err := netip.ParsePrefix(cidr.String())
	if err != nil {
		return ""
	}
	prefix = prefix.Masked()

	// .1 (gateway), .2 (DNS).
	addr := prefix.Addr().Next().Next()
	if !prefix.Contains(addr) {
		return ""
	}
	if !addressIsUsableInPrefix(addr, prefix) {
		return ""
	}
	return addr.String()
}

func newLAA() (net.HardwareAddr, error) {
	mac := make([]byte, 6)
	if _, err := rand.Read(mac); err != nil {
		return nil, err
	}

	// bit0: I/G (0 = unicast)
	// bit1: U/L (1 = locally administered)
	mac[0] &^= 0x01 // clear I/G
	mac[0] |= 0x02  // set U/L

	return net.HardwareAddr(mac), nil
}
