package controller

import (
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var allocationNameSanitizer = regexp.MustCompile(`[^a-z0-9.-]+`)

const (
	allocationPoolSubnetVNI                = "subnet-vni"
	allocationPoolRouteTableID             = "route-table-id"
	allocationPoolVpcID                    = "vpc-id"
	allocationPoolNATGatewayID             = "nat-gateway-id"
	allocationPoolSecurityGroupID          = "security-group-id"
	allocationPoolNetworkACLID             = "network-acl-id"
	allocationPoolTransitGatewayRouteTable = "transit-gateway-route-table-id"
)

// allocationClaimName composes a deterministic claim name from the
// (pool, kind, namespace, name, attribute) tuple. Namespace may be empty for
// cluster-scoped owners.
func allocationClaimName(poolName string, gvk schema.GroupVersionKind, namespace, resourceName, attribute string) string {
	parts := []string{poolName, gvk.Kind, namespace, resourceName, attribute}
	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
		parts[i] = strings.ReplaceAll(parts[i], ".", "-")
		parts[i] = allocationNameSanitizer.ReplaceAllString(parts[i], "-")
		parts[i] = strings.Trim(parts[i], "-.")
	}
	// Drop empty namespace segment to keep names compact for cluster-scoped owners.
	out := parts[0] + "--" + parts[1] + "--"
	if parts[2] != "" {
		out += parts[2] + "--"
	}
	out += parts[3] + "--" + parts[4]
	return out
}

func newAllocationClaim(poolName string, gvk schema.GroupVersionKind, namespace, resourceName, attribute string) *juneauv1alpha1.AllocationClaim {
	claim := &juneauv1alpha1.AllocationClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: allocationClaimName(poolName, gvk, namespace, resourceName, attribute),
		},
		Spec: juneauv1alpha1.AllocationClaimSpec{
			PoolRefs: []juneauv1alpha1.AllocationPoolReference{{Name: poolName}},
			ResourceRef: juneauv1alpha1.AllocationResourceReference{
				APIVersion: gvk.GroupVersion().String(),
				Kind:       gvk.Kind,
				Namespace:  namespace,
				Name:       resourceName,
			},
			Attribute: attribute,
		},
	}
	return claim
}

// leaseNameFor returns the AllocationLease name that backs a claim. The
// reuse key decouples the reservation from the claim's own name, which lets
// a workload keep its value across recreations that rename the claim.
func leaseNameFor(claim *juneauv1alpha1.AllocationClaim) string {
	if claim.Spec.ReuseKey != "" {
		return claim.Spec.ReuseKey
	}
	return claim.Name
}

// leaseOwnedByClaim reports whether the claim is the recorded holder of the
// lease. Claim names are unique at any point in time, so the name alone
// identifies the holder; a claim re-created under the same name is the same
// holder and keeps its value even though its UID changed.
func leaseOwnedByClaim(lease *juneauv1alpha1.AllocationLease, claim *juneauv1alpha1.AllocationClaim) bool {
	return lease.Spec.ClaimRef.Name == claim.Name
}

// leaseHeldByOtherClaim reports whether another claim holds the lease and has
// not been deleted yet. Such a lease is off limits: taking it would hand the
// same value to two live claims.
func leaseHeldByOtherClaim(lease *juneauv1alpha1.AllocationLease, claim *juneauv1alpha1.AllocationClaim) bool {
	return !leaseOwnedByClaim(lease, claim) && lease.Spec.OwnerDeletionTimestamp.IsZero()
}

// claimReferencesPool reports whether the claim lists the given pool among
// its candidates.
func claimReferencesPool(claim *juneauv1alpha1.AllocationClaim, poolName string) bool {
	for _, ref := range claim.Spec.PoolRefs {
		if ref.Name == poolName {
			return true
		}
	}
	return false
}
