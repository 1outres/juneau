package controller

import (
	"fmt"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var allocationNameSanitizer = regexp.MustCompile(`[^a-z0-9.-]+`)

const (
	allocationPoolSubnetVNI    = "subnet-vni"
	allocationPoolRouteTableID = "route-table-id"
	allocationPoolVpcID        = "vpc-id"
	allocationPoolNATGatewayID = "nat-gateway-id"
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

// primaryPoolRef returns the first poolRef name for compatibility with
// reconcilers that operate on a single pool.
func primaryPoolRef(claim *juneauv1alpha1.AllocationClaim) string {
	if len(claim.Spec.PoolRefs) == 0 {
		return ""
	}
	return claim.Spec.PoolRefs[0].Name
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

// poolRefNamesFromClaim extracts the list of candidate pool names declared
// on the claim, preserving order.
func poolRefNamesFromClaim(claim *juneauv1alpha1.AllocationClaim) []string {
	out := make([]string, 0, len(claim.Spec.PoolRefs))
	for _, ref := range claim.Spec.PoolRefs {
		out = append(out, ref.Name)
	}
	return out
}

func fmtClaimMissingPool(name string) string {
	return fmt.Sprintf("pool %q not found", name)
}
