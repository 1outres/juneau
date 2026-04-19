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
)

func allocationClaimName(poolName string, gvk schema.GroupVersionKind, resourceName, attribute string) string {
	parts := []string{poolName, gvk.Kind, resourceName, attribute}
	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
		parts[i] = strings.ReplaceAll(parts[i], ".", "-")
		parts[i] = allocationNameSanitizer.ReplaceAllString(parts[i], "-")
		parts[i] = strings.Trim(parts[i], "-.")
	}
	return fmt.Sprintf("%s--%s--%s--%s", parts[0], parts[1], parts[2], parts[3])
}

func newAllocationClaim(poolName string, gvk schema.GroupVersionKind, resourceName, attribute string) *juneauv1alpha1.AllocationClaim {
	claim := &juneauv1alpha1.AllocationClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: allocationClaimName(poolName, gvk, resourceName, attribute),
		},
		Spec: juneauv1alpha1.AllocationClaimSpec{
			PoolRef: juneauv1alpha1.AllocationPoolReference{Name: poolName},
			ResourceRef: juneauv1alpha1.AllocationResourceReference{
				APIVersion: gvk.GroupVersion().String(),
				Kind:       gvk.Kind,
				Name:       resourceName,
			},
			Attribute: attribute,
		},
	}
	return claim
}
