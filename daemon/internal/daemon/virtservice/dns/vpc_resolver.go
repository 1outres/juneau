package dns

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// CachedVPCResolver implements VPCResolver by listing Vpcs from a
// controller-runtime cached client and matching on Status.VpcID. The
// cache makes this O(N_vpcs) per lookup; in practice N is tiny.
//
// Returning a cached client (not a custom indexed snapshot) lets the
// daemon's existing informer wiring be the single source of truth for
// Vpc state — no extra goroutine, no separate sync barrier.
type CachedVPCResolver struct {
	client client.Client
}

// NewCachedVPCResolver constructs a resolver bound to the supplied
// client (must be backed by an informer cache that watches Vpc).
func NewCachedVPCResolver(cl client.Client) *CachedVPCResolver {
	return &CachedVPCResolver{client: cl}
}

// LookupByID scans the cached Vpc list for a match on Status.VpcID and
// returns its name + enableService bit. Reports ok=false when no Vpc
// in cache matches; the handler then answers ServerFailure rather than
// risk applying policy with a bogus identity.
func (r *CachedVPCResolver) LookupByID(ctx context.Context, vpcID uint32) (string, bool, bool) {
	if vpcID == 0 {
		return "", false, false
	}
	var list juneauv1alpha1.VpcList
	if err := r.client.List(ctx, &list); err != nil {
		return "", false, false
	}
	for i := range list.Items {
		if list.Items[i].Status.VpcID == vpcID {
			return list.Items[i].Name, list.Items[i].Spec.EnableService, true
		}
	}
	return "", false, false
}
