package dns

import (
	"context"
	"fmt"
	"strconv"

	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const cachedVPCIDIndexField = "status.vpcID"

// CachedVPCResolver implements VPCResolver with exact cached Vpc ID lookups.
type CachedVPCResolver struct {
	client client.Client
}

// RegisterVPCResolverIndex registers the exact Vpc ID lookup used by CachedVPCResolver.
func RegisterVPCResolverIndex(ctx context.Context, indexer client.FieldIndexer) error {
	if err := indexer.IndexField(ctx, &juneauv1alpha1.Vpc{}, cachedVPCIDIndexField, vpcIDIndexValues); err != nil {
		return fmt.Errorf("index Vpc by status.vpcID: %w", err)
	}
	return nil
}

// NewCachedVPCResolver constructs a resolver bound to an indexed cached client.
func NewCachedVPCResolver(cl client.Client) *CachedVPCResolver {
	return &CachedVPCResolver{client: cl}
}

// LookupByID returns one unambiguous cached Vpc match and its Service policy.
func (r *CachedVPCResolver) LookupByID(ctx context.Context, vpcID uint32) (string, bool, bool, bool) {
	if vpcID == 0 {
		return "", false, false, false
	}
	var list juneauv1alpha1.VpcList
	if err := r.client.List(ctx, &list, client.MatchingFields{
		cachedVPCIDIndexField: vpcIDIndexKey(vpcID),
	}); err != nil || len(list.Items) != 1 {
		return "", false, false, false
	}
	vpc := &list.Items[0]
	return vpc.Name, vpc.Spec.ServiceEnabled(), vpc.Spec.Service.Consumes(), true
}

func vpcIDIndexValues(object client.Object) []string {
	vpcID := object.(*juneauv1alpha1.Vpc).Status.VpcID
	if vpcID == 0 {
		return nil
	}
	return []string{vpcIDIndexKey(vpcID)}
}

func vpcIDIndexKey(vpcID uint32) string {
	return strconv.FormatUint(uint64(vpcID), 10)
}
