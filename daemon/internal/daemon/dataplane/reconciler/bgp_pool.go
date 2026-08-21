package reconciler

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/ownedaddr"
)

const (
	bgpPoolScope = "bgp-pool"
	bgpPoolOwner = "address-pools"
)

// BgpPool claims the prefixes of every AddressPool referenced by a
// BGPAdvertisement in external_address_pools. It runs with SingletonKey
// because the desired state is a function of all AddressPool and
// BGPAdvertisement objects, not any single one.
type BgpPool struct {
	client client.Client
	owned  *ownedaddr.Scope
}

func NewBgpPool(cl client.Client, owned *ownedaddr.Store) *BgpPool {
	return &BgpPool{
		client: cl,
		owned:  owned.Scope(bgpPoolScope),
	}
}

func (r *BgpPool) Name() string { return "bgp-pool" }

func (r *BgpPool) Reconcile(ctx context.Context, _ string) error {
	desired, warnings, err := r.buildDesired(ctx)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		zap.S().Warn(w)
	}

	if err := r.owned.Set(bgpPoolOwner, desired); err != nil {
		return err
	}

	zap.S().Infof("bgp-pool: reconciled %d entries", len(desired))
	return nil
}

func (r *BgpPool) buildDesired(ctx context.Context) ([]ownedaddr.Key, []string, error) {
	var pools juneauv1alpha1.AddressPoolList
	if err := r.client.List(ctx, &pools); err != nil {
		return nil, nil, fmt.Errorf("list AddressPools: %w", err)
	}

	var advs juneauv1alpha1.BGPAdvertisementList
	if err := r.client.List(ctx, &advs); err != nil {
		return nil, nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}

	poolsByName := make(map[string]*juneauv1alpha1.AddressPool, len(pools.Items))
	for i := range pools.Items {
		pool := &pools.Items[i]
		poolsByName[pool.Name] = pool
	}

	referencedPools := make(map[string]struct{})
	for i := range advs.Items {
		adv := &advs.Items[i]
		for _, poolName := range adv.Spec.AddressPools {
			poolName = strings.TrimSpace(poolName)
			if poolName == "" {
				continue
			}
			referencedPools[poolName] = struct{}{}
		}
	}

	poolNames := make([]string, 0, len(referencedPools))
	for name := range referencedPools {
		poolNames = append(poolNames, name)
	}
	sort.Strings(poolNames)

	var desired []ownedaddr.Key
	seen := make(map[ownedaddr.Key]struct{})
	var warnings []string
	for _, poolName := range poolNames {
		pool, ok := poolsByName[poolName]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("BGPAdvertisement references missing AddressPool/%s", poolName))
			continue
		}
		if pool.Spec.AdvertiseMode != juneauv1alpha1.AddressPoolAdvertiseModeBGP {
			warnings = append(warnings, fmt.Sprintf("AddressPool/%s: spec.advertiseMode=%q is not bgp", pool.Name, pool.Spec.AdvertiseMode))
			continue
		}

		for _, raw := range pool.Spec.Addresses {
			key, err := ownedaddr.ParsePrefix(raw)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AddressPool/%s: invalid address %q: %v", pool.Name, raw, err))
				continue
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			desired = append(desired, key)
		}
	}

	return desired, warnings, nil
}
