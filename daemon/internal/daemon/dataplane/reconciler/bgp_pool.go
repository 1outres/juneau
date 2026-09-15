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
//
// Each claim also says which node the network delivers the prefix to.
// An advertisement for every node, or pinned to this one, delivers the
// whole pool here. An advertisement pinned to another node delivers its
// prefix there: the ExternalNetworkAttachment controller advertises the
// NAPT address of each node as a /32 of that node alone, and the router
// prefers it to a pool every node advertises. node_ingress handles both
// kinds alike; pod_egress only sends a packet for a prefix delivered here
// through node_ingress, so the reply to another node's NATGateway leaves
// for that node instead of being dropped on this one.
type BgpPool struct {
	client   client.Client
	owned    *ownedaddr.Scope
	nodeName string
}

func NewBgpPool(cl client.Client, owned *ownedaddr.Store, nodeName string) *BgpPool {
	return &BgpPool{
		client:   cl,
		owned:    owned.Scope(bgpPoolScope),
		nodeName: nodeName,
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

	if err := r.owned.SetClaims(bgpPoolOwner, desired); err != nil {
		return err
	}

	zap.S().Infof("bgp-pool: reconciled %d entries", len(desired))
	return nil
}

func (r *BgpPool) buildDesired(ctx context.Context) ([]ownedaddr.Claim, []string, error) {
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

	sort.Slice(advs.Items, func(i, j int) bool { return advs.Items[i].Name < advs.Items[j].Name })

	desired := make(map[ownedaddr.Key]ownedaddr.Delivery)
	warned := make(map[string]struct{})
	var warnings []string
	warn := func(message string) {
		if _, seen := warned[message]; seen {
			return
		}
		warned[message] = struct{}{}
		warnings = append(warnings, message)
	}

	for i := range advs.Items {
		adv := &advs.Items[i]
		delivery := r.deliveryOf(adv)
		for _, poolName := range adv.Spec.AddressPools {
			poolName = strings.TrimSpace(poolName)
			if poolName == "" {
				continue
			}
			pool, ok := poolsByName[poolName]
			if !ok {
				warn(fmt.Sprintf("BGPAdvertisement references missing AddressPool/%s", poolName))
				continue
			}
			if pool.Spec.AdvertiseMode != juneauv1alpha1.AddressPoolAdvertiseModeBGP {
				warn(fmt.Sprintf("AddressPool/%s: spec.advertiseMode=%q is not bgp", pool.Name, pool.Spec.AdvertiseMode))
				continue
			}

			for _, raw := range claimedPrefixes(adv, pool, delivery) {
				key, err := ownedaddr.ParsePrefix(raw)
				if err != nil {
					warn(fmt.Sprintf("AddressPool/%s: invalid address %q: %v", pool.Name, raw, err))
					continue
				}
				if desired[key] != ownedaddr.DeliveredHere {
					desired[key] = delivery
				}
			}
		}
	}

	claims := make([]ownedaddr.Claim, 0, len(desired))
	for key, delivery := range desired {
		claims = append(claims, ownedaddr.Claim{Key: key, Delivery: delivery})
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].Key.String() < claims[j].Key.String() })
	return claims, warnings, nil
}

// deliveryOf reads which node the network delivers what an advertisement
// announces to.
func (r *BgpPool) deliveryOf(adv *juneauv1alpha1.BGPAdvertisement) ownedaddr.Delivery {
	if adv.Spec.NodeName == "" || adv.Spec.NodeName == r.nodeName {
		return ownedaddr.DeliveredHere
	}
	return ownedaddr.DeliveredElsewhere
}

// claimedPrefixes lists what one advertisement claims out of one pool.
//
// Delivered here, it is the whole pool, even when the advertisement names
// a narrower prefix: node_ingress has always owned the whole pool of an
// advertisement it serves, and a packet for the rest of it is dropped
// rather than handed to the host stack. Delivered elsewhere, it is only
// what the other node announces, since that is all the router sends there
// instead of here.
func claimedPrefixes(adv *juneauv1alpha1.BGPAdvertisement, pool *juneauv1alpha1.AddressPool, delivery ownedaddr.Delivery) []string {
	if delivery == ownedaddr.DeliveredElsewhere && strings.TrimSpace(adv.Spec.Prefix) != "" {
		return []string{adv.Spec.Prefix}
	}
	return pool.Spec.Addresses
}
