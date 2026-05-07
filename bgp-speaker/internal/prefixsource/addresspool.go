package prefixsource

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// AddressPoolAdvertisementSource is the original Juneau prefix
// source: each BGPAdvertisement names a list of AddressPools, and
// each pool contributes its CIDRs (or the advertisement's spec.prefix
// override). Pools must be in BGP advertise mode; ARP-mode pools are
// skipped with a recorded error.
//
// The source intentionally does its own per-node filtering
// (BGPAdvertisement.spec.nodeName) so that BGPAdvertisements that
// pin to other nodes do not surface as warnings on this node.
type AddressPoolAdvertisementSource struct{}

const addressPoolSourceName = "addresspool-advertisement"

// Name implements Source.
func (AddressPoolAdvertisementSource) Name() string { return addressPoolSourceName }

// Build implements Source. The function lists AddressPools and
// BGPAdvertisements, projects them through the original Juneau
// semantics, and returns the result as a slice of
// SourceAdvertisements (one per AddressPool, dedup-merged across
// BGPAdvertisements that target the same pool).
func (AddressPoolAdvertisementSource) Build(ctx context.Context, in Input) (Result, error) {
	var pools juneauv1alpha1.AddressPoolList
	if err := in.Client.List(ctx, &pools); err != nil {
		return Result{}, fmt.Errorf("list AddressPool: %w", err)
	}
	var advs juneauv1alpha1.BGPAdvertisementList
	if err := in.Client.List(ctx, &advs); err != nil {
		return Result{}, fmt.Errorf("list BGPAdvertisement: %w", err)
	}

	poolsByName := make(map[string]*juneauv1alpha1.AddressPool, len(pools.Items))
	for i := range pools.Items {
		pool := &pools.Items[i]
		poolsByName[pool.Name] = pool
	}

	relevant := relevantBGPAdvertisements(advs.Items, in.NodeName)

	var errs []nodestate.ResourceError
	addErr := func(kind, name, msg string) {
		errs = append(errs, nodestate.ResourceError{
			ResourceKind: kind,
			ResourceName: name,
			Message:      msg,
		})
	}

	merged := mergeAddressPoolAdvertisements(poolsByName, relevant, addErr)

	advertisements := make([]SourceAdvertisement, 0, len(merged))
	for _, e := range merged {
		advertisements = append(advertisements, SourceAdvertisement{
			SourceKind:  "BGPAdvertisement",
			SourceName:  e.advertisementName,
			AddressPool: e.pool,
			Prefixes:    e.prefixes,
		})
	}
	// Stable order: by pool, then by representative advertisement
	// name. Two sources contributing to the same pool collapse onto
	// a single SourceAdvertisement entry already.
	sort.Slice(advertisements, func(i, j int) bool {
		if advertisements[i].AddressPool != advertisements[j].AddressPool {
			return advertisements[i].AddressPool < advertisements[j].AddressPool
		}
		return advertisements[i].SourceName < advertisements[j].SourceName
	})

	return Result{
		Advertisements: advertisements,
		Errors:         errs,
	}, nil
}

// relevantBGPAdvertisements applies the per-node filter that the
// original speaker code applied: an advertisement with a non-empty
// spec.nodeName only counts for the node it names.
func relevantBGPAdvertisements(advs []juneauv1alpha1.BGPAdvertisement, nodeName string) []*juneauv1alpha1.BGPAdvertisement {
	out := make([]*juneauv1alpha1.BGPAdvertisement, 0, len(advs))
	for i := range advs {
		adv := &advs[i]
		if adv.Spec.NodeName != "" && adv.Spec.NodeName != nodeName {
			continue
		}
		out = append(out, adv)
	}
	return out
}

// mergedEntry is the per-AddressPool aggregation of relevant
// BGPAdvertisements. The advertisementName field records the
// last-seen advertisement that touched the pool; ties are broken
// lexicographically so the output is stable. The single name is
// purely informational — the source kind and address pool are the
// authoritative join keys for status.
type mergedEntry struct {
	pool              string
	prefixes          []*net.IPNet
	advertisementName string
}

func mergeAddressPoolAdvertisements(
	poolsByName map[string]*juneauv1alpha1.AddressPool,
	advs []*juneauv1alpha1.BGPAdvertisement,
	addErr func(kind, name, msg string),
) []*mergedEntry {
	merged := make(map[string]*mergedEntry)
	addToMerged := func(poolName, advName string, prefixes []*net.IPNet) {
		e, ok := merged[poolName]
		if !ok {
			e = &mergedEntry{pool: poolName, advertisementName: advName}
			merged[poolName] = e
		} else if advName != "" && (e.advertisementName == "" || advName < e.advertisementName) {
			e.advertisementName = advName
		}
		seen := map[string]struct{}{}
		for _, p := range e.prefixes {
			seen[p.String()] = struct{}{}
		}
		for _, p := range prefixes {
			key := p.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			e.prefixes = append(e.prefixes, p)
		}
		sort.Slice(e.prefixes, func(i, j int) bool { return e.prefixes[i].String() < e.prefixes[j].String() })
	}

	for _, adv := range advs {
		for _, raw := range adv.Spec.AddressPools {
			poolName := strings.TrimSpace(raw)
			if poolName == "" {
				continue
			}
			pool, ok := poolsByName[poolName]
			if !ok {
				addErr("AddressPool", poolName, "referenced by BGPAdvertisement but not found")
				continue
			}
			if pool.Spec.AdvertiseMode != juneauv1alpha1.AddressPoolAdvertiseModeBGP {
				addErr("AddressPool", pool.Name, fmt.Sprintf("spec.advertiseMode=%q is not bgp", pool.Spec.AdvertiseMode))
				continue
			}

			prefixes := poolPrefixesForAdvertisement(pool, adv, addErr)
			if len(prefixes) == 0 {
				// Either the override was invalid (already recorded)
				// or the pool has no usable address; do not register
				// an empty entry to avoid a noisy "0 prefixes" status.
				continue
			}
			addToMerged(pool.Name, adv.Name, prefixes)
		}
	}

	out := make([]*mergedEntry, 0, len(merged))
	for _, e := range merged {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pool < out[j].pool })
	return out
}

// poolPrefixesForAdvertisement returns the CIDR list a single
// (advertisement, pool) pair contributes. Honours the spec.prefix
// override when set; falls back to pool.spec.addresses otherwise.
func poolPrefixesForAdvertisement(
	pool *juneauv1alpha1.AddressPool,
	adv *juneauv1alpha1.BGPAdvertisement,
	addErr func(kind, name, msg string),
) []*net.IPNet {
	if adv.Spec.Prefix != "" {
		ipnet, err := ParsePrefix(strings.TrimSpace(adv.Spec.Prefix))
		if err != nil {
			addErr("BGPAdvertisement", adv.Name, fmt.Sprintf("invalid spec.prefix %q: %v", adv.Spec.Prefix, err))
			return nil
		}
		return []*net.IPNet{ipnet}
	}

	out := make([]*net.IPNet, 0, len(pool.Spec.Addresses))
	seen := map[string]struct{}{}
	for _, raw := range pool.Spec.Addresses {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ipnet, err := ParsePrefix(raw)
		if err != nil {
			addErr("AddressPool", pool.Name, fmt.Sprintf("invalid address %q: %v", raw, err))
			continue
		}
		key := ipnet.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ipnet)
	}
	return out
}

// ParsePrefix turns a CIDR or bare IP string into a canonical IPNet
// (network address + prefix length). Exposed for use by other Source
// implementations and tests; behaviour matches the original
// speaker.parsePrefix for backward compatibility.
func ParsePrefix(s string) (*net.IPNet, error) {
	if strings.Contains(s, "/") {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		ipnet.IP = ip.Mask(ipnet.Mask)
		return ipnet, nil
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("not an IP or CIDR")
	}

	if ip.To4() != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}
