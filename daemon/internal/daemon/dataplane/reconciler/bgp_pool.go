package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// BgpPool keeps podEgress.BgpAddressPools in sync with the set of
// AddressPools referenced by BGPAdvertisements. It runs with SingletonKey
// because the desired state is a function of all AddressPool and
// BGPAdvertisement objects, not any single one.
type BgpPool struct {
	client    client.Client
	podEgress *program.PodEgress

	mu   sync.Mutex
	last map[string]bpf.PodEgressBgpAddressPoolsKey
}

func NewBgpPool(cl client.Client, podEgress *program.PodEgress) *BgpPool {
	return &BgpPool{
		client:    cl,
		podEgress: podEgress,
		last:      make(map[string]bpf.PodEgressBgpAddressPoolsKey),
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

	r.mu.Lock()
	defer r.mu.Unlock()

	for key, oldKey := range r.last {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := r.podEgress.Objs.BgpAddressPools.Delete(&oldKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete bgp_address_pools entry %s: %w", key, err)
		}
	}

	var one uint8 = 1
	for key, newKey := range desired {
		if oldKey, ok := r.last[key]; ok && oldKey == newKey {
			continue
		}
		if err := r.podEgress.Objs.BgpAddressPools.Update(&newKey, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update bgp_address_pools entry %s: %w", key, err)
		}
	}

	r.last = desired
	zap.S().Infof("bgp-pool: reconciled %d entries", len(desired))
	return nil
}

func (r *BgpPool) buildDesired(ctx context.Context) (map[string]bpf.PodEgressBgpAddressPoolsKey, []string, error) {
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

	desired := make(map[string]bpf.PodEgressBgpAddressPoolsKey)
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
			key, canonical, err := parseBGPAddressPoolPrefix(raw)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AddressPool/%s: invalid address %q: %v", pool.Name, raw, err))
				continue
			}
			desired[canonical] = key
		}
	}

	return desired, warnings, nil
}

func parseBGPAddressPoolPrefix(raw string) (bpf.PodEgressBgpAddressPoolsKey, string, error) {
	var key bpf.PodEgressBgpAddressPoolsKey

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return key, "", fmt.Errorf("empty address")
	}

	var (
		ip    net.IP
		ipnet *net.IPNet
		err   error
	)
	if strings.Contains(raw, "/") {
		ip, ipnet, err = net.ParseCIDR(raw)
		if err != nil {
			return key, "", err
		}
		ip = ip.Mask(ipnet.Mask)
		ipnet.IP = ip
	} else {
		ip = net.ParseIP(raw)
		if ip == nil {
			return key, "", fmt.Errorf("invalid IP address")
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return key, "", fmt.Errorf("IPv6 is not supported")
		}
		ip = ip4
		ipnet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return key, "", fmt.Errorf("IPv6 is not supported")
	}

	addr, err := convert.IPv4ToLPMTrieUint32(ip4)
	if err != nil {
		return key, "", err
	}
	prefixlen, _ := ipnet.Mask.Size()
	key.Prefixlen = uint32(prefixlen)
	key.Addr = addr

	return key, ipnet.String(), nil
}
