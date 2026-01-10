package speaker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	bgptypes "github.com/1outres/juneau/bgp-speaker/internal/types"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func reconcileOnce(ctx context.Context, nodeName string, cl client.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var pools juneauv1alpha1.AddressPoolList
	if err := cl.List(ctx, &pools); err != nil {
		return fmt.Errorf("list AddressPool: %w", err)
	}

	var advs juneauv1alpha1.BGPAdvertisementList
	if err := cl.List(ctx, &advs); err != nil {
		return fmt.Errorf("list BGPAdvertisement: %w", err)
	}

	var peers juneauv1alpha1.BGPPeerList
	if err := cl.List(ctx, &peers); err != nil {
		return fmt.Errorf("list BGPPeer: %w", err)
	}

	desired, warnings := buildDesiredConfig(nodeName, &pools, &advs, &peers)
	for _, w := range warnings {
		zap.S().Warnw("ignored invalid bgp resource/config", "nodeName", nodeName, "warning", w)
	}

	zap.S().Infow(
		"reconciled (desired config built)",
		"nodeName", nodeName,
		"addressPools", len(pools.Items),
		"bgpAdvertisements", len(advs.Items),
		"bgpPeers", len(peers.Items),
		"desiredPeers", len(desired.Peers),
		"desiredPrefixes", countDesiredPrefixes(desired),
	)

	if b, err := json.Marshal(desiredConfigForLog(desired)); err != nil {
		zap.S().Warnw("marshal desired config failed", "nodeName", nodeName, "error", err)
	} else {
		zap.S().Debugw("desired config", "nodeName", nodeName, "desiredConfig", string(b))
	}

	return nil
}

type desiredConfigLog struct {
	Peers []desiredPeerLog `json:"peers"`
}

type desiredPeerLog struct {
	LocalASN  uint32   `json:"localASN"`
	RemoteIP  string   `json:"remoteIP"`
	RemoteASN uint32   `json:"remoteASN"`
	Prefixes  []string `json:"prefixes"`
}

func desiredConfigForLog(cfg *bgptypes.DesiredConfig) desiredConfigLog {
	if cfg == nil || len(cfg.Peers) == 0 {
		return desiredConfigLog{}
	}

	out := desiredConfigLog{
		Peers: make([]desiredPeerLog, 0, len(cfg.Peers)),
	}

	for _, p := range cfg.Peers {
		var prefixes []string
		for _, ipnet := range p.Prefixes {
			if ipnet == nil {
				continue
			}
			prefixes = append(prefixes, ipnet.String())
		}
		sort.Strings(prefixes)

		out.Peers = append(out.Peers, desiredPeerLog{
			LocalASN:  p.LocalASN,
			RemoteIP:  p.RemoteIP,
			RemoteASN: p.RemoteASN,
			Prefixes:  prefixes,
		})
	}

	return out
}

func buildDesiredConfig(
	nodeName string,
	pools *juneauv1alpha1.AddressPoolList,
	advs *juneauv1alpha1.BGPAdvertisementList,
	peers *juneauv1alpha1.BGPPeerList,
) (*bgptypes.DesiredConfig, []string) {
	_ = nodeName

	var warnings []string

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

	prefixes, prefixWarnings := buildPrefixes(poolsByName, referencedPools)
	warnings = append(warnings, prefixWarnings...)

	desiredPeers := make([]*bgptypes.Peer, 0, len(peers.Items))
	for i := range peers.Items {
		p := &peers.Items[i]

		remoteIP := strings.TrimSpace(p.Spec.PeerAddress)
		if remoteIP == "" {
			warnings = append(warnings, fmt.Sprintf("BGPPeer/%s: spec.peerAddress is empty", p.Name))
			continue
		}
		if p.Spec.MyASN == 0 {
			warnings = append(warnings, fmt.Sprintf("BGPPeer/%s: spec.myASN is 0", p.Name))
			continue
		}
		if p.Spec.PeerASN == 0 {
			warnings = append(warnings, fmt.Sprintf("BGPPeer/%s: spec.peerASN is 0", p.Name))
			continue
		}

		peer := &bgptypes.Peer{
			LocalASN:  p.Spec.MyASN,
			RemoteIP:  remoteIP,
			RemoteASN: p.Spec.PeerASN,
			Prefixes:  append([]*net.IPNet(nil), prefixes...),
		}
		desiredPeers = append(desiredPeers, peer)
	}

	sort.Slice(desiredPeers, func(i, j int) bool {
		if desiredPeers[i].RemoteIP != desiredPeers[j].RemoteIP {
			return desiredPeers[i].RemoteIP < desiredPeers[j].RemoteIP
		}
		if desiredPeers[i].RemoteASN != desiredPeers[j].RemoteASN {
			return desiredPeers[i].RemoteASN < desiredPeers[j].RemoteASN
		}
		return desiredPeers[i].LocalASN < desiredPeers[j].LocalASN
	})

	return &bgptypes.DesiredConfig{Peers: desiredPeers}, warnings
}

func buildPrefixes(
	poolsByName map[string]*juneauv1alpha1.AddressPool,
	referencedPools map[string]struct{},
) ([]*net.IPNet, []string) {
	var warnings []string

	var poolNames []string
	for name := range referencedPools {
		poolNames = append(poolNames, name)
	}
	sort.Strings(poolNames)

	unique := make(map[string]*net.IPNet)

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
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}

			ipnet, err := parsePrefix(raw)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AddressPool/%s: invalid address %q: %v", pool.Name, raw, err))
				continue
			}

			key := ipnet.String()
			unique[key] = ipnet
		}
	}

	var keys []string
	for k := range unique {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]*net.IPNet, 0, len(keys))
	for _, k := range keys {
		out = append(out, unique[k])
	}
	return out, warnings
}

func parsePrefix(s string) (*net.IPNet, error) {
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

func countDesiredPrefixes(cfg *bgptypes.DesiredConfig) int {
	if cfg == nil || len(cfg.Peers) == 0 {
		return 0
	}
	return len(cfg.Peers[0].Prefixes)
}
