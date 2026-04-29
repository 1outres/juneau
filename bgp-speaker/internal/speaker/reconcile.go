package speaker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/1outres/juneau/bgp-speaker/internal/bird"
	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
	"github.com/1outres/juneau/bgp-speaker/internal/peerindex"
	bgptypes "github.com/1outres/juneau/bgp-speaker/internal/types"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReconcileResult bundles everything produced by a single pass over the
// BGP-related custom resources: the bird desired config, the advertisement
// intent, the PeerAddress→BGPPeer name index, and spec-level errors.
type ReconcileResult struct {
	Desired            *bgptypes.DesiredConfig
	Advertisements     []nodestate.Advertisement
	PeerNamesByAddress map[string]string
	Errors             []nodestate.ResourceError
	// Warnings is the Errors list rendered as human-readable strings for logs.
	Warnings []string
}

type Reconciler struct {
	nodeName  string
	client    client.Client
	builder   bird.ConfigBuilder
	process   *bird.ProcessManager
	peerIndex *peerindex.PeerIndex

	mu         sync.Mutex
	lastHash   []byte
	lastSync   time.Time
	lastAdvs   []nodestate.Advertisement
	lastErrors []nodestate.ResourceError
	nowFn      func() time.Time
}

func NewReconciler(nodeName string, cl client.Client, builder bird.ConfigBuilder, process *bird.ProcessManager, index *peerindex.PeerIndex) *Reconciler {
	return &Reconciler{
		nodeName:  nodeName,
		client:    cl,
		builder:   builder,
		process:   process,
		peerIndex: index,
		nowFn:     time.Now,
	}
}

// StatusInputs returns a snapshot of the Reconciler's observed state suitable
// for nodestate.Builder. It blends intent (advertisements/errors from the most
// recent successful reconcile) with runtime observation (bird process state).
func (r *Reconciler) StatusInputs() nodestate.Inputs {
	r.mu.Lock()
	ads := append([]nodestate.Advertisement(nil), r.lastAdvs...)
	errs := append([]nodestate.ResourceError(nil), r.lastErrors...)
	lastSync := r.lastSync
	r.mu.Unlock()

	if !lastSync.IsZero() {
		for i := range ads {
			ads[i].LastSyncedAt = lastSync
		}
	}
	return nodestate.Inputs{
		BirdRunning:    r.process.IsRunning(),
		Advertisements: ads,
		Errors:         errs,
	}
}

func (r *Reconciler) Reconcile(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var pools juneauv1alpha1.AddressPoolList
	if err := r.client.List(ctx, &pools); err != nil {
		return fmt.Errorf("list AddressPool: %w", err)
	}

	var advs juneauv1alpha1.BGPAdvertisementList
	if err := r.client.List(ctx, &advs); err != nil {
		return fmt.Errorf("list BGPAdvertisement: %w", err)
	}

	var peers juneauv1alpha1.BGPPeerList
	if err := r.client.List(ctx, &peers); err != nil {
		return fmt.Errorf("list BGPPeer: %w", err)
	}

	result := buildReconcileResult(r.nodeName, &pools, &advs, &peers)
	desired := result.Desired
	warnings := result.Warnings
	for _, w := range warnings {
		zap.S().Warnw("ignored invalid bgp resource/config", "nodeName", r.nodeName, "warning", w)
	}

	zap.S().Infow(
		"reconciled (desired config built)",
		"nodeName", r.nodeName,
		"addressPools", len(pools.Items),
		"bgpAdvertisements", len(advs.Items),
		"bgpPeers", len(peers.Items),
		"desiredPeers", len(desired.Peers),
		"desiredPrefixes", countDesiredPrefixes(desired),
	)

	if b, err := json.Marshal(desiredConfigForLog(desired)); err != nil {
		zap.S().Warnw("marshal desired config failed", "nodeName", r.nodeName, "error", err)
	} else {
		zap.S().Debugw("desired config", "nodeName", r.nodeName, "desiredConfig", string(b))
	}

	config, err := r.builder.Build(desired)
	if err != nil {
		return fmt.Errorf("build bird config: %w", err)
	}

	hash := sha256.Sum256([]byte(config))

	r.mu.Lock()
	changed := r.lastHash == nil || !bytes.Equal(r.lastHash, hash[:])
	r.mu.Unlock()

	running := r.process.IsRunning()
	if !running || changed {
		if err := os.MkdirAll(filepath.Dir(r.process.ConfigPath()), 0o755); err != nil {
			return fmt.Errorf("create bird config dir: %w", err)
		}
		if err := os.WriteFile(r.process.ConfigPath(), []byte(config), 0o644); err != nil {
			return fmt.Errorf("write bird config: %w", err)
		}
	}

	if !running {
		if err := r.process.EnsureControlDir(); err != nil {
			return fmt.Errorf("create bird control dir: %w", err)
		}
		if err := r.process.Start(); err != nil {
			return fmt.Errorf("start bird: %w", err)
		}
	}

	if changed || !running {
		if !running {
			waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
			defer waitCancel()
			if err := r.process.WaitForControlSocket(waitCtx, 50*time.Millisecond); err != nil {
				return fmt.Errorf("wait for bird control socket: %w", err)
			}
		}
		if err := r.process.Reload(ctx); err != nil {
			return fmt.Errorf("reload bird: %w", err)
		}
		r.mu.Lock()
		r.lastHash = append([]byte(nil), hash[:]...)
		r.mu.Unlock()
	}

	// Publish status intent from this successful reconcile.
	now := r.nowFn()
	r.mu.Lock()
	r.lastSync = now
	r.lastAdvs = result.Advertisements
	r.lastErrors = result.Errors
	for i := range r.lastErrors {
		t := now
		r.lastErrors[i].LastSeen = t
	}
	r.mu.Unlock()
	r.peerIndex.Set(result.PeerNamesByAddress)

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

func buildReconcileResult(
	nodeName string,
	pools *juneauv1alpha1.AddressPoolList,
	advs *juneauv1alpha1.BGPAdvertisementList,
	peers *juneauv1alpha1.BGPPeerList,
) ReconcileResult {
	var warnings []string
	var errs []nodestate.ResourceError
	addErr := func(kind, name, msg string) {
		errs = append(errs, nodestate.ResourceError{
			ResourceKind: kind,
			ResourceName: name,
			Message:      msg,
		})
		warnings = append(warnings, fmt.Sprintf("%s/%s: %s", kind, name, msg))
	}

	poolsByName := make(map[string]*juneauv1alpha1.AddressPool, len(pools.Items))
	for i := range pools.Items {
		pool := &pools.Items[i]
		poolsByName[pool.Name] = pool
	}

	// Filter advertisements by nodeName: only keep those that this
	// speaker should emit. spec.prefix overrides are honoured per
	// advertisement when projecting prefixes.
	relevantAdvs := make([]*juneauv1alpha1.BGPAdvertisement, 0, len(advs.Items))
	for i := range advs.Items {
		adv := &advs.Items[i]
		if adv.Spec.NodeName != "" && adv.Spec.NodeName != nodeName {
			continue
		}
		relevantAdvs = append(relevantAdvs, adv)
	}

	prefixes := buildPrefixes(poolsByName, relevantAdvs, addErr)

	desiredPeers := make([]*bgptypes.Peer, 0, len(peers.Items))
	peerIndex := map[string]string{}
	for i := range peers.Items {
		p := &peers.Items[i]

		remoteIP := strings.TrimSpace(p.Spec.PeerAddress)
		if remoteIP == "" {
			addErr("BGPPeer", p.Name, "spec.peerAddress is empty")
			continue
		}
		if p.Spec.MyASN == 0 {
			addErr("BGPPeer", p.Name, "spec.myASN is 0")
			continue
		}
		if p.Spec.PeerASN == 0 {
			addErr("BGPPeer", p.Name, "spec.peerASN is 0")
			continue
		}

		peer := &bgptypes.Peer{
			LocalASN:  p.Spec.MyASN,
			RemoteIP:  remoteIP,
			RemoteASN: p.Spec.PeerASN,
			Prefixes:  append([]*net.IPNet(nil), prefixes...),
		}
		desiredPeers = append(desiredPeers, peer)
		peerIndex[remoteIP] = p.Name
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

	return ReconcileResult{
		Desired:            &bgptypes.DesiredConfig{Peers: desiredPeers},
		Advertisements:     buildAdvertisementsIntent(poolsByName, relevantAdvs),
		PeerNamesByAddress: peerIndex,
		Errors:             errs,
		Warnings:           warnings,
	}
}

// buildAdvertisementsIntent projects the set of relevant advertisements
// into the shape consumed by BGPNodeState.advertisements: one entry per
// (advertisement, pool) pair. Pools not in BGP mode are skipped. When an
// advertisement specifies spec.prefix it overrides the pool-wide prefix
// list with a single prefix.
func buildAdvertisementsIntent(
	poolsByName map[string]*juneauv1alpha1.AddressPool,
	advs []*juneauv1alpha1.BGPAdvertisement,
) []nodestate.Advertisement {
	type entry struct {
		pool     string
		prefixes []string
	}
	merged := make(map[string]*entry)
	for _, adv := range advs {
		for _, poolName := range adv.Spec.AddressPools {
			poolName = strings.TrimSpace(poolName)
			if poolName == "" {
				continue
			}
			pool, ok := poolsByName[poolName]
			if !ok {
				continue
			}
			if pool.Spec.AdvertiseMode != juneauv1alpha1.AddressPoolAdvertiseModeBGP {
				continue
			}

			var prefixes []string
			if adv.Spec.Prefix != "" {
				if ipnet, err := parsePrefix(strings.TrimSpace(adv.Spec.Prefix)); err == nil {
					prefixes = append(prefixes, ipnet.String())
				}
			} else {
				unique := map[string]struct{}{}
				for _, raw := range pool.Spec.Addresses {
					raw = strings.TrimSpace(raw)
					if raw == "" {
						continue
					}
					if ipnet, err := parsePrefix(raw); err == nil {
						unique[ipnet.String()] = struct{}{}
					}
				}
				for p := range unique {
					prefixes = append(prefixes, p)
				}
			}
			sort.Strings(prefixes)

			e, ok := merged[poolName]
			if !ok {
				merged[poolName] = &entry{pool: poolName, prefixes: prefixes}
				continue
			}
			seen := map[string]struct{}{}
			for _, p := range e.prefixes {
				seen[p] = struct{}{}
			}
			for _, p := range prefixes {
				if _, ok := seen[p]; ok {
					continue
				}
				seen[p] = struct{}{}
				e.prefixes = append(e.prefixes, p)
			}
			sort.Strings(e.prefixes)
		}
	}

	out := make([]nodestate.Advertisement, 0, len(merged))
	for _, e := range merged {
		out = append(out, nodestate.Advertisement{
			AddressPool: e.pool,
			Prefixes:    e.prefixes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AddressPool < out[j].AddressPool })
	return out
}

// buildPrefixes returns the union of CIDRs that the bgp-speaker should
// announce. Each advertisement contributes either its spec.prefix
// (override) or every CIDR backing the referenced AddressPools.
func buildPrefixes(
	poolsByName map[string]*juneauv1alpha1.AddressPool,
	advs []*juneauv1alpha1.BGPAdvertisement,
	addErr func(kind, name, msg string),
) []*net.IPNet {
	unique := make(map[string]*net.IPNet)

	type advPool struct {
		adv      *juneauv1alpha1.BGPAdvertisement
		poolName string
	}
	pairs := make([]advPool, 0, len(advs))
	for _, adv := range advs {
		for _, poolName := range adv.Spec.AddressPools {
			poolName = strings.TrimSpace(poolName)
			if poolName == "" {
				continue
			}
			pairs = append(pairs, advPool{adv: adv, poolName: poolName})
		}
	}

	for _, pair := range pairs {
		pool, ok := poolsByName[pair.poolName]
		if !ok {
			addErr("AddressPool", pair.poolName, "referenced by BGPAdvertisement but not found")
			continue
		}
		if pool.Spec.AdvertiseMode != juneauv1alpha1.AddressPoolAdvertiseModeBGP {
			addErr("AddressPool", pool.Name, fmt.Sprintf("spec.advertiseMode=%q is not bgp", pool.Spec.AdvertiseMode))
			continue
		}

		if pair.adv.Spec.Prefix != "" {
			ipnet, err := parsePrefix(strings.TrimSpace(pair.adv.Spec.Prefix))
			if err != nil {
				addErr("BGPAdvertisement", pair.adv.Name, fmt.Sprintf("invalid spec.prefix %q: %v", pair.adv.Spec.Prefix, err))
				continue
			}
			unique[ipnet.String()] = ipnet
			continue
		}

		for _, raw := range pool.Spec.Addresses {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}

			ipnet, err := parsePrefix(raw)
			if err != nil {
				addErr("AddressPool", pool.Name, fmt.Sprintf("invalid address %q: %v", raw, err))
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
	return out
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
