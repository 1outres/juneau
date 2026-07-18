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
	"github.com/1outres/juneau/bgp-speaker/internal/prefixsource"
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
	sources   []prefixsource.Source

	mu         sync.Mutex
	lastHash   []byte
	lastSync   time.Time
	lastAdvs   []nodestate.Advertisement
	lastErrors []nodestate.ResourceError
	nowFn      func() time.Time
}

// NewReconciler returns a Reconciler with the default prefix source
// set: today that is the AddressPool + BGPAdvertisement source. Use
// NewReconcilerWithSources to override the set (Phase 5 wires in
// the ServiceLoadBalancer source).
func NewReconciler(nodeName string, cl client.Client, builder bird.ConfigBuilder, process *bird.ProcessManager, index *peerindex.PeerIndex) *Reconciler {
	return NewReconcilerWithSources(nodeName, cl, builder, process, index, defaultPrefixSources())
}

// NewReconcilerWithSources lets callers pass an explicit list of
// PrefixSources. The slice is used in order and may be empty (in
// which case no prefixes are advertised).
func NewReconcilerWithSources(
	nodeName string,
	cl client.Client,
	builder bird.ConfigBuilder,
	process *bird.ProcessManager,
	index *peerindex.PeerIndex,
	sources []prefixsource.Source,
) *Reconciler {
	return &Reconciler{
		nodeName:  nodeName,
		client:    cl,
		builder:   builder,
		process:   process,
		peerIndex: index,
		sources:   sources,
		nowFn:     time.Now,
	}
}

// defaultPrefixSources returns the production prefix-source set. It
// is its own function so tests and future entry-points can mutate
// the set without depending on package-level mutable state.
func defaultPrefixSources() []prefixsource.Source {
	return []prefixsource.Source{
		prefixsource.AddressPoolAdvertisementSource{},
		prefixsource.ServiceLoadBalancerSource{},
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

	aggregated, err := prefixsource.Aggregate(ctx, r.sources, prefixsource.Input{
		NodeName: r.nodeName,
		Client:   r.client,
	})
	if err != nil {
		return err
	}

	var peers juneauv1alpha1.BGPPeerList
	if err := r.client.List(ctx, &peers); err != nil {
		return fmt.Errorf("list BGPPeer: %w", err)
	}

	result := buildReconcileResult(r.nodeName, aggregated, &peers)
	desired := result.Desired
	warnings := result.Warnings
	for _, w := range warnings {
		zap.S().Warnw("ignored invalid bgp resource/config", "nodeName", r.nodeName, "warning", w)
	}

	zap.S().Infow(
		"reconciled (desired config built)",
		"nodeName", r.nodeName,
		"prefixSources", len(r.sources),
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

// buildReconcileResult composes peer-side state with the
// pre-aggregated prefix set. The function used to also drive prefix
// discovery; that responsibility now belongs to PrefixSource
// implementations behind the aggregator.
func buildReconcileResult(
	nodeName string,
	aggregated prefixsource.Aggregated,
	peers *juneauv1alpha1.BGPPeerList,
) ReconcileResult {
	var warnings []string
	errs := append([]nodestate.ResourceError(nil), aggregated.Errors...)
	for _, e := range aggregated.Errors {
		warnings = append(warnings, fmt.Sprintf("%s/%s: %s", e.ResourceKind, e.ResourceName, e.Message))
	}
	addErr := func(kind, name, msg string) {
		errs = append(errs, nodestate.ResourceError{
			ResourceKind: kind,
			ResourceName: name,
			Message:      msg,
		})
		warnings = append(warnings, fmt.Sprintf("%s/%s: %s", kind, name, msg))
	}

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
			LocalASN:  uint32(p.Spec.MyASN),
			RemoteIP:  remoteIP,
			RemoteASN: uint32(p.Spec.PeerASN),
			Prefixes:  append([]*net.IPNet(nil), aggregated.MergedPrefixes...),
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

	_ = nodeName
	return ReconcileResult{
		Desired:            &bgptypes.DesiredConfig{Peers: desiredPeers},
		Advertisements:     advertisementsIntentFromSources(aggregated.Advertisements),
		PeerNamesByAddress: peerIndex,
		Errors:             errs,
		Warnings:           warnings,
	}
}

// advertisementsIntentFromSources projects per-source advertisements
// into the shape consumed by BGPNodeState.advertisements.
//
// AddressPool-shaped advertisements still bucket by pool so multiple
// BGPAdvertisements that target the same pool collapse onto a single
// entry — preserving the pre-refactor BGPNodeState representation.
// Non-pool sources (ServiceLoadBalancer) bucket by (sourceKind,
// sourceNamespace, sourceName) so each source resource maps to one
// status entry.
func advertisementsIntentFromSources(advs []prefixsource.SourceAdvertisement) []nodestate.Advertisement {
	type bucketKey struct {
		Pool      string
		Kind      string
		Namespace string
		Name      string
	}
	type bucket struct {
		key      bucketKey
		prefixes map[string]struct{}
		// kind / name preserved when the bucket is uniquely owned by
		// one source. AddressPool-keyed buckets reset SourceKind/Name
		// to empty when more than one source contributes (matching
		// the prior behaviour where the legacy entry has no source
		// attribution at all).
		kind      string
		namespace string
		name      string
	}
	buckets := map[bucketKey]*bucket{}
	for _, ad := range advs {
		var key bucketKey
		if ad.AddressPool != "" {
			key = bucketKey{Pool: ad.AddressPool}
		} else {
			key = bucketKey{Kind: ad.SourceKind, Namespace: ad.SourceNamespace, Name: ad.SourceName}
		}
		b, ok := buckets[key]
		if !ok {
			b = &bucket{
				key:       key,
				prefixes:  map[string]struct{}{},
				kind:      ad.SourceKind,
				namespace: ad.SourceNamespace,
				name:      ad.SourceName,
			}
			buckets[key] = b
		} else if ad.AddressPool != "" {
			// Pool-keyed bucket with multiple contributors: drop the
			// per-source fields so consumers see "shared between
			// multiple BGPAdvertisements" rather than a misleading
			// single name.
			if b.name != ad.SourceName || b.namespace != ad.SourceNamespace {
				b.name = ""
				b.namespace = ""
			}
		}
		for _, p := range ad.Prefixes {
			if p == nil {
				continue
			}
			b.prefixes[p.String()] = struct{}{}
		}
	}

	out := make([]nodestate.Advertisement, 0, len(buckets))
	for _, b := range buckets {
		prefixes := make([]string, 0, len(b.prefixes))
		for p := range b.prefixes {
			prefixes = append(prefixes, p)
		}
		sort.Strings(prefixes)
		out = append(out, nodestate.Advertisement{
			AddressPool:     b.key.Pool,
			SourceKind:      b.kind,
			SourceNamespace: b.namespace,
			SourceName:      b.name,
			Prefixes:        prefixes,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AddressPool != out[j].AddressPool {
			return out[i].AddressPool < out[j].AddressPool
		}
		if out[i].SourceKind != out[j].SourceKind {
			return out[i].SourceKind < out[j].SourceKind
		}
		if out[i].SourceNamespace != out[j].SourceNamespace {
			return out[i].SourceNamespace < out[j].SourceNamespace
		}
		return out[i].SourceName < out[j].SourceName
	})
	return out
}

func countDesiredPrefixes(cfg *bgptypes.DesiredConfig) int {
	if cfg == nil || len(cfg.Peers) == 0 {
		return 0
	}
	return len(cfg.Peers[0].Prefixes)
}
