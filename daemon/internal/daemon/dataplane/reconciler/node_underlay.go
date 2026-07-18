package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// NodeUnderlay keeps podEgress.NodeUnderlays in sync with the set of
// Node InternalIPv4 addresses cluster-wide. The map is consumed by
// pod_egress.handle_l3 to detect the reply leg of a Service flow
// whose forward DNAT was performed by an external in-kernel kube-
// proxy iptables ruleset (rather than by juneau's own handle_service):
// juneau's fib_map cannot resolve node underlay IPs, so without an
// explicit "delegate to kernel" contract those replies would drop at
// the fib_map miss and kube-proxy's conntrack would never see the
// response to un-DNAT it.
//
// One entry per Node × InternalIPv4 address. IPv6 InternalIPs and
// ExternalIP / Hostname address types are skipped: only underlay IPv4
// is a legitimate response-leg destination that juneau needs to
// delegate.
type NodeUnderlay struct {
	client    client.Client
	podEgress *program.PodEgress

	mu        sync.Mutex
	snapshots map[string][]uint32
}

// NewNodeUnderlay wires the reconciler onto podEgress.NodeUnderlays.
// snapshots tracks the BE-encoded keys previously written per Node so
// a later reconcile (or delete) can undo exactly the entries this
// reconciler is responsible for, even after the source Node object is
// gone from the cache.
func NewNodeUnderlay(cl client.Client, podEgress *program.PodEgress) *NodeUnderlay {
	return &NodeUnderlay{
		client:    cl,
		podEgress: podEgress,
		snapshots: make(map[string][]uint32),
	}
}

func (r *NodeUnderlay) Name() string { return "node-underlay" }

func (r *NodeUnderlay) Reconcile(ctx context.Context, key string) error {
	_, name, err := toolscache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	var node corev1.Node
	err = r.client.Get(ctx, client.ObjectKey{Name: name}, &node)
	if apierrors.IsNotFound(err) {
		return r.delete(name)
	}
	if err != nil {
		return err
	}
	return r.upsert(&node)
}

func (r *NodeUnderlay) upsert(node *corev1.Node) error {
	desired, err := buildNodeUnderlayDesired(node)
	if err != nil {
		return err
	}

	r.mu.Lock()
	prev := r.snapshots[node.Name]
	r.mu.Unlock()

	toAdd, toDel := diffUint32Sets(prev, desired)

	var one uint8 = 1
	for _, addr := range toAdd {
		if err := r.podEgress.Objs.NodeUnderlays.Update(&addr, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update node_underlays for %s (addr=%d): %w", node.Name, addr, err)
		}
	}
	for _, addr := range toDel {
		if err := r.podEgress.Objs.NodeUnderlays.Delete(&addr); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete node_underlays for %s (addr=%d): %w", node.Name, addr, err)
		}
	}

	r.mu.Lock()
	r.snapshots[node.Name] = desired
	r.mu.Unlock()

	if len(toAdd) > 0 || len(toDel) > 0 {
		zap.S().Infof("node-underlay: reconciled %s (add=%d del=%d total=%d)",
			node.Name, len(toAdd), len(toDel), len(desired))
	}
	return nil
}

func (r *NodeUnderlay) delete(name string) error {
	r.mu.Lock()
	prev, ok := r.snapshots[name]
	if ok {
		delete(r.snapshots, name)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}

	for _, addr := range prev {
		if err := r.podEgress.Objs.NodeUnderlays.Delete(&addr); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete node_underlays for %s (addr=%d): %w", name, addr, err)
		}
	}
	zap.S().Infof("node-underlay: removed %s (%d entries)", name, len(prev))
	return nil
}

// buildNodeUnderlayDesired extracts a Node's InternalIPv4 addresses
// and returns them BE-encoded and de-duplicated in a stable order.
// Non-InternalIP address types, IPv6 addresses, and unparseable
// strings are ignored: the map is only consulted for dst-IP matches
// against IPv4 headers by pod_egress, so other address kinds cannot
// contribute matches even if they were written.
func buildNodeUnderlayDesired(node *corev1.Node) ([]uint32, error) {
	seen := make(map[uint32]struct{})
	out := make([]uint32, 0, len(node.Status.Addresses))
	for _, a := range node.Status.Addresses {
		if a.Type != corev1.NodeInternalIP {
			continue
		}
		ip := net.ParseIP(a.Address)
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		be, err := convert.IPv4ToBPFNetworkOrder(ip4)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[be]; dup {
			continue
		}
		seen[be] = struct{}{}
		out = append(out, be)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// diffUint32Sets returns the multiset difference on already-sorted or
// order-insensitive slices. toAdd = desired \ prev, toDel = prev \
// desired. Small-cluster N means the O(N²) implementation is
// preferable to the allocation churn of a map for typical node counts.
func diffUint32Sets(prev, desired []uint32) (toAdd, toDel []uint32) {
	for _, d := range desired {
		if !containsUint32(prev, d) {
			toAdd = append(toAdd, d)
		}
	}
	for _, p := range prev {
		if !containsUint32(desired, p) {
			toDel = append(toDel, p)
		}
	}
	return
}

func containsUint32(xs []uint32, needle uint32) bool {
	for _, x := range xs {
		if x == needle {
			return true
		}
	}
	return false
}
