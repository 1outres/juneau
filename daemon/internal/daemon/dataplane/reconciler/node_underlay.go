package reconciler

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// NodeUnderlay keeps the node_underlay BPF map in sync with the set of
// juneau_node NetworkEndpoints in the cluster. The map is consulted by
// pod_egress (to recognise "this destination is a peer Node IP, route
// via the underlay rather than VPC") and by node_ingress's LB reverse
// path; both rely on every Node's IP being present so cross-Node LB
// flows can complete.
//
// The local Node's IP is also seeded synchronously at construction so
// the LB reverse path does not depend on the controller-side
// NetworkEndpoint reconciler having published Status.NodeIP yet —
// ordering matters because the daemon may start serving LB traffic
// the moment its first AllocationClaim resolves.
type NodeUnderlay struct {
	client    client.Client
	podEgress *program.PodEgress

	mu        sync.Mutex
	snapshots map[string]uint32 // key: NWEP namespacedName, value: nbo IP
	seeded    map[uint32]struct{}
}

// NewNodeUnderlay constructs the reconciler and pre-populates the map
// with seedIPs (typically the local Node's underlay address). Seed
// entries are tracked separately from informer-driven entries so a
// later NWEP delete cannot accidentally drop the seed.
func NewNodeUnderlay(cl client.Client, podEgress *program.PodEgress, seedIPs []net.IP) (*NodeUnderlay, error) {
	r := &NodeUnderlay{
		client:    cl,
		podEgress: podEgress,
		snapshots: make(map[string]uint32),
		seeded:    make(map[uint32]struct{}),
	}
	for _, ip := range seedIPs {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		nbo := binary.BigEndian.Uint32(v4)
		if err := r.write(nbo); err != nil {
			return nil, fmt.Errorf("seed node_underlay %s: %w", v4, err)
		}
		r.seeded[nbo] = struct{}{}
	}
	return r, nil
}

func (r *NodeUnderlay) Name() string { return "node-underlay" }

func (r *NodeUnderlay) Reconcile(ctx context.Context, key string) error {
	namespace, name, err := toolscache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	var nwep juneauv1alpha1.NetworkEndpoint
	err = r.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &nwep)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}

	// Only Kind=Node endpoints contribute to the underlay set; Pod
	// endpoints are routed through VPC fabric and do not belong here.
	if nwep.Spec.Kind != juneauv1alpha1.EndpointKindNode {
		return r.delete(key)
	}

	if nwep.Status.NodeIP == "" {
		// Status not yet populated by the controller-side
		// NetworkEndpoint reconciler. Skip; we'll be re-driven when
		// status changes.
		return nil
	}

	v4 := net.ParseIP(nwep.Status.NodeIP).To4()
	if v4 == nil {
		return fmt.Errorf("NetworkEndpoint %s/%s status.nodeIP %q is not IPv4", namespace, name, nwep.Status.NodeIP)
	}
	nbo := binary.BigEndian.Uint32(v4)

	r.mu.Lock()
	old, hadOld := r.snapshots[key]
	r.snapshots[key] = nbo
	r.mu.Unlock()

	if hadOld && old != nbo {
		// IP changed (rare; would happen if a Node's InternalIP is
		// re-issued). Delete the stale entry first to avoid leaking
		// the old IP. Skip when the stale entry is still pinned by a
		// seed — the seed survives across reconciler churn.
		if err := r.maybeDelete(old); err != nil {
			return err
		}
	}

	return r.write(nbo)
}

func (r *NodeUnderlay) delete(key string) error {
	r.mu.Lock()
	old, ok := r.snapshots[key]
	if ok {
		delete(r.snapshots, key)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}
	return r.maybeDelete(old)
}

// write installs ip into the BPF map. Existence is the verdict; the
// stored byte is unused so we always write 1.
func (r *NodeUnderlay) write(nboIP uint32) error {
	key := bpf.PodEgressNodeUnderlayKey{Ipaddr: nboIP}
	val := uint8(1)
	if err := r.podEgress.Objs.NodeUnderlay.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update node_underlay: %w", err)
	}
	return nil
}

// maybeDelete removes ip from the BPF map unless it is still pinned by
// the local seed list (so an informer-driven NWEP delete cannot drop
// the local Node's own IP from under the LB reverse path).
func (r *NodeUnderlay) maybeDelete(nboIP uint32) error {
	r.mu.Lock()
	_, seeded := r.seeded[nboIP]
	// Do not remove if any other key still references the same IP.
	stillReferenced := false
	for _, v := range r.snapshots {
		if v == nboIP {
			stillReferenced = true
			break
		}
	}
	r.mu.Unlock()
	if seeded || stillReferenced {
		return nil
	}
	key := bpf.PodEgressNodeUnderlayKey{Ipaddr: nboIP}
	if err := r.podEgress.Objs.NodeUnderlay.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete node_underlay: %w", err)
	}
	return nil
}
