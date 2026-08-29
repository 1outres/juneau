package reconciler

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// L2NetworkTables are the per-VNI tables of one segment. They are
// named rather than passed in order because they all have the same
// type, and a caller that swapped two of them would build a segment
// that floods to the addresses it has learned.
type L2NetworkTables struct {
	// Fdb is l2_fdb, the forwarding table the data plane learns into.
	Fdb l2NetworkTable
	// BumLocal is l2_bum_local, the local ports a broadcast reaches.
	BumLocal l2NetworkTable
	// BumRemote is l2_bum_remote, the nodes a broadcast reaches.
	BumRemote l2NetworkTable
	// Arp is l2_arp, what the gateway of the segment resolves a
	// destination address to a MAC with.
	Arp l2NetworkTable
	// ArpProbe is l2_arp_probe, when the gateway last asked the segment
	// for an address it could not resolve.
	ArpProbe l2NetworkTable
}

func (t L2NetworkTables) all() []l2NetworkTable {
	return []l2NetworkTable{t.Fdb, t.BumLocal, t.BumRemote, t.Arp, t.ArpProbe}
}

// L2Network keeps l2_network_map in sync with L2Network objects and
// owns the per-VNI tables the L2 programs read.
//
// l2_network_map is what tells vxlan_ingress that a VNI belongs to an
// L2Network rather than to a Subnet, so it decides which of the two
// data planes an arriving frame takes. The tables beside it hold what
// the L2 programs learn and flood to; this reconciler creates them when
// the network appears and drops them when it goes away, but never
// writes an entry into l2_fdb. Learning is the data plane's alone: a
// controller-written entry would be overwritten by the next frame and
// would make it impossible to say who owns a MAC.
type L2Network struct {
	client     client.Client
	networkMap bpfMap
	tables     L2NetworkTables

	mu        sync.Mutex
	snapshots map[string]l2NetworkSnapshot
}

// l2NetworkSnapshot remembers the VNI a network was last programmed
// under, so a renumbering or a delete cleans up the right tables even
// though the object that named them is gone by then.
type l2NetworkSnapshot struct {
	vni uint32
}

func NewL2Network(cl client.Client, networkMap bpfMap, tables L2NetworkTables) *L2Network {
	return &L2Network{
		client:     cl,
		networkMap: networkMap,
		tables:     tables,
		snapshots:  make(map[string]l2NetworkSnapshot),
	}
}

func (r *L2Network) Name() string { return "l2-network" }

func (r *L2Network) Reconcile(ctx context.Context, key string) error {
	var network juneauv1alpha1.L2Network
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &network)
	if apierrors.IsNotFound(err) {
		return r.delete(key)
	}
	if err != nil {
		return err
	}
	return r.upsert(ctx, &network)
}

func (r *L2Network) upsert(ctx context.Context, network *juneauv1alpha1.L2Network) error {
	if network.Status.VNI == 0 {
		// The controller has not handed out a VNI yet. There is
		// nothing to key a table on, and the status update that
		// carries the VNI will bring us back here.
		return nil
	}

	var vpc juneauv1alpha1.Vpc
	if err := r.client.Get(ctx, client.ObjectKey{Name: network.Spec.Vpc}, &vpc); err != nil {
		return err
	}

	r.mu.Lock()
	prev, hadPrev := r.snapshots[network.Name]
	r.mu.Unlock()

	if hadPrev && prev.vni != network.Status.VNI {
		if err := r.release(prev.vni); err != nil {
			return err
		}
	}

	if err := r.ensureTables(network.Status.VNI); err != nil {
		return err
	}

	if err := r.networkMap.Update(
		&bpf.PodEgressL2NetworkKey{Vni: network.Status.VNI},
		&bpf.PodEgressL2NetworkVal{VpcId: vpc.Status.VpcID},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update L2NetworkMap: %w", err)
	}

	r.mu.Lock()
	r.snapshots[network.Name] = l2NetworkSnapshot{vni: network.Status.VNI}
	r.mu.Unlock()

	zap.S().Infof("l2-network: reconciled %s (VNI=%d)", network.Name, network.Status.VNI)
	return nil
}

// ensureTables builds every per-VNI table. They are created together
// because the data plane treats a network with only some of them as
// broken: a frame that finds no flood list is dropped without anything
// saying which table was missing.
func (r *L2Network) ensureTables(vni uint32) error {
	for _, table := range r.tables.all() {
		if err := table.Ensure(vni); err != nil {
			return err
		}
	}
	return nil
}

func (r *L2Network) delete(key string) error {
	r.mu.Lock()
	snap, ok := r.snapshots[key]
	if ok {
		delete(r.snapshots, key)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}

	zap.S().Infof("l2-network: deleting %s (VNI=%d)", key, snap.vni)
	return r.release(snap.vni)
}

func (r *L2Network) release(vni uint32) error {
	if err := r.networkMap.Delete(&bpf.PodEgressL2NetworkKey{Vni: vni}); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete L2NetworkMap: %w", err)
	}
	for _, table := range r.tables.all() {
		if err := table.Delete(vni); err != nil {
			return err
		}
	}
	return nil
}

// FanOutVpcToL2Networks re-enqueues every L2Network of the changed Vpc.
// Vpc.status.vpcID is allocated after the Vpc itself exists, and it is
// what the trace events of the segment are stamped with, so the
// allocation has to reach l2_network_map without waiting for an
// unrelated L2Network event.
func (r *L2Network) FanOutVpcToL2Networks(obj any) []string {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}

	var list juneauv1alpha1.L2NetworkList
	if err := r.client.List(context.Background(), &list); err != nil {
		zap.S().Warnf("l2-network: list L2Networks for vpc %q fan-out: %v", vpc.Name, err)
		return nil
	}
	keys := make([]string, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.Vpc != vpc.Name {
			continue
		}
		keys = append(keys, list.Items[i].Name)
	}
	return keys
}
