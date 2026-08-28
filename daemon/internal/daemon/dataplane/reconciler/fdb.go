package reconciler

import (
	"context"
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
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// Fdb keeps the FDB maps in sync with NetworkEndpoint objects. Local
// endpoints (NodeName==self with Attachment populated) go to
// vxlanIngress.Fdb (ifindex-valued); remote endpoints go to
// hostEgress.Fdb (VTEP IP-valued). Kind-agnostic: handles every NWEP
// variant uniformly. The snapshot tracks which side an entry was
// written to so delete/move can clean up the right map.
type Fdb struct {
	client       client.Client
	hostEgress   *program.PodEgress
	vxlanIngress *program.VxlanIngress
	nodeName     string

	mu        sync.Mutex
	snapshots map[string]fdbSnapshot
}

type fdbSnapshot struct {
	vni     uint32
	mac     [6]uint8
	isLocal bool
}

func NewFdb(cl client.Client, hostEgress *program.PodEgress, vxlanIngress *program.VxlanIngress, nodeName string) *Fdb {
	return &Fdb{
		client:       cl,
		hostEgress:   hostEgress,
		vxlanIngress: vxlanIngress,
		nodeName:     nodeName,
		snapshots:    make(map[string]fdbSnapshot),
	}
}

func (r *Fdb) Name() string { return "fdb" }

func (r *Fdb) Reconcile(ctx context.Context, key string) error {
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

	if nwep.Spec.Subnet == "" {
		// An endpoint on an L2Network is left alone: that data plane
		// learns its own entries, and a controller-written one would be
		// overwritten by the next frame anyway.
		return r.delete(key)
	}
	return r.upsert(ctx, key, &nwep)
}

type fdbDesired struct {
	snap fdbSnapshot
	val  bpf.PodEgressFdbVal
}

func (r *Fdb) upsert(ctx context.Context, key string, nwep *juneauv1alpha1.NetworkEndpoint) error {
	var subnet juneauv1alpha1.Subnet
	if err := r.client.Get(ctx, client.ObjectKey{Name: nwep.Spec.Subnet}, &subnet); err != nil {
		return err
	}

	netmac, err := net.ParseMAC(nwep.Spec.MACAddress)
	if err != nil {
		return err
	}
	mac, err := convert.HardwareAddrToUint8Array(netmac)
	if err != nil {
		return err
	}

	isLocal := nwep.Spec.NodeName == r.nodeName

	var desired *fdbDesired
	switch {
	case isLocal && nwep.Spec.Attachment != nil:
		desired = &fdbDesired{
			snap: fdbSnapshot{vni: subnet.Status.VNI, mac: mac, isLocal: true},
			val:  bpf.PodEgressFdbVal{Ifindex: uint32(nwep.Spec.Attachment.Ifindex)},
		}
	case isLocal:
		// Attachment not yet populated by the local daemon; skip until
		// it appears. The reconciler will be re-driven by the watch.
	case nwep.Status.NodeIP != "":
		netNodeAddr := net.ParseIP(nwep.Status.NodeIP)
		if netNodeAddr == nil {
			return fmt.Errorf("failed to parse node IP: %s", nwep.Status.NodeIP)
		}
		nodeAddr, err := convert.IPv4ToUint32(netNodeAddr)
		if err != nil {
			return err
		}
		desired = &fdbDesired{
			snap: fdbSnapshot{vni: subnet.Status.VNI, mac: mac, isLocal: false},
			val:  bpf.PodEgressFdbVal{VtepIp: nodeAddr},
		}
	}

	r.mu.Lock()
	old, hadOld := r.snapshots[key]
	r.mu.Unlock()

	if hadOld && (desired == nil || old != desired.snap) {
		if err := r.deleteEntry(old); err != nil {
			return err
		}
		r.mu.Lock()
		delete(r.snapshots, key)
		r.mu.Unlock()
	}

	if desired == nil {
		return nil
	}

	m := r.mapFor(desired.snap.isLocal)
	if err := m.Update(
		&bpf.PodEgressFdbKey{SubnetId: desired.snap.vni, Mac: desired.snap.mac},
		&desired.val,
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update Fdb: %w", err)
	}

	r.mu.Lock()
	r.snapshots[key] = desired.snap
	r.mu.Unlock()
	return nil
}

func (r *Fdb) delete(key string) error {
	r.mu.Lock()
	snap, ok := r.snapshots[key]
	r.mu.Unlock()
	if !ok {
		return nil
	}

	if err := r.deleteEntry(snap); err != nil {
		return err
	}

	r.mu.Lock()
	delete(r.snapshots, key)
	r.mu.Unlock()
	return nil
}

func (r *Fdb) deleteEntry(snap fdbSnapshot) error {
	m := r.mapFor(snap.isLocal)
	if err := m.Delete(&bpf.PodEgressFdbKey{SubnetId: snap.vni, Mac: snap.mac}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete Fdb: %w", err)
	}
	return nil
}

func (r *Fdb) mapFor(isLocal bool) *ebpf.Map {
	if isLocal {
		return r.vxlanIngress.Objs.Fdb
	}
	return r.hostEgress.Objs.Fdb
}
