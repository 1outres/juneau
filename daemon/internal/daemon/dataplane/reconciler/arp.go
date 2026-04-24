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

// Arp keeps hostEgress.ArpTable in sync with NetworkEndpoint objects.
// Keyed by NWEP namespace/name.
type Arp struct {
	client     client.Client
	hostEgress *program.HostEgress

	mu        sync.Mutex
	snapshots map[string]arpSnapshot
}

type arpSnapshot struct {
	vni  uint32
	addr uint32
}

func NewArp(cl client.Client, hostEgress *program.HostEgress) *Arp {
	return &Arp{
		client:     cl,
		hostEgress: hostEgress,
		snapshots:  make(map[string]arpSnapshot),
	}
}

func (r *Arp) Name() string { return "arp" }

func (r *Arp) Reconcile(ctx context.Context, key string) error {
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
	return r.upsert(ctx, key, &nwep)
}

func (r *Arp) upsert(ctx context.Context, key string, nwep *juneauv1alpha1.NetworkEndpoint) error {
	var subnet juneauv1alpha1.Subnet
	if err := r.client.Get(ctx, client.ObjectKey{Name: nwep.Spec.Subnet}, &subnet); err != nil {
		return err
	}

	netaddr, _, err := net.ParseCIDR(nwep.Spec.Address)
	if err != nil {
		return err
	}
	addr, err := convert.IPv4ToUint32(netaddr)
	if err != nil {
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

	desired := arpSnapshot{vni: subnet.Status.VNI, addr: addr}

	r.mu.Lock()
	old, hadOld := r.snapshots[key]
	r.mu.Unlock()

	if hadOld && old != desired {
		if err := r.hostEgress.Objs.ArpTable.Delete(&bpf.HostEgressArpTableKey{
			SubnetId: old.vni, Ipaddr: old.addr,
		}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete old ArpTable entry: %w", err)
		}
	}

	if err := r.hostEgress.Objs.ArpTable.Update(
		&bpf.HostEgressArpTableKey{SubnetId: desired.vni, Ipaddr: desired.addr},
		&bpf.HostEgressArpTableVal{Mac: mac},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update ArpTable: %w", err)
	}

	r.mu.Lock()
	r.snapshots[key] = desired
	r.mu.Unlock()
	return nil
}

func (r *Arp) delete(key string) error {
	r.mu.Lock()
	snap, ok := r.snapshots[key]
	r.mu.Unlock()
	if !ok {
		return nil
	}

	if err := r.hostEgress.Objs.ArpTable.Delete(&bpf.HostEgressArpTableKey{
		SubnetId: snap.vni, Ipaddr: snap.addr,
	}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete ArpTable: %w", err)
	}

	r.mu.Lock()
	delete(r.snapshots, key)
	r.mu.Unlock()
	return nil
}
