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
// Keyed by NWEP namespace/name. Operates on L2 identity only
// (segment+address+macAddress); does not depend on Kind, PodRef, or
// Attachment, so it handles every endpoint variant (Pod, Node, …).
//
// The segment is the VNI of a Subnet or the network ID of an
// ExternalNetwork; see overlaySegmentID.
type Arp struct {
	client   client.Client
	arpTable bpfMap

	mu        sync.Mutex
	snapshots map[string]arpSnapshot
}

type arpSnapshot struct {
	vni  uint32
	addr uint32
}

func NewArp(cl client.Client, hostEgress *program.PodEgress) *Arp {
	return &Arp{
		client:    cl,
		arpTable:  hostEgress.Objs.ArpTable,
		snapshots: make(map[string]arpSnapshot),
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

	network, err := endpointNetworkOf(&nwep)
	if err != nil {
		return err
	}
	if network == endpointOnL2Network {
		// An endpoint on an L2Network is left alone: that data plane
		// learns its own entries, and a controller-written one would be
		// overwritten by the next frame anyway.
		return r.delete(key)
	}

	vni, ready, err := overlaySegmentID(ctx, r.client, &nwep, network)
	if err != nil {
		return err
	}
	if !ready {
		return r.delete(key)
	}
	return r.upsert(key, &nwep, vni)
}

// FanOutExternalNetworkToEndpoints re-enqueues the endpoints of an
// ExternalNetwork, whose network ID is what their entries are keyed by.
func (r *Arp) FanOutExternalNetworkToEndpoints(obj any) []string {
	return externalNetworkEndpointKeys(r.client, obj)
}

func (r *Arp) upsert(key string, nwep *juneauv1alpha1.NetworkEndpoint, vni uint32) error {
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

	desired := arpSnapshot{vni: vni, addr: addr}

	r.mu.Lock()
	old, hadOld := r.snapshots[key]
	r.mu.Unlock()

	if hadOld && old != desired {
		if err := r.arpTable.Delete(&bpf.PodEgressArpTableKey{
			SubnetId: old.vni, Ipaddr: old.addr,
		}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete old ArpTable entry: %w", err)
		}
	}

	if err := r.arpTable.Update(
		&bpf.PodEgressArpTableKey{SubnetId: desired.vni, Ipaddr: desired.addr},
		&bpf.PodEgressArpTableVal{Mac: mac},
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

	if err := r.arpTable.Delete(&bpf.PodEgressArpTableKey{
		SubnetId: snap.vni, Ipaddr: snap.addr,
	}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete ArpTable: %w", err)
	}

	r.mu.Lock()
	delete(r.snapshots, key)
	r.mu.Unlock()
	return nil
}
