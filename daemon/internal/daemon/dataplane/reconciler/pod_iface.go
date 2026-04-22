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

// PodIface keeps podEgress.IfindexSubnet and podEgress.IfindexHostMac in
// sync with local NetworkEndpoint objects. Remote endpoints are ignored
// (but any stale local entry from a previous reconcile is cleaned up if
// the endpoint is reassigned to another node).
type PodIface struct {
	client    client.Client
	podEgress *program.PodEgress
	nodeName  string

	mu        sync.Mutex
	snapshots map[string]uint32 // NWEP key -> ifindex we last wrote for
}

func NewPodIface(cl client.Client, podEgress *program.PodEgress, nodeName string) *PodIface {
	return &PodIface{
		client:    cl,
		podEgress: podEgress,
		nodeName:  nodeName,
		snapshots: make(map[string]uint32),
	}
}

func (r *PodIface) Name() string { return "pod-iface" }

func (r *PodIface) Reconcile(ctx context.Context, key string) error {
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

	if nwep.Spec.NodeName != r.nodeName {
		return r.delete(key)
	}
	return r.upsert(ctx, key, &nwep)
}

func (r *PodIface) upsert(ctx context.Context, key string, nwep *juneauv1alpha1.NetworkEndpoint) error {
	var subnet juneauv1alpha1.Subnet
	if err := r.client.Get(ctx, client.ObjectKey{Name: nwep.Spec.Subnet}, &subnet); err != nil {
		return err
	}

	hostMAC, err := net.ParseMAC(nwep.Spec.HostMACAddress)
	if err != nil {
		return err
	}
	hostMACArray, err := convert.HardwareAddrToUint8Array(hostMAC)
	if err != nil {
		return err
	}

	newIfindex := uint32(nwep.Spec.Ifindex)

	r.mu.Lock()
	oldIfindex, hadOld := r.snapshots[key]
	r.mu.Unlock()

	if hadOld && oldIfindex != newIfindex {
		if err := r.deleteEntries(oldIfindex); err != nil {
			return err
		}
	}

	if err := r.podEgress.Objs.IfindexSubnet.Update(
		&bpf.PodEgressIfindexSubnetKey{Ifindex: newIfindex},
		&bpf.PodEgressIfindexSubnetVal{SubnetId: subnet.Status.VNI},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update IfindexSubnet: %w", err)
	}

	if err := r.podEgress.Objs.IfindexHostMac.Update(
		&bpf.PodEgressIfindexHostMacKey{Ifindex: newIfindex},
		&bpf.PodEgressIfindexHostMacVal{Mac: hostMACArray},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update IfindexHostMac: %w", err)
	}

	r.mu.Lock()
	r.snapshots[key] = newIfindex
	r.mu.Unlock()
	return nil
}

func (r *PodIface) delete(key string) error {
	r.mu.Lock()
	ifindex, ok := r.snapshots[key]
	r.mu.Unlock()
	if !ok {
		return nil
	}

	if err := r.deleteEntries(ifindex); err != nil {
		return err
	}

	r.mu.Lock()
	delete(r.snapshots, key)
	r.mu.Unlock()
	return nil
}

func (r *PodIface) deleteEntries(ifindex uint32) error {
	if err := r.podEgress.Objs.IfindexSubnet.Delete(&bpf.PodEgressIfindexSubnetKey{Ifindex: ifindex}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete IfindexSubnet: %w", err)
	}
	if err := r.podEgress.Objs.IfindexHostMac.Delete(&bpf.PodEgressIfindexHostMacKey{Ifindex: ifindex}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete IfindexHostMac: %w", err)
	}
	return nil
}
