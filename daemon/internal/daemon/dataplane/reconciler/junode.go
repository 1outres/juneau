package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// JuneauNode keeps the local node's juneau_node iface registered in the
// data plane: ifindex_subnet, arp_table, and fdb entries that let pods
// in the default Subnet reach (and reply to) the host's pseudo-pod.
//
// The reconciler is keyed on the default Subnet name; it is awakened
// whenever the Subnet's VNI flips. Static node-local data (the iface's
// ifindex, host-side MAC, and assigned IP) is provided at construction.
type JuneauNode struct {
	client     client.Client
	hostEgress *program.PodEgress

	subnetName  string
	ifindex     uint32
	hostSideMAC [6]uint8
	assignedIP  uint32 // network byte order
	nodeIP      uint32 // network byte order

	mu     sync.Mutex
	last   *juneauNodeSnapshot
}

type juneauNodeSnapshot struct {
	vni uint32
}

// NewJuneauNode constructs a JuneauNode reconciler. assignedIP and
// nodeIP must be in network byte order (big-endian uint32).
func NewJuneauNode(
	cl client.Client,
	hostEgress *program.PodEgress,
	subnetName string,
	ifindex uint32,
	hostSideMAC net.HardwareAddr,
	assignedIP net.IP,
	nodeIP net.IP,
) (*JuneauNode, error) {
	macArr, err := convert.HardwareAddrToUint8Array(hostSideMAC)
	if err != nil {
		return nil, fmt.Errorf("convert juneau_node host-side MAC: %w", err)
	}
	assignedIP4 := assignedIP.To4()
	if assignedIP4 == nil {
		return nil, fmt.Errorf("juneau_node assignedIP must be IPv4: %v", assignedIP)
	}
	assignedHost, err := convert.IPv4ToUint32(assignedIP4)
	if err != nil {
		return nil, fmt.Errorf("convert juneau_node assignedIP: %w", err)
	}

	var nodeIP4U32 uint32
	if nodeIP != nil {
		ip4 := nodeIP.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("nodeIP must be IPv4: %v", nodeIP)
		}
		nodeIP4U32, err = convert.IPv4ToUint32(ip4)
		if err != nil {
			return nil, fmt.Errorf("convert nodeIP: %w", err)
		}
	}

	return &JuneauNode{
		client:      cl,
		hostEgress:  hostEgress,
		subnetName:  subnetName,
		ifindex:     ifindex,
		hostSideMAC: macArr,
		assignedIP:  assignedHost,
		nodeIP:      nodeIP4U32,
	}, nil
}

func (r *JuneauNode) Name() string { return "juneau-node" }

func (r *JuneauNode) Reconcile(ctx context.Context, key string) error {
	if key != r.subnetName {
		return nil
	}

	var subnet juneauv1alpha1.Subnet
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &subnet)
	if apierrors.IsNotFound(err) {
		return r.deleteAll()
	}
	if err != nil {
		return err
	}

	if subnet.Status.VNI == 0 {
		return nil
	}

	desired := &juneauNodeSnapshot{vni: subnet.Status.VNI}

	r.mu.Lock()
	old := r.last
	r.mu.Unlock()

	if old != nil && old.vni != desired.vni {
		if err := r.cleanup(old); err != nil {
			return err
		}
	}

	if err := r.hostEgress.Objs.IfindexSubnet.Update(
		&bpf.PodEgressIfindexSubnetKey{Ifindex: r.ifindex},
		&bpf.PodEgressIfindexSubnetVal{SubnetId: desired.vni},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update ifindex_subnet for juneau_node: %w", err)
	}

	if err := r.hostEgress.Objs.ArpTable.Update(
		&bpf.PodEgressArpTableKey{SubnetId: desired.vni, Ipaddr: r.assignedIP},
		&bpf.PodEgressArpTableVal{Mac: r.hostSideMAC},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update arp_table for juneau_node: %w", err)
	}

	// Local fdb entry: redirect to juneau_node ifindex.
	if err := r.hostEgress.Objs.Fdb.Update(
		&bpf.PodEgressFdbKey{SubnetId: desired.vni, Mac: r.hostSideMAC},
		&bpf.PodEgressFdbVal{Ifindex: r.ifindex, VtepIp: r.nodeIP},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update fdb for juneau_node: %w", err)
	}

	r.mu.Lock()
	r.last = desired
	r.mu.Unlock()
	return nil
}

func (r *JuneauNode) deleteAll() error {
	r.mu.Lock()
	old := r.last
	r.last = nil
	r.mu.Unlock()
	if old == nil {
		return nil
	}
	return r.cleanup(old)
}

func (r *JuneauNode) cleanup(snap *juneauNodeSnapshot) error {
	var errs []error
	if err := r.hostEgress.Objs.IfindexSubnet.Delete(&bpf.PodEgressIfindexSubnetKey{Ifindex: r.ifindex}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, fmt.Errorf("delete ifindex_subnet for juneau_node: %w", err))
	}
	if err := r.hostEgress.Objs.ArpTable.Delete(&bpf.PodEgressArpTableKey{SubnetId: snap.vni, Ipaddr: r.assignedIP}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, fmt.Errorf("delete arp_table for juneau_node: %w", err))
	}
	if err := r.hostEgress.Objs.Fdb.Delete(&bpf.PodEgressFdbKey{SubnetId: snap.vni, Mac: r.hostSideMAC}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, fmt.Errorf("delete fdb for juneau_node: %w", err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// CloseAll removes every entry this reconciler installed. Called on
// daemon shutdown.
func (r *JuneauNode) CloseAll() error {
	return r.deleteAll()
}
