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

// PodIface keeps the per-veth maps in sync with local NetworkEndpoint
// objects (NodeName==self with Attachment populated): IfindexHostMac for
// every such endpoint, plus the entry that names the network behind the
// veth, IfindexSubnet for a Subnet and IfindexExternalNetwork for an
// ExternalNetwork. Remote endpoints and Attachment-less endpoints are
// ignored; any stale local entry from a previous reconcile is cleaned up
// if the endpoint is reassigned to another node or its attachment
// disappears. Kind-agnostic: any endpoint with a real local veth (Pod,
// Node, …) is handled here.
type PodIface struct {
	client                 client.Client
	ifindexSubnet          bpfMap
	ifindexExternalNetwork bpfMap
	ifindexHostMac         bpfMap
	nodeName               string

	mu        sync.Mutex
	snapshots map[string]uint32 // NWEP key -> ifindex we last wrote for
}

func NewPodIface(cl client.Client, podEgress *program.PodEgress, nodeName string) *PodIface {
	return &PodIface{
		client:                 cl,
		ifindexSubnet:          podEgress.Objs.IfindexSubnet,
		ifindexExternalNetwork: podEgress.Objs.IfindexExternalNetwork,
		ifindexHostMac:         podEgress.Objs.IfindexHostMac,
		nodeName:               nodeName,
		snapshots:              make(map[string]uint32),
	}
}

func (r *PodIface) Name() string { return "pod-iface" }

// vethNetwork is the entry that names the network behind a veth. Exactly
// one of the two is set: pod_egress and pod_ingress read the kind of a
// veth from which map holds its ifindex.
type vethNetwork struct {
	subnet          *bpf.PodEgressIfindexSubnetVal
	externalNetwork *bpf.PodEgressIfindexExternalNetworkVal
}

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

	if nwep.Spec.NodeName != r.nodeName || nwep.Spec.Attachment == nil {
		return r.delete(key)
	}
	network, err := endpointNetworkOf(&nwep)
	if err != nil {
		return err
	}
	if network == endpointOnL2Network {
		// An endpoint on an L2Network is left alone: the L2 data plane
		// keys its own tables and reads none of what this writes.
		return r.delete(key)
	}

	entry, ready, err := r.vethNetworkEntry(ctx, key, &nwep, network)
	if err != nil {
		return err
	}
	if !ready {
		return r.delete(key)
	}
	return r.upsert(key, &nwep, entry)
}

// FanOutExternalNetworkToEndpoints re-enqueues the endpoints of an
// ExternalNetwork, whose network ID their ifindex_external_network entry
// carries.
func (r *PodIface) FanOutExternalNetworkToEndpoints(obj any) []string {
	return externalNetworkEndpointKeys(r.client, obj)
}

// vethNetworkEntry builds the entry that names the network behind the veth
// of a local endpoint.
//
// ready is false while an ExternalNetwork is missing or has no network ID
// yet; see overlaySegmentID. The veth is then named by nothing, so
// pod_egress drops what the Pod sends until the number lands.
func (r *PodIface) vethNetworkEntry(ctx context.Context, key string, nwep *juneauv1alpha1.NetworkEndpoint, network endpointNetwork) (vethNetwork, bool, error) {
	ipv4BE, err := endpointAddressToBE(nwep.Spec.Address)
	if err != nil {
		return vethNetwork{}, false, fmt.Errorf("endpoint %s: %w", key, err)
	}

	switch network {
	case endpointOnSubnet:
		var subnet juneauv1alpha1.Subnet
		if err := r.client.Get(ctx, client.ObjectKey{Name: nwep.Spec.Subnet}, &subnet); err != nil {
			return vethNetwork{}, false, err
		}
		return vethNetwork{
			subnet: &bpf.PodEgressIfindexSubnetVal{SubnetId: subnet.Status.VNI, Ipv4: ipv4BE},
		}, true, nil
	case endpointOnExternalNetwork:
		networkID, ready, err := overlaySegmentID(ctx, r.client, nwep, network)
		if err != nil || !ready {
			return vethNetwork{}, false, err
		}
		return vethNetwork{
			externalNetwork: &bpf.PodEgressIfindexExternalNetworkVal{NetworkId: networkID, Ipv4: ipv4BE},
		}, true, nil
	default:
		return vethNetwork{}, false, fmt.Errorf("endpoint %s: a %s names no network behind its veth", key, network)
	}
}

// upsert writes the host MAC of the veth and the entry that names its
// network, and removes an entry of the other kind at the same ifindex.
//
// The host MAC goes in first. pod_egress and pod_ingress answer and stamp
// frames of an ExternalNetwork veth with it, so it has to be there by the
// time the veth is named.
func (r *PodIface) upsert(key string, nwep *juneauv1alpha1.NetworkEndpoint, entry vethNetwork) error {
	hostMAC, err := net.ParseMAC(nwep.Spec.Attachment.HostMACAddress)
	if err != nil {
		return err
	}
	hostMACArray, err := convert.HardwareAddrToUint8Array(hostMAC)
	if err != nil {
		return err
	}

	newIfindex := uint32(nwep.Spec.Attachment.Ifindex)

	r.mu.Lock()
	oldIfindex, hadOld := r.snapshots[key]
	r.mu.Unlock()

	if hadOld && oldIfindex != newIfindex {
		if err := r.deleteEntries(oldIfindex); err != nil {
			return err
		}
	}

	if err := r.ifindexHostMac.Update(
		&bpf.PodEgressIfindexHostMacKey{Ifindex: newIfindex},
		&bpf.PodEgressIfindexHostMacVal{Mac: hostMACArray},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update IfindexHostMac: %w", err)
	}

	switch {
	case entry.subnet != nil:
		if err := r.deleteExternalNetworkEntry(newIfindex); err != nil {
			return err
		}
		if err := r.ifindexSubnet.Update(
			&bpf.PodEgressIfindexSubnetKey{Ifindex: newIfindex},
			entry.subnet,
			ebpf.UpdateAny,
		); err != nil {
			return fmt.Errorf("update IfindexSubnet: %w", err)
		}
	case entry.externalNetwork != nil:
		if err := r.deleteSubnetEntry(newIfindex); err != nil {
			return err
		}
		if err := r.ifindexExternalNetwork.Update(
			&bpf.PodEgressIfindexExternalNetworkKey{Ifindex: newIfindex},
			entry.externalNetwork,
			ebpf.UpdateAny,
		); err != nil {
			return fmt.Errorf("update IfindexExternalNetwork: %w", err)
		}
	default:
		return fmt.Errorf("endpoint %s: no network entry to write for ifindex %d", key, newIfindex)
	}

	r.mu.Lock()
	r.snapshots[key] = newIfindex
	r.mu.Unlock()
	return nil
}

// endpointAddressToBE turns a NetworkEndpoint L3 identity into the
// __be32 the data plane compares against iph->saddr / iph->daddr. The
// identity is written in CIDR form ("10.0.0.5/24"), so the host part
// names the NIC; a bare address is accepted too.
//
// An endpoint the data plane cannot name by address cannot be looked
// up in sg_membership_map, so an unusable value is an error and not a
// zero entry. A zero would read as a different NIC and let the policy
// stage skip the rules this one is behind.
func endpointAddressToBE(address string) (uint32, error) {
	if address == "" {
		return 0, errors.New("endpoint has no address")
	}
	ip := net.ParseIP(address)
	if ip == nil {
		hostIP, _, err := net.ParseCIDR(address)
		if err != nil {
			return 0, fmt.Errorf("parse endpoint address %q: %w", address, err)
		}
		ip = hostIP
	}
	return convert.IPv4ToBPFNetworkOrder(ip)
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

// deleteEntries removes every entry of a veth. The network entries go
// before the host MAC, the reverse of upsert.
func (r *PodIface) deleteEntries(ifindex uint32) error {
	if err := r.deleteSubnetEntry(ifindex); err != nil {
		return err
	}
	if err := r.deleteExternalNetworkEntry(ifindex); err != nil {
		return err
	}
	if err := r.ifindexHostMac.Delete(&bpf.PodEgressIfindexHostMacKey{Ifindex: ifindex}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete IfindexHostMac: %w", err)
	}
	return nil
}

func (r *PodIface) deleteSubnetEntry(ifindex uint32) error {
	if err := r.ifindexSubnet.Delete(&bpf.PodEgressIfindexSubnetKey{Ifindex: ifindex}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete IfindexSubnet: %w", err)
	}
	return nil
}

func (r *PodIface) deleteExternalNetworkEntry(ifindex uint32) error {
	if err := r.ifindexExternalNetwork.Delete(&bpf.PodEgressIfindexExternalNetworkKey{Ifindex: ifindex}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete IfindexExternalNetwork: %w", err)
	}
	return nil
}
