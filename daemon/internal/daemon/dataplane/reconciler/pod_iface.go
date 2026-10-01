package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"
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
const ifindexSubnetKindTrustedGateway = 1

type PodIface struct {
	client                 client.Client
	ifindexSubnet          bpfMap
	ifindexExternalNetwork bpfMap
	ifindexHostMac         bpfMap
	vpnGateway             bpfMap
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
		vpnGateway:             podEgress.Objs.VpnGateway,
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
	if err := r.deleteVPNGateway(uint32(nwep.Spec.Attachment.Ifindex)); err != nil {
		return err
	}
	identity, err := r.gatewayIdentity(ctx, &nwep)
	if err != nil {
		return err
	}
	if err := r.upsert(key, &nwep, entry); err != nil {
		return err
	}
	if identity != nil {
		if err := r.vpnGateway.Update(&bpf.PodEgressVpnGatewayKey{Ifindex: uint32(nwep.Spec.Attachment.Ifindex)}, &bpf.PodEgressVpnIdentity{Bytes: *identity}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update VpnGateway: %w", err)
		}
	}
	return nil
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
		value := &bpf.PodEgressIfindexSubnetVal{SubnetId: subnet.Status.VNI, Ipv4: ipv4BE}
		if nwep.Spec.Kind == juneauv1alpha1.EndpointKindNode {
			value.Kind = ifindexSubnetKindTrustedGateway
		}
		return vethNetwork{subnet: value}, true, nil
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
	if err := r.deleteVPNGateway(ifindex); err != nil {
		return err
	}
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

func (r *PodIface) deleteVPNGateway(ifindex uint32) error {
	if err := r.vpnGateway.Delete(&bpf.PodEgressVpnGatewayKey{Ifindex: ifindex}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete VpnGateway: %w", err)
	}
	return nil
}

func (r *PodIface) gatewayIdentity(ctx context.Context, ep *juneauv1alpha1.NetworkEndpoint) (*[16]uint8, error) {
	if ep.Spec.PodRef == nil || ep.Spec.PodRef.Interface != "eth0" || ep.Spec.Kind != juneauv1alpha1.EndpointKindPod || ep.Spec.Subnet == "" {
		return nil, nil
	}
	var pod corev1.Pod
	if err := r.client.Get(ctx, client.ObjectKey{Namespace: ep.Namespace, Name: ep.Spec.PodRef.Name}, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if pod.UID == "" || string(pod.UID) != ep.Spec.PodRef.UID {
		return nil, nil
	}
	for _, owner := range pod.OwnerReferences {
		if owner.Kind != "VPN" || owner.Name == "" {
			continue
		}
		var vpn juneauv1alpha1.VPN
		if err := r.client.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, &vpn); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		if vpn.UID == "" || vpn.UID != owner.UID {
			return nil, nil
		}
		_, gatewayPod, _, endpoint, err := resolveVPNGateway(ctx, r.client, &vpn)
		if err != nil || gatewayPod.UID != pod.UID || endpoint.Name != ep.Name {
			return nil, nil
		}
		identity := vpnIdentity(vpn.UID)
		return &identity, nil
	}
	return nil, nil
}

func (r *PodIface) FanOutGatewayEndpoints(obj any) []string {
	var targetNamespace, targetPod string
	switch item := obj.(type) {
	case *corev1.Pod:
		if strings.HasPrefix(item.Name, "vpn-") {
			targetNamespace, targetPod = item.Namespace, item.Name
		}
	case *juneauv1alpha1.NetworkInterface:
		if strings.HasPrefix(item.Name, "vpn-") && strings.HasSuffix(item.Name, ".eth0") {
			targetNamespace, targetPod = item.Namespace, strings.TrimSuffix(item.Name, ".eth0")
		}
	case *juneauv1alpha1.VPN:
		if item.UID != "" {
			targetNamespace, targetPod = item.Namespace, vpnGatewayPodName(item)
		}
	}
	if targetNamespace == "" || targetPod == "" {
		return nil
	}
	var endpoints juneauv1alpha1.NetworkEndpointList
	if err := r.client.List(context.Background(), &endpoints); err != nil {
		return nil
	}
	var keys []string
	for i := range endpoints.Items {
		ep := &endpoints.Items[i]
		if ep.Namespace != targetNamespace || ep.Name != targetPod+".eth0" {
			continue
		}
		keys = append(keys, ep.Namespace+"/"+ep.Name)
	}
	return keys
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
