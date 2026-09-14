package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/ownedaddr"
)

const elasticIPDirectScope = "elastic-ip-direct"

// ElasticIPDirect makes every node take the ElasticIP a Pod NIC carries
// directly, and tells node_ingress which network to find the NIC on.
// Keyed by NetworkEndpoint namespace/name, for endpoints on every node:
// BGP ECMP lands a packet for the address on any node, and a Pod on any
// node may send to it.
//
// Each address needs two entries:
//
//   - elastic_ip_direct[address] = network ID, which node_ingress reads
//     after the NAT dispositions to find the NIC in arp_table and fdb.
//   - a /32 in external_address_pools, the gate node_ingress checks first.
//     It is claimed through ownedaddr.Store under a scope of its own: in
//     ARP mode the external-arp reconciler claims the same /32 on the
//     node the Pod runs on, and in BGP mode the bgp-pool reconciler claims
//     the pool around it.
//
// Two endpoints can carry one address for a while: a node that dies keeps
// its NetworkEndpoints until something removes them, and the ElasticIP
// may already be on a NIC somewhere else. The address stays programmed
// until the last of them goes.
type ElasticIPDirect struct {
	client client.Client
	direct bpfMap
	owned  *ownedaddr.Scope

	mu        sync.Mutex
	claims    map[string]elasticIPDirectClaim // endpoint key -> what it carries
	installed map[uint32]uint32               // address -> network ID in elastic_ip_direct
}

// elasticIPDirectClaim is the ElasticIP one endpoint carries.
type elasticIPDirectClaim struct {
	address   uint32 // host byte order, as elastic_ip_direct is keyed
	prefix    ownedaddr.Key
	networkID uint32
}

func NewElasticIPDirect(cl client.Client, podEgress *program.PodEgress, owned *ownedaddr.Store) *ElasticIPDirect {
	return newElasticIPDirect(cl, podEgress.Objs.ElasticIpDirect, owned)
}

func newElasticIPDirect(cl client.Client, direct bpfMap, owned *ownedaddr.Store) *ElasticIPDirect {
	return &ElasticIPDirect{
		client:    cl,
		direct:    direct,
		owned:     owned.Scope(elasticIPDirectScope),
		claims:    make(map[string]elasticIPDirectClaim),
		installed: make(map[uint32]uint32),
	}
}

func (r *ElasticIPDirect) Name() string { return "elastic-ip-direct" }

func (r *ElasticIPDirect) Reconcile(ctx context.Context, key string) error {
	namespace, name, err := toolscache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	var nwep juneauv1alpha1.NetworkEndpoint
	err = r.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &nwep)
	if apierrors.IsNotFound(err) {
		return r.release(key)
	}
	if err != nil {
		return err
	}

	network, err := endpointNetworkOf(&nwep)
	if err != nil {
		return err
	}
	if network != endpointOnExternalNetwork {
		return r.release(key)
	}

	networkID, ready, err := overlaySegmentID(ctx, r.client, &nwep, network)
	if err != nil {
		return err
	}
	if !ready {
		return r.release(key)
	}

	claim, err := newElasticIPDirectClaim(nwep.Spec.Address, networkID)
	if err != nil {
		return fmt.Errorf("endpoint %s: %w", key, err)
	}
	return r.claim(key, claim)
}

// FanOutExternalNetworkToEndpoints re-enqueues the endpoints of an
// ExternalNetwork, whose network ID their entries carry.
func (r *ElasticIPDirect) FanOutExternalNetworkToEndpoints(obj any) []string {
	return externalNetworkEndpointKeys(r.client, obj)
}

// newElasticIPDirectClaim reads the address of an endpoint on an
// ExternalNetwork. The CNI writes it as the /32 of the ElasticIP; a bare
// address is accepted too, the way the other readers of the field do.
func newElasticIPDirectClaim(address string, networkID uint32) (elasticIPDirectClaim, error) {
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		addr, addrErr := netip.ParseAddr(address)
		if addrErr != nil {
			return elasticIPDirectClaim{}, fmt.Errorf("address %q is not an IP address: %w", address, err)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if !prefix.Addr().Is4() || prefix.Bits() != 32 {
		return elasticIPDirectClaim{}, fmt.Errorf("address %q is not one IPv4 address", address)
	}

	hostOrder, err := convert.IPv4ToUint32(net.IP(prefix.Addr().AsSlice()))
	if err != nil {
		return elasticIPDirectClaim{}, err
	}
	key, err := ownedaddr.ParsePrefix(prefix.String())
	if err != nil {
		return elasticIPDirectClaim{}, err
	}
	return elasticIPDirectClaim{address: hostOrder, prefix: key, networkID: networkID}, nil
}

// claim programs what one endpoint carries. The entry goes in before the
// gate opens, so a packet let through by the gate always finds it.
func (r *ElasticIPDirect) claim(key string, claim elasticIPDirectClaim) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if holder, networkID, found := r.otherNetworkFor(key, claim); found {
		return fmt.Errorf("endpoint %s carries %s on network %d, but endpoint %s carries it on network %d",
			key, claim.prefix, claim.networkID, holder, networkID)
	}

	previous, hadPrevious := r.claims[key]
	if err := r.install(claim.address, claim.networkID); err != nil {
		return err
	}
	r.claims[key] = claim
	if err := r.owned.Set(key, []ownedaddr.Key{claim.prefix}); err != nil {
		return err
	}
	if hadPrevious && previous.address != claim.address {
		return r.uninstallUnclaimed(previous.address)
	}
	return nil
}

// release gives back what one endpoint carried. The gate closes before the
// entry goes, the reverse of claim.
func (r *ElasticIPDirect) release(key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	previous, hadPrevious := r.claims[key]
	if !hadPrevious {
		return nil
	}
	if err := r.owned.Release(key); err != nil {
		return err
	}
	delete(r.claims, key)
	return r.uninstallUnclaimed(previous.address)
}

// otherNetworkFor finds an endpoint other than key that carries the same
// address on a different network. The caller must hold r.mu. Endpoints are
// visited in key order so the error names the same one every time.
func (r *ElasticIPDirect) otherNetworkFor(key string, claim elasticIPDirectClaim) (string, uint32, bool) {
	holders := make([]string, 0, len(r.claims))
	for holder := range r.claims {
		holders = append(holders, holder)
	}
	sort.Strings(holders)
	for _, holder := range holders {
		other := r.claims[holder]
		if holder != key && other.address == claim.address && other.networkID != claim.networkID {
			return holder, other.networkID, true
		}
	}
	return "", 0, false
}

// install writes one entry unless the map already holds it. The caller
// must hold r.mu.
func (r *ElasticIPDirect) install(address, networkID uint32) error {
	if installed, ok := r.installed[address]; ok && installed == networkID {
		return nil
	}
	key := bpf.PodEgressElasticIpDirectKey{Addr: address}
	val := bpf.PodEgressElasticIpDirectVal{NetworkId: networkID}
	if err := r.direct.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update elastic_ip_direct[%s]: %w", convert.Uint32ToIPv4(address), err)
	}
	r.installed[address] = networkID
	return nil
}

// uninstallUnclaimed removes the entry of an address no endpoint carries
// any more. The caller must hold r.mu.
func (r *ElasticIPDirect) uninstallUnclaimed(address uint32) error {
	for _, claim := range r.claims {
		if claim.address == address {
			return nil
		}
	}
	key := bpf.PodEgressElasticIpDirectKey{Addr: address}
	if err := r.direct.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete elastic_ip_direct[%s]: %w", convert.Uint32ToIPv4(address), err)
	}
	delete(r.installed, address)
	return nil
}

// CloseAll removes every entry and claim this reconciler made.
func (r *ElasticIPDirect) CloseAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	if err := r.owned.ReleaseAll(); err != nil {
		errs = append(errs, err)
	}
	r.claims = make(map[string]elasticIPDirectClaim)
	for address := range r.installed {
		if err := r.uninstallUnclaimed(address); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
