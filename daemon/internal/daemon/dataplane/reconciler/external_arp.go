package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/ownedaddr"
)

const externalArpScope = "external-arp"

// externalArpResponder is the interface this node answers ARP on and
// the MAC it answers with. The BPF key carries the ifindex so a node
// that later faces two external links can answer different addresses
// on each one without a map layout change.
type externalArpResponder struct {
	ifindex uint32
	mac     [6]uint8
}

// ExternalArp makes this node answer ARP for the external addresses
// the control plane gave it. Keyed by ARPAdvertisement name.
//
// Which advertisements belong to this node is decided by
// spec.nodeName, never by the object's name: a consumer moves an
// address by rewriting spec.nodeName in place, so the same object can
// be ours on one event and somebody else's on the next. A deleted
// advertisement means nobody answers for that address any more (an
// ElasticIP was detached, a ServiceLoadBalancer lost every backend),
// so its entry goes away at once.
//
// Each owned address needs two map entries:
//
//   - external_arp_table[(ifindex, address)] = responder MAC, which
//     node_ingress uses to build the ARP reply.
//   - a /32 in external_address_pools, the gate node_ingress checks
//     before reverse NAPT and ElasticIP DNAT. It is claimed through
//     ownedaddr.Store because the NAPT reconciler claims the very same
//     /32 for an ExternalNetworkAttachment address.
type ExternalArp struct {
	client    client.Client
	arpTable  bpfMap
	owned     *ownedaddr.Scope
	nodeName  string
	responder externalArpResponder

	mu        sync.Mutex
	installed map[string]bpf.PodEgressExternalArpKey
}

func NewExternalArp(
	cl client.Client,
	podEgress *program.PodEgress,
	owned *ownedaddr.Store,
	nodeName string,
	nodeIngressIfindex int,
	nodeIngressMac net.HardwareAddr,
) (*ExternalArp, error) {
	responder, err := newExternalArpResponder(nodeIngressIfindex, nodeIngressMac)
	if err != nil {
		return nil, err
	}
	return &ExternalArp{
		client:    cl,
		arpTable:  podEgress.Objs.ExternalArpTable,
		owned:     owned.Scope(externalArpScope),
		nodeName:  nodeName,
		responder: responder,
		installed: make(map[string]bpf.PodEgressExternalArpKey),
	}, nil
}

func newExternalArpResponder(ifindex int, mac net.HardwareAddr) (externalArpResponder, error) {
	var responder externalArpResponder
	if ifindex <= 0 {
		return responder, fmt.Errorf("node ingress ifindex %d is not a usable interface index", ifindex)
	}
	hardwareAddr, err := convert.HardwareAddrToUint8Array(mac)
	if err != nil {
		return responder, fmt.Errorf("node ingress MAC %q: %w", mac, err)
	}
	return externalArpResponder{ifindex: uint32(ifindex), mac: hardwareAddr}, nil
}

func (r *ExternalArp) Name() string { return "external-arp" }

func (r *ExternalArp) Reconcile(ctx context.Context, key string) error {
	var advertisement juneauv1alpha1.ARPAdvertisement
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &advertisement)
	if apierrors.IsNotFound(err) {
		return r.release(key)
	}
	if err != nil {
		return err
	}

	if advertisement.Spec.NodeName != r.nodeName {
		return r.release(key)
	}

	return r.program(ctx, key, &advertisement)
}

func (r *ExternalArp) program(ctx context.Context, name string, advertisement *juneauv1alpha1.ARPAdvertisement) error {
	if err := r.checkExternalNetwork(ctx, advertisement); err != nil {
		return fmt.Errorf("ARPAdvertisement %q: %w", name, err)
	}

	address := strings.TrimSpace(advertisement.Spec.Address)
	desired, poolKey, err := r.buildEntry(address)
	if err != nil {
		return fmt.Errorf("ARPAdvertisement %q: spec.address %q: %w", name, advertisement.Spec.Address, err)
	}

	r.mu.Lock()
	stale, hadStale := r.installed[name]
	r.mu.Unlock()

	if hadStale && stale != desired {
		if err := r.deleteEntry(stale); err != nil {
			return err
		}
	}

	// Claim the gate before answering ARP for the address. The reply
	// invites traffic, and until external_address_pools holds the /32
	// node_ingress hands those packets to the host stack instead of
	// reverse NAPT and ElasticIP DNAT.
	if err := r.owned.Set(name, []ownedaddr.Key{poolKey}); err != nil {
		return err
	}

	val := bpf.PodEgressExternalArpVal{Mac: r.responder.mac}
	if err := r.arpTable.Update(&desired, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update external_arp_table[if %d, %s]: %w", desired.Ifindex, address, err)
	}

	r.mu.Lock()
	r.installed[name] = desired
	r.mu.Unlock()

	if !hadStale || stale != desired {
		zap.S().Infof("external-arp: %s now answers %s on ifindex %d", name, address, desired.Ifindex)
	}
	return nil
}

func (r *ExternalArp) buildEntry(address string) (bpf.PodEgressExternalArpKey, ownedaddr.Key, error) {
	var (
		entry   bpf.PodEgressExternalArpKey
		poolKey ownedaddr.Key
	)

	ip := net.ParseIP(address)
	if ip == nil {
		return entry, poolKey, errors.New("not an IP address")
	}
	ipaddr, err := convert.IPv4ToUint32(ip)
	if err != nil {
		return entry, poolKey, err
	}
	poolKey, err = ownedaddr.ParsePrefix(address)
	if err != nil {
		return entry, poolKey, err
	}

	entry = bpf.PodEgressExternalArpKey{Ifindex: r.responder.ifindex, Ipaddr: ipaddr}
	return entry, poolKey, nil
}

func (r *ExternalArp) checkExternalNetwork(ctx context.Context, advertisement *juneauv1alpha1.ARPAdvertisement) error {
	var externalNetwork juneauv1alpha1.ExternalNetwork
	if err := r.client.Get(ctx, client.ObjectKey{Name: advertisement.Spec.ExternalNetwork}, &externalNetwork); err != nil {
		return fmt.Errorf("get ExternalNetwork %q: %w", advertisement.Spec.ExternalNetwork, err)
	}
	if externalNetwork.Spec.Type != juneauv1alpha1.ExternalNetworkTypeARP {
		return fmt.Errorf(
			"ExternalNetwork %q has spec.type=%q, want %q",
			externalNetwork.Name,
			externalNetwork.Spec.Type,
			juneauv1alpha1.ExternalNetworkTypeARP,
		)
	}
	return nil
}

// release stops answering for an advertisement and gives its address
// back. The ARP entry goes first so the node stops attracting traffic
// it no longer forwards.
func (r *ExternalArp) release(name string) error {
	r.mu.Lock()
	entry, installed := r.installed[name]
	delete(r.installed, name)
	r.mu.Unlock()

	var errs []error
	if installed {
		if err := r.deleteEntry(entry); err != nil {
			errs = append(errs, err)
		}
	}
	if err := r.owned.Release(name); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (r *ExternalArp) deleteEntry(entry bpf.PodEgressExternalArpKey) error {
	if err := r.arpTable.Delete(&entry); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete external_arp_table[if %d, %s]: %w",
			entry.Ifindex, convert.Uint32ToIPv4(entry.Ipaddr), err)
	}
	return nil
}

// FanOutExternalNetworkToAdvertisements re-enqueues every
// ARPAdvertisement backed by the changed ExternalNetwork. An
// ExternalNetwork that appears late, or whose spec.type is wrong,
// decides whether the advertisement may be programmed at all, so its
// events must reach the reconciler.
func (r *ExternalArp) FanOutExternalNetworkToAdvertisements(obj any) []string {
	externalNetwork, ok := obj.(*juneauv1alpha1.ExternalNetwork)
	if !ok {
		return nil
	}

	var advertisementList juneauv1alpha1.ARPAdvertisementList
	if err := r.client.List(context.Background(), &advertisementList); err != nil {
		zap.S().Warnf("external-arp: list ARPAdvertisements for externalnetwork %q fan-out: %v", externalNetwork.Name, err)
		return nil
	}
	keys := make([]string, 0, len(advertisementList.Items))
	for i := range advertisementList.Items {
		advertisement := &advertisementList.Items[i]
		if advertisement.Spec.ExternalNetwork != externalNetwork.Name {
			continue
		}
		keys = append(keys, advertisement.Name)
	}
	return keys
}

// CloseAll removes every entry this reconciler installed across all
// advertisements.
func (r *ExternalArp) CloseAll() error {
	r.mu.Lock()
	installed := r.installed
	r.installed = make(map[string]bpf.PodEgressExternalArpKey)
	r.mu.Unlock()

	var errs []error
	for _, entry := range installed {
		if err := r.deleteEntry(entry); err != nil {
			errs = append(errs, err)
		}
	}
	if err := r.owned.ReleaseAll(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
