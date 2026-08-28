package reconciler

import (
	"context"
	"fmt"
	"net"
	"sync"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
)

// l2ArpTable is what L2Arp needs of l2_arp. The two writes are offers
// rather than assignments: one only lands on a key nothing holds, the
// other only takes back an entry that still says what it wrote.
type l2ArpTable interface {
	l2NetworkTable
	PutIfAbsent(vni uint32, key, value any) error
	RemoveIfEqual(vni uint32, key, value any) error
}

// L2Arp offers the gateway of a segment the addresses the controller
// already handed out.
//
// The gateway resolves a destination address to a MAC out of l2_arp,
// and the data plane fills that table from the ARP it sees: frames a
// local port sent, and frames the overlay delivered. A node holding no
// port on the segment sees neither, because nothing lists it as a place
// to flood to. Its gateway is there — every node runs one for a segment
// that declares a gateway — but it can address nobody, so a packet
// routed into the segment on that node dies at the resolution.
//
// The controller knows what is missing. A segment with a gateway always
// has a CIDR, so every NIC on it carries an address, and the
// NetworkEndpoint that names the NIC carries the MAC. Writing that down
// is enough: with the address resolved, an unknown MAC floods over the
// overlay to the nodes that do hold ports, and one of them delivers.
//
// This is not the controller writing the forwarding table. l2_fdb stays
// fully learned, for the reasons the design gives: a NIC with a bridge
// or a nested VM behind it speaks for MACs juneau never handed out.
// l2_arp is the neighbor table of a port juneau built itself, and what
// goes in it is the same kind of thing as the static entry for the
// gateway's own MAC.
//
// The seed never wins over the data plane. It is written only where
// nothing is recorded yet, and taken back only while it still says what
// this reconciler wrote. A workload that speaks for its address under
// another MAC corrects the entry with its first frame and keeps it.
type L2Arp struct {
	client client.Client
	arp    l2ArpTable

	mu        sync.Mutex
	snapshots map[string]l2ArpSeed
}

// l2ArpSeed is the address one endpoint declares, in the form the
// gateway looks it up by. The zero value means the endpoint offers
// nothing.
type l2ArpSeed struct {
	vni  uint32
	ipv4 uint32
	mac  [6]uint8
}

func (s l2ArpSeed) valid() bool { return s.vni != 0 && s.ipv4 != 0 }

func (s l2ArpSeed) key() bpf.PodEgressL2ArpKey { return bpf.PodEgressL2ArpKey{Ipv4: s.ipv4} }

func (s l2ArpSeed) value() bpf.PodEgressL2ArpVal { return bpf.PodEgressL2ArpVal{Mac: s.mac} }

func NewL2Arp(cl client.Client, arp l2ArpTable) *L2Arp {
	return &L2Arp{
		client:    cl,
		arp:       arp,
		snapshots: make(map[string]l2ArpSeed),
	}
}

func (r *L2Arp) Name() string { return "l2-arp" }

func (r *L2Arp) Reconcile(ctx context.Context, key string) error {
	namespace, name, err := toolscache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	var endpoint juneauv1alpha1.NetworkEndpoint
	err = r.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &endpoint)
	if apierrors.IsNotFound(err) {
		return r.apply(key, l2ArpSeed{})
	}
	if err != nil {
		return err
	}

	desired, err := r.desiredSeed(ctx, &endpoint)
	if err != nil {
		return err
	}
	return r.apply(key, desired)
}

// desiredSeed reads what an endpoint offers the gateway of its segment.
//
// Everything that comes back empty is a state the cluster passes
// through or a segment this table does not serve: an endpoint on a
// Subnet, a segment with no gateway to read the table, a VNI that has
// not been handed out, a NIC with no address because the segment hands
// out none.
func (r *L2Arp) desiredSeed(ctx context.Context, endpoint *juneauv1alpha1.NetworkEndpoint) (l2ArpSeed, error) {
	if endpoint.Spec.L2Network == "" || endpoint.Spec.Address == "" || endpoint.Spec.MACAddress == "" {
		return l2ArpSeed{}, nil
	}

	var network juneauv1alpha1.L2Network
	err := r.client.Get(ctx, client.ObjectKey{Name: endpoint.Spec.L2Network}, &network)
	if apierrors.IsNotFound(err) {
		return l2ArpSeed{}, nil
	}
	if err != nil {
		return l2ArpSeed{}, err
	}
	if network.Status.VNI == 0 || network.Spec.Gateway == nil {
		return l2ArpSeed{}, nil
	}

	address, err := endpointAddressToHost(endpoint.Spec.Address)
	if err != nil {
		return l2ArpSeed{}, fmt.Errorf("endpoint %s/%s: %w", endpoint.Namespace, endpoint.Name, err)
	}
	mac, err := net.ParseMAC(endpoint.Spec.MACAddress)
	if err != nil {
		return l2ArpSeed{}, fmt.Errorf("parse the MAC of endpoint %s/%s: %w", endpoint.Namespace, endpoint.Name, err)
	}
	array, err := convert.HardwareAddrToUint8Array(mac)
	if err != nil {
		return l2ArpSeed{}, err
	}

	return l2ArpSeed{vni: network.Status.VNI, ipv4: address, mac: array}, nil
}

// apply moves one endpoint from the address it offered to the address
// it offers now. Either may be the zero value, which stands for "it
// offers none".
func (r *L2Arp) apply(key string, desired l2ArpSeed) error {
	r.mu.Lock()
	previous := r.snapshots[key]
	r.mu.Unlock()

	if previous == desired {
		if !desired.valid() {
			return nil
		}
		// Offered again rather than trusted. The table belongs to the
		// L2Network reconciler, so a segment that was deleted and made
		// again leaves this endpoint recorded against a table that no
		// longer holds it.
		return r.arp.PutIfAbsent(desired.vni, desired.key(), desired.value())
	}

	if previous.valid() {
		if err := r.arp.RemoveIfEqual(previous.vni, previous.key(), previous.value()); err != nil {
			return err
		}
		r.mu.Lock()
		delete(r.snapshots, key)
		r.mu.Unlock()
	}

	if !desired.valid() {
		return nil
	}
	if err := r.arp.PutIfAbsent(desired.vni, desired.key(), desired.value()); err != nil {
		return err
	}

	r.mu.Lock()
	r.snapshots[key] = desired
	r.mu.Unlock()
	return nil
}

// endpointAddressToHost turns a NetworkEndpoint address into the number
// l2_arp is keyed on, which is the host-order form the data plane gets
// from bpf_ntohl. The identity is written in CIDR form ("10.60.0.5/24"),
// so the host part names the NIC; a bare address is accepted too.
func endpointAddressToHost(address string) (uint32, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		hostIP, _, err := net.ParseCIDR(address)
		if err != nil {
			return 0, fmt.Errorf("parse endpoint address %q: %w", address, err)
		}
		ip = hostIP
	}
	return convert.IPv4ToUint32(ip)
}

// FanOutL2NetworkToEndpoints re-enqueues every endpoint of the changed
// L2Network. The VNI is handed out after the segment exists and the
// gateway may be added later, and the seed depends on both.
func (r *L2Arp) FanOutL2NetworkToEndpoints(obj any) []string {
	network, ok := l2NetworkFromEvent(obj)
	if !ok {
		return nil
	}

	var list juneauv1alpha1.NetworkEndpointList
	if err := r.client.List(context.Background(), &list); err != nil {
		zap.S().Warnf("l2-arp: list NetworkEndpoints for %q fan-out: %v", network.Name, err)
		return nil
	}
	keys := make([]string, 0, len(list.Items))
	for i := range list.Items {
		endpoint := &list.Items[i]
		if endpoint.Spec.L2Network != network.Name {
			continue
		}
		keys = append(keys, endpoint.Namespace+"/"+endpoint.Name)
	}
	return keys
}
