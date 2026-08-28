package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/l2"
)

// l2GatewayPorts is what L2Gateway needs of the veth pairs behind the
// gateway ports. link.L2GatewayAttacher is the only implementation the
// daemon runs; tests bring their own because building a veth and
// attaching a program to it need CAP_NET_ADMIN and CAP_BPF.
type l2GatewayPorts interface {
	// Ensure brings up the gateway veth of one segment under the given
	// identity and reports the ifindex the kernel gave it.
	Ensure(vni uint32, mac net.HardwareAddr) (uint32, error)
	// Remove takes the veth of one segment down again.
	Remove(vni uint32) error
}

// l2EntryTable is a per-VNI table L2Gateway writes single entries into,
// rather than the membership lists L2Port keeps.
type l2EntryTable interface {
	l2NetworkTable
	Put(vni uint32, key, value any) error
	Remove(vni uint32, key any) error
}

// L2GatewayMaps is everything the gateway port of a segment occupies.
// They are named rather than passed in order because the six of them
// are the whole footprint of one port, and a caller that mixed two up
// would build a gateway that answers for the wrong segment.
type L2GatewayMaps struct {
	// Gateway is l2_gateway: which veth carries the port of a segment
	// on this node, and the MAC it signs with.
	Gateway bpfMap
	// Subnet is subnet_map. The gateway veth runs pod_egress, which
	// reads the route table, the Vpc and the ACL of a boundary out of
	// it exactly as it does for a Subnet.
	Subnet bpfMap
	// IfindexSubnet is ifindex_subnet, which is how pod_egress finds
	// the boundary behind the veth it was called on.
	IfindexSubnet bpfMap
	// Ifindex is l2_ifindex, which is how the L2 programs find the
	// segment behind the same veth.
	Ifindex bpfMap
	// Fdb is l2_fdb, which carries the one entry user space writes:
	// the MAC of this port.
	Fdb l2EntryTable
	// BumLocal is l2_bum_local, so a broadcast on the segment reaches
	// the gateway too. Its entry carries a flag of its own, because the
	// gateway takes its copy on the port's ingress.
	BumLocal l2EntryTable
}

// L2Gateway stands up the router port of an L2Network on this node.
//
// The port is one veth pair in the host namespace. Its ingress runs
// pod_egress and its egress runs l2_gateway, so a packet that leaves
// the segment walks the same RouteTable, NATGateway, Service and
// policy path a Subnet walks, and a packet that comes back is put on
// the segment by the segment's own tables. Nothing else in the Vpc had
// to learn what an L2Network is.
//
// The identity of the port — the address and the MAC — is the
// controller's, published in L2Network.status. Every node that holds a
// port on the segment stands up a port with that same identity, so a
// workload reaches its gateway without leaving its node.
//
// A node that holds no port on the segment builds nothing. There is
// nothing on it to route for, and a veth per segment per node would
// otherwise sit on every node in the cluster.
type L2Gateway struct {
	client   client.Client
	nodeName string
	ports    l2GatewayPorts
	maps     L2GatewayMaps

	mu        sync.Mutex
	snapshots map[string]l2GatewaySnapshot
}

// l2GatewaySnapshot is what a port was last programmed as. The object
// that named it is gone by the time the port comes down, so the keys to
// take out have to be remembered rather than recomputed.
type l2GatewaySnapshot struct {
	vni     uint32
	ifindex uint32
	mac     [6]uint8
}

func NewL2Gateway(cl client.Client, ports l2GatewayPorts, maps L2GatewayMaps, nodeName string) *L2Gateway {
	return &L2Gateway{
		client:    cl,
		nodeName:  nodeName,
		ports:     ports,
		maps:      maps,
		snapshots: make(map[string]l2GatewaySnapshot),
	}
}

func (r *L2Gateway) Name() string { return "l2-gateway" }

func (r *L2Gateway) Reconcile(ctx context.Context, key string) error {
	var network juneauv1alpha1.L2Network
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &network)
	if apierrors.IsNotFound(err) {
		return r.teardown(key)
	}
	if err != nil {
		return err
	}

	port, err := r.desiredPort(ctx, &network)
	if err != nil {
		return err
	}
	if port == nil {
		return r.teardown(key)
	}
	return r.stand(ctx, key, &network, port)
}

// l2GatewayPortSpec is the port a segment asks this node for, read off
// the objects that describe it.
type l2GatewayPortSpec struct {
	vni     uint32
	mac     net.HardwareAddr
	address net.IP
	mask    uint32
	vpcID   uint32
	tableID uint32
	aclID   uint32
}

// desiredPort reads what this node should run for the segment, or nil
// when it should run nothing.
//
// Every reason to run nothing is a state the cluster passes through on
// its way somewhere: a VNI or a MAC that has not been handed out yet, a
// Vpc that has not been numbered, a segment with no port on this node.
// None of them is an error, because the event that resolves them is
// already on its way and failing here would only spin the work queue.
func (r *L2Gateway) desiredPort(ctx context.Context, network *juneauv1alpha1.L2Network) (*l2GatewayPortSpec, error) {
	if network.Status.VNI == 0 || network.Status.Gateway == "" || network.Status.GatewayMAC == "" {
		return nil, nil
	}

	local, err := r.holdsAPort(ctx, network.Name)
	if err != nil {
		return nil, err
	}
	if !local {
		return nil, nil
	}

	mac, err := net.ParseMAC(network.Status.GatewayMAC)
	if err != nil {
		return nil, fmt.Errorf("parse the gateway MAC of %s: %w", network.Name, err)
	}
	address := net.ParseIP(network.Status.Gateway)
	if address == nil {
		return nil, fmt.Errorf("parse the gateway address %q of %s", network.Status.Gateway, network.Name)
	}
	_, prefix, err := net.ParseCIDR(network.Spec.CIDR)
	if err != nil {
		return nil, fmt.Errorf("parse the CIDR of %s: %w", network.Name, err)
	}
	mask, err := convert.IPMaskToUint32(prefix.Mask)
	if err != nil {
		return nil, err
	}

	var vpc juneauv1alpha1.Vpc
	if err := r.client.Get(ctx, client.ObjectKey{Name: network.Spec.Vpc}, &vpc); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	routeTableName := ""
	if network.Spec.Gateway != nil {
		routeTableName = network.Spec.Gateway.RouteTable
	}
	if routeTableName == "" {
		routeTableName = vpc.Status.MainRouteTable
	}
	var routeTable juneauv1alpha1.RouteTable
	if err := r.client.Get(ctx, client.ObjectKey{Name: routeTableName}, &routeTable); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	// A named ACL that has not been given an id yet reads as no ACL,
	// the same way a Subnet reads it. The boundary is default-allow
	// until the controller publishes the number.
	var aclID uint32
	if network.Status.NetworkACL != nil {
		aclID = network.Status.NetworkACL.ACLID
	}

	return &l2GatewayPortSpec{
		vni:     network.Status.VNI,
		mac:     mac,
		address: address,
		mask:    mask,
		vpcID:   vpc.Status.VpcID,
		tableID: routeTable.Status.TableID,
		aclID:   aclID,
	}, nil
}

// holdsAPort reports whether any NetworkEndpoint of the segment sits on
// this node.
func (r *L2Gateway) holdsAPort(ctx context.Context, name string) (bool, error) {
	var list juneauv1alpha1.NetworkEndpointList
	if err := r.client.List(ctx, &list); err != nil {
		return false, err
	}
	for i := range list.Items {
		endpoint := &list.Items[i]
		if endpoint.Spec.L2Network == name && endpoint.Spec.NodeName == r.nodeName {
			return true, nil
		}
	}
	return false, nil
}

// stand brings the port up and writes everything that names it.
//
// The order is the one a frame travels in reverse. The veth and its
// programs come first, then the tables the programs read, and
// l2_gateway last: that is the entry a route follows, so until it is
// there nothing sends a packet to a port that is not ready for one.
func (r *L2Gateway) stand(ctx context.Context, key string, network *juneauv1alpha1.L2Network, port *l2GatewayPortSpec) error {
	_ = ctx

	ifindex, err := r.ports.Ensure(port.vni, port.mac)
	if err != nil {
		return fmt.Errorf("bring up the gateway port of %s: %w", network.Name, err)
	}

	var mac [6]uint8
	copy(mac[:], port.mac)

	// A veth the kernel rebuilt comes back under another index, and the
	// entries under the old one would name a port that is gone.
	r.mu.Lock()
	previous, hadPrevious := r.snapshots[key]
	delete(r.snapshots, key)
	r.mu.Unlock()
	if hadPrevious && (previous.ifindex != ifindex || previous.vni != port.vni) {
		if err := r.release(previous); err != nil {
			return err
		}
	}

	address, err := convert.IPv4ToBPFNetworkOrder(port.address)
	if err != nil {
		return err
	}
	gwAddr, err := convert.IPv4ToUint32(port.address)
	if err != nil {
		return err
	}

	if err := r.maps.Ifindex.Update(
		&bpf.PodEgressL2IfindexKey{Ifindex: ifindex},
		&bpf.PodEgressL2IfindexVal{Vni: port.vni},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update L2Ifindex: %w", err)
	}

	if err := r.maps.Subnet.Update(
		&bpf.PodEgressSubnetKey{SubnetId: port.vni},
		&bpf.PodEgressSubnetVal{
			TableId: port.tableID,
			VpcId:   port.vpcID,
			GwMac:   mac,
			GwAddr:  gwAddr,
			Mask:    port.mask,
			AclId:   port.aclID,
		},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update SubnetMap: %w", err)
	}

	if err := r.maps.IfindexSubnet.Update(
		&bpf.PodEgressIfindexSubnetKey{Ifindex: ifindex},
		&bpf.PodEgressIfindexSubnetVal{SubnetId: port.vni, Ipv4: address},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update IfindexSubnet: %w", err)
	}

	// The one forwarding entry user space writes. A gateway sends no
	// frame of its own, so there is nothing for the data plane to learn
	// it from, and the flag keeps a workload that claims the address
	// from taking the entry over.
	if err := r.maps.Fdb.Put(port.vni,
		bpf.PodEgressL2FdbKey{Mac: mac},
		bpf.PodEgressL2FdbVal{Ifindex: ifindex, Flags: l2.FdbFlagGateway},
	); err != nil {
		return err
	}

	if err := r.maps.BumLocal.Put(port.vni, ifindex, l2.PortFlagPresent|l2.PortFlagGateway); err != nil {
		return err
	}

	if err := r.maps.Gateway.Update(
		&bpf.PodEgressL2GatewayKey{Vni: port.vni},
		&bpf.PodEgressL2GatewayVal{Ifindex: ifindex, Mac: mac},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update L2Gateway: %w", err)
	}

	r.mu.Lock()
	r.snapshots[key] = l2GatewaySnapshot{vni: port.vni, ifindex: ifindex, mac: mac}
	r.mu.Unlock()

	zap.S().Infof("l2-gateway: %s answers on %s behind ifindex %d (VNI=%d)",
		network.Name, port.address, ifindex, port.vni)
	return nil
}

func (r *L2Gateway) teardown(key string) error {
	r.mu.Lock()
	snapshot, ok := r.snapshots[key]
	if ok {
		delete(r.snapshots, key)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}

	zap.S().Infof("l2-gateway: taking the port of %s down (VNI=%d)", key, snapshot.vni)
	return r.release(snapshot)
}

// release takes out everything stand wrote, starting with the entry a
// route follows so nothing is sent to a port that is coming down.
func (r *L2Gateway) release(snapshot l2GatewaySnapshot) error {
	var errs []error

	if err := r.maps.Gateway.Delete(&bpf.PodEgressL2GatewayKey{Vni: snapshot.vni}); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, fmt.Errorf("delete L2Gateway: %w", err))
	}
	if err := r.maps.BumLocal.Remove(snapshot.vni, snapshot.ifindex); err != nil {
		errs = append(errs, err)
	}
	if err := r.maps.Fdb.Remove(snapshot.vni, bpf.PodEgressL2FdbKey{Mac: snapshot.mac}); err != nil {
		errs = append(errs, err)
	}
	if err := r.maps.IfindexSubnet.Delete(&bpf.PodEgressIfindexSubnetKey{Ifindex: snapshot.ifindex}); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, fmt.Errorf("delete IfindexSubnet: %w", err))
	}
	if err := r.maps.Subnet.Delete(&bpf.PodEgressSubnetKey{SubnetId: snapshot.vni}); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, fmt.Errorf("delete SubnetMap: %w", err))
	}
	if err := r.maps.Ifindex.Delete(&bpf.PodEgressL2IfindexKey{Ifindex: snapshot.ifindex}); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, fmt.Errorf("delete L2Ifindex: %w", err))
	}
	if err := r.ports.Remove(snapshot.vni); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// CloseAll takes every gateway port this daemon built down. The Manager
// calls it on shutdown so a reload does not leave a veth behind that
// the next daemon would find with programs it no longer owns.
func (r *L2Gateway) CloseAll() error {
	r.mu.Lock()
	snapshots := r.snapshots
	r.snapshots = make(map[string]l2GatewaySnapshot)
	r.mu.Unlock()

	var errs []error
	for _, snapshot := range snapshots {
		if err := r.release(snapshot); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// FanOutEndpointToL2Network re-enqueues the segment an endpoint joined.
// Whether this node runs a gateway for a segment follows whether it
// holds a port on it, so the first endpoint to arrive brings the port
// up and the last one to leave takes it down.
func (r *L2Gateway) FanOutEndpointToL2Network(obj any) []string {
	endpoint, ok := networkEndpointFromL2Event(obj)
	if !ok || endpoint.Spec.L2Network == "" {
		return nil
	}
	return []string{endpoint.Spec.L2Network}
}

// FanOutL2Network re-enqueues the changed segment itself. The runner
// keys L2Network events by namespace and name, and an L2Network is
// cluster-scoped, so the key is already the name.
func (r *L2Gateway) FanOutL2Network(obj any) []string {
	network, ok := l2NetworkFromEvent(obj)
	if !ok {
		return nil
	}
	return []string{network.Name}
}

// FanOutVpcToL2Networks re-enqueues every segment of the changed Vpc.
// The Vpc carries the id the boundary is stamped with and the main
// RouteTable a gateway falls back to.
func (r *L2Gateway) FanOutVpcToL2Networks(obj any) []string {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}
	return r.networksMatching(func(network *juneauv1alpha1.L2Network) bool {
		return network.Spec.Vpc == vpc.Name
	})
}

// FanOutRouteTableToL2Networks re-enqueues every segment in the Vpc of
// the changed RouteTable. Which of them actually follow it depends on
// the Vpc's main table, so the whole Vpc is re-read rather than guessed
// at.
func (r *L2Gateway) FanOutRouteTableToL2Networks(obj any) []string {
	routeTable, ok := obj.(*juneauv1alpha1.RouteTable)
	if !ok {
		return nil
	}
	return r.networksMatching(func(network *juneauv1alpha1.L2Network) bool {
		return network.Spec.Vpc == routeTable.Spec.Vpc
	})
}

// FanOutNetworkACLToL2Networks re-enqueues every segment that names the
// changed NetworkACL, so a fresh id reaches the boundary without
// waiting for an unrelated event.
func (r *L2Gateway) FanOutNetworkACLToL2Networks(obj any) []string {
	acl, ok := obj.(*juneauv1alpha1.NetworkACL)
	if !ok {
		return nil
	}
	return r.networksMatching(func(network *juneauv1alpha1.L2Network) bool {
		return network.Spec.NetworkACL == acl.Name
	})
}

func (r *L2Gateway) networksMatching(keep func(*juneauv1alpha1.L2Network) bool) []string {
	var list juneauv1alpha1.L2NetworkList
	if err := r.client.List(context.Background(), &list); err != nil {
		zap.S().Warnf("l2-gateway: list L2Networks for fan-out: %v", err)
		return nil
	}
	keys := make([]string, 0, len(list.Items))
	for i := range list.Items {
		if !keep(&list.Items[i]) {
			continue
		}
		keys = append(keys, list.Items[i].Name)
	}
	return keys
}
