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
)

// l2NetworkTable is what a reconciler needs to build and drop one
// per-VNI table. *l2.Table is the only implementation the daemon runs;
// tests bring their own because minting a BPF map needs CAP_BPF.
type l2NetworkTable interface {
	Ensure(vni uint32) error
	Delete(vni uint32) error
}

// l2FloodTable adds the membership writes, which only the two flood
// lists take. The learning table has no members: the data plane fills
// it in on its own.
type l2FloodTable interface {
	l2NetworkTable
	AddMember(vni, member uint32) error
	RemoveMember(vni, member uint32) error
}

// L2Port turns the NetworkEndpoints of an L2Network into the ports of
// a switch.
//
// An endpoint on this node becomes a local port: l2_ifindex names the
// network behind its veth, and the veth joins the local flood list.
// An endpoint on another node becomes a remote port: that node's
// underlay address joins the remote flood list, which is what makes a
// broadcast reach the rest of the segment.
//
// Both sides are counted rather than written straight through. Several
// endpoints of one network usually sit on the same remote node, and
// they must add that node once and remove it only when the last of
// them is gone. Local ports are counted the same way so a veth that a
// restarting workload hands from one endpoint to the next is never
// left out of the flood list.
type L2Port struct {
	client     client.Client
	nodeName   string
	ifindexMap bpfMap
	bumLocal   l2FloodTable
	bumRemote  l2FloodTable

	mu        sync.Mutex
	snapshots map[string]l2PortMember
	refs      map[l2PortMember]int
}

// l2PortMember is one entry of a flood list. member is a veth ifindex
// when local and a node's underlay IPv4 when remote; the zero value
// means the endpoint contributes no port yet.
type l2PortMember struct {
	vni     uint32
	member  uint32
	isLocal bool
}

func (m l2PortMember) valid() bool { return m.vni != 0 && m.member != 0 }

func NewL2Port(cl client.Client, ifindexMap bpfMap, bumLocal, bumRemote l2FloodTable, nodeName string) *L2Port {
	return &L2Port{
		client:     cl,
		nodeName:   nodeName,
		ifindexMap: ifindexMap,
		bumLocal:   bumLocal,
		bumRemote:  bumRemote,
		snapshots:  make(map[string]l2PortMember),
		refs:       make(map[l2PortMember]int),
	}
}

func (r *L2Port) Name() string { return "l2-port" }

func (r *L2Port) Reconcile(ctx context.Context, key string) error {
	namespace, name, err := toolscache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	var nwep juneauv1alpha1.NetworkEndpoint
	err = r.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &nwep)
	if apierrors.IsNotFound(err) {
		return r.apply(key, l2PortMember{})
	}
	if err != nil {
		return err
	}
	if nwep.Spec.L2Network == "" {
		// An endpoint on a Subnet. The Subnet data plane has its own
		// tables and this one must not put a port on its behalf.
		return r.apply(key, l2PortMember{})
	}

	desired, err := r.desiredMember(ctx, &nwep)
	if err != nil {
		return err
	}
	return r.apply(key, desired)
}

// desiredMember reads the port an endpoint contributes. An endpoint
// that names a network which is gone, or one the data plane cannot
// place yet, contributes nothing rather than an error: the object that
// is missing comes back as an event of its own, and failing here would
// only spin the work queue.
func (r *L2Port) desiredMember(ctx context.Context, nwep *juneauv1alpha1.NetworkEndpoint) (l2PortMember, error) {
	var network juneauv1alpha1.L2Network
	err := r.client.Get(ctx, client.ObjectKey{Name: nwep.Spec.L2Network}, &network)
	if apierrors.IsNotFound(err) {
		return l2PortMember{}, nil
	}
	if err != nil {
		return l2PortMember{}, err
	}
	if network.Status.VNI == 0 {
		return l2PortMember{}, nil
	}

	if nwep.Spec.NodeName == r.nodeName {
		if nwep.Spec.Attachment == nil {
			return l2PortMember{}, nil
		}
		return l2PortMember{
			vni:     network.Status.VNI,
			member:  uint32(nwep.Spec.Attachment.Ifindex),
			isLocal: true,
		}, nil
	}

	if nwep.Status.NodeIP == "" {
		return l2PortMember{}, nil
	}
	nodeIP := net.ParseIP(nwep.Status.NodeIP)
	if nodeIP == nil {
		return l2PortMember{}, fmt.Errorf("parse node IP %q of endpoint %s", nwep.Status.NodeIP, nwep.Name)
	}
	// The data plane hands this straight to bpf_tunnel_key.remote_ipv4,
	// which the kernel byte-swaps itself, so it wants the host-order
	// number and not the network-order bytes.
	vtep, err := convert.IPv4ToUint32(nodeIP)
	if err != nil {
		return l2PortMember{}, err
	}
	return l2PortMember{vni: network.Status.VNI, member: vtep}, nil
}

// apply moves one endpoint from the port it held to the port it should
// hold. Either may be the zero value, which stands for "no port".
//
// The snapshot is written last. A failed acquire has to leave the
// endpoint recorded as holding nothing, or the retry would read the
// snapshot it never managed to program and decide there was nothing
// left to do.
func (r *L2Port) apply(key string, desired l2PortMember) error {
	r.mu.Lock()
	previous := r.snapshots[key]
	r.mu.Unlock()

	if previous == desired {
		return nil
	}

	if previous.valid() {
		if err := r.release(previous); err != nil {
			return err
		}
		r.mu.Lock()
		delete(r.snapshots, key)
		r.mu.Unlock()
	}

	if !desired.valid() {
		return nil
	}
	if err := r.acquire(desired); err != nil {
		return err
	}

	r.mu.Lock()
	r.snapshots[key] = desired
	r.mu.Unlock()
	return nil
}

// acquire counts one more endpoint on a port and programs it when it
// is the first.
func (r *L2Port) acquire(member l2PortMember) error {
	r.mu.Lock()
	r.refs[member]++
	first := r.refs[member] == 1
	r.mu.Unlock()

	if !first {
		return nil
	}
	if err := r.program(member); err != nil {
		r.mu.Lock()
		r.refs[member]--
		if r.refs[member] <= 0 {
			delete(r.refs, member)
		}
		r.mu.Unlock()
		return err
	}
	return nil
}

// release counts one endpoint off a port and unprograms it when it was
// the last. A failed unprogram puts the count back, because the caller
// keeps the endpoint on the port and will come here again.
func (r *L2Port) release(member l2PortMember) error {
	r.mu.Lock()
	r.refs[member]--
	last := r.refs[member] <= 0
	if last {
		delete(r.refs, member)
	}
	r.mu.Unlock()

	if !last {
		return nil
	}
	if err := r.unprogram(member); err != nil {
		r.mu.Lock()
		r.refs[member]++
		r.mu.Unlock()
		return err
	}
	return nil
}

func (r *L2Port) program(member l2PortMember) error {
	if !member.isLocal {
		return r.bumRemote.AddMember(member.vni, member.member)
	}

	if err := r.ifindexMap.Update(
		&bpf.PodEgressL2IfindexKey{Ifindex: member.member},
		&bpf.PodEgressL2IfindexVal{Vni: member.vni},
		ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("update L2Ifindex: %w", err)
	}
	return r.bumLocal.AddMember(member.vni, member.member)
}

func (r *L2Port) unprogram(member l2PortMember) error {
	if !member.isLocal {
		return r.bumRemote.RemoveMember(member.vni, member.member)
	}

	if err := r.ifindexMap.Delete(
		&bpf.PodEgressL2IfindexKey{Ifindex: member.member},
	); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete L2Ifindex: %w", err)
	}
	return r.bumLocal.RemoveMember(member.vni, member.member)
}

// FanOutL2NetworkToEndpoints re-enqueues every endpoint of the changed
// L2Network. The VNI is handed out after the network exists, and every
// port is keyed by it, so the endpoints have to be looked at again
// once it lands.
func (r *L2Port) FanOutL2NetworkToEndpoints(obj any) []string {
	network, ok := obj.(*juneauv1alpha1.L2Network)
	if !ok {
		return nil
	}

	var list juneauv1alpha1.NetworkEndpointList
	if err := r.client.List(context.Background(), &list); err != nil {
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
