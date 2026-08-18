package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/runner"
)

// JuneauNodeIfaceName is the BPF-attached side of the per-node veth
// pair that acts as the host's pseudo-pod for the default Subnet.
// Renamed from the legacy "cni_net" in Phase 4b-4.
const JuneauNodeIfaceName = "juneau_node"

// JuneauNodeHostIfaceName is the peer end of the juneau_node veth pair.
// It carries the per-node reserved IP and is what the host network
// stack sees as its default-Subnet gateway.
const JuneauNodeHostIfaceName = "juneau_node_h"

// JuneauNodeResyncPeriod is how often the converger re-reads the
// kernel. Changes to the NetworkEndpoint arrive as informer events, but
// `ip link set juneau_node_h address ...` produces none, so without a
// resync that drift would never be corrected.
const JuneauNodeResyncPeriod = time.Minute

// JuneauNodeIfaceInfo bundles the BPF-side veth's ifindex with the
// peer-side iface details that downstream daemon reconcilers need to
// install arp_table / fdb entries.
type JuneauNodeIfaceInfo struct {
	HostIfaceInfo

	// HostSideMAC is the MAC of the veth peer that holds the
	// per-node IP and faces the kernel network stack. Used by the
	// daemon's juneau_node reconciler to populate arp_table and fdb
	// for the reserved IP.
	HostSideMAC net.HardwareAddr

	// AssignedIP is the per-node reserved IP allocated for this node.
	AssignedIP net.IP
}

// JuneauNodeIdentity is the identity the controller assigned to this
// node's juneau_node iface: the address the host-facing peer carries
// and the MAC the rest of the overlay expects to see behind it.
type JuneauNodeIdentity struct {
	Address *net.IPNet
	MAC     net.HardwareAddr
}

// JuneauNodeConverger owns "the kernel follows the endpoint" for the
// juneau_node veth pair. It creates the pair, makes its MAC and address
// match the kind=Node NetworkEndpoint the controller published for this
// node, and records the resulting veth in spec.attachment.
//
// It runs once at startup and then on every change to that endpoint,
// because the controller may delete and recreate the object at any time
// (an identity change, an upgrade). The replacement carries no
// attachment, and a daemon that only converged at startup left the node
// with a dead data plane until someone restarted the DaemonSet.
type JuneauNodeConverger struct {
	client   client.Client
	nodeName string

	// waiting is set while the endpoint is absent so the gap is logged
	// once rather than on every event that arrives during it. Only the
	// single work-queue worker touches it.
	waiting bool
}

func NewJuneauNodeConverger(cl client.Client, nodeName string) *JuneauNodeConverger {
	return &JuneauNodeConverger{client: cl, nodeName: nodeName}
}

func (c *JuneauNodeConverger) Name() string { return "juneau-node-iface" }

// Reconcile implements runner.Reconciler. The converger is a singleton,
// so the key carries no information.
//
// A missing endpoint is not a failure here, unlike at startup: the
// controller deletes and recreates the object on an identity change, so
// the work queue sees the gap between the two every time. The create
// event is already on its way, and JuneauNodeResyncPeriod is the
// backstop if it somehow is not. Every other error still reaches the
// runner, which logs it and requeues.
func (c *JuneauNodeConverger) Reconcile(ctx context.Context, _ string) error {
	_, err := c.Converge(ctx)
	if errors.Is(err, ErrJuneauNodeEndpointNotFound) {
		if !c.waiting {
			c.waiting = true
			zap.S().Infof("waiting for the controller to publish the kind=Node NetworkEndpoint of node %q", c.nodeName)
		}
		return nil
	}

	c.waiting = false
	return err
}

// EnqueueKey is the keyFunc for runner.Watch: it keeps the work queue
// to this node's kind=Node endpoint. Every other NetworkEndpoint in the
// cluster belongs to a Pod or to another node.
func (c *JuneauNodeConverger) EnqueueKey(obj any) (string, bool) {
	endpoint, ok := networkEndpointFromEvent(obj)
	if !ok {
		return "", false
	}
	if endpoint.Spec.Kind != juneauv1alpha1.EndpointKindNode {
		return "", false
	}
	if endpoint.Spec.NodeName != c.nodeName {
		return "", false
	}
	return runner.SingletonKey, true
}

func networkEndpointFromEvent(obj any) (*juneauv1alpha1.NetworkEndpoint, bool) {
	if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	endpoint, ok := obj.(*juneauv1alpha1.NetworkEndpoint)
	return endpoint, ok
}

// Converge makes the kernel match the published identity and returns
// the veth details the rest of the daemon needs.
//
// A missing endpoint is an error. At startup that exits the daemon and
// the DaemonSet restart is the retry; from the work queue it is just a
// requeue.
func (c *JuneauNodeConverger) Converge(ctx context.Context) (*JuneauNodeIfaceInfo, error) {
	endpoint, err := FindJuneauNodeEndpoint(ctx, c.client, c.nodeName)
	if err != nil {
		return nil, err
	}

	identity, err := parseJuneauNodeIdentity(endpoint)
	if err != nil {
		return nil, err
	}

	info, err := ensureJuneauNodeIface(identity)
	if err != nil {
		return nil, err
	}

	if err := patchJuneauNodeAttachment(ctx, c.client, endpoint, info); err != nil {
		return nil, err
	}

	return info, nil
}

// ensureJuneauNodeIface brings the veth pair in line with identity and
// reports what the kernel ended up with.
func ensureJuneauNodeIface(identity *JuneauNodeIdentity) (*JuneauNodeIfaceInfo, error) {
	veth, err := ensureJuneauNodeVeth(identity)
	if err != nil {
		return nil, err
	}

	peer, err := netlink.LinkByName(JuneauNodeHostIfaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", JuneauNodeHostIfaceName, err)
	}

	addrs, err := netlink.AddrList(peer, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("list addresses on %s: %w", JuneauNodeHostIfaceName, err)
	}

	plan := planJuneauNodeConvergence(juneauNodeLinkState{
		MAC:       peer.Attrs().HardwareAddr,
		Addresses: addrIPNets(addrs),
	}, identity)

	if err := applyJuneauNodePlan(peer, identity, plan); err != nil {
		return nil, err
	}

	if err := netlink.LinkSetUp(veth); err != nil {
		return nil, fmt.Errorf("bring up %s: %w", JuneauNodeIfaceName, err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		return nil, fmt.Errorf("bring up %s: %w", JuneauNodeHostIfaceName, err)
	}

	// A pair the daemon just rebuilt comes back with the kernel
	// defaults, and a `sysctl --system` reload resets these too, so they
	// are written on every pass rather than once at startup.
	if err := ConfigureJuneauNodeSysctl(); err != nil {
		return nil, err
	}

	return &JuneauNodeIfaceInfo{
		HostIfaceInfo: HostIfaceInfo{
			MAC:     identity.MAC,
			Ifindex: veth.Attrs().Index,
		},
		HostSideMAC: identity.MAC,
		AssignedIP:  identity.Address.IP,
	}, nil
}

// ensureJuneauNodeVeth returns the BPF-side end of the pair, creating
// the pair when it is gone.
//
// Rebuilding it while the daemon runs gives the pair a new ifindex,
// which is safe: everything that consumes the ifindex reads it from
// spec.attachment, and both consumers key their BPF state on the last
// ifindex they wrote. link.PodAttacher moves its TC programs to the new
// one and reconciler.PodIface rewrites its map entries.
func ensureJuneauNodeVeth(identity *JuneauNodeIdentity) (netlink.Link, error) {
	veth, err := netlink.LinkByName(JuneauNodeIfaceName)
	if err == nil {
		return veth, nil
	}
	if _, ok := err.(netlink.LinkNotFoundError); !ok {
		return nil, fmt.Errorf("lookup %s: %w", JuneauNodeIfaceName, err)
	}

	zap.S().Infof("creating %s veth pair with address %s and MAC %s",
		JuneauNodeIfaceName, identity.Address, identity.MAC)

	pair := &netlink.Veth{
		LinkAttrs:        netlink.LinkAttrs{Name: JuneauNodeIfaceName},
		PeerName:         JuneauNodeHostIfaceName,
		PeerHardwareAddr: identity.MAC,
	}
	if err := netlink.LinkAdd(pair); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("create %s veth pair: %w", JuneauNodeIfaceName, err)
	}

	veth, err = netlink.LinkByName(JuneauNodeIfaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup created %s: %w", JuneauNodeIfaceName, err)
	}
	return veth, nil
}

// juneauNodeLinkState is what the kernel currently reports for the
// host-facing peer of the pair.
type juneauNodeLinkState struct {
	MAC       net.HardwareAddr
	Addresses []*net.IPNet
}

// juneauNodePlan is the set of changes that bring a juneauNodeLinkState
// in line with the published identity.
type juneauNodePlan struct {
	SetMAC      bool
	AddAddress  bool
	DeleteAddrs []*net.IPNet
}

// planJuneauNodeConvergence compares the kernel against the identity.
// A veth left over from an older daemon carries the MAC the kernel
// picked at random, and the per-node IP changes when the claim is
// recreated, so both have to be corrected rather than trusted.
func planJuneauNodeConvergence(state juneauNodeLinkState, identity *JuneauNodeIdentity) juneauNodePlan {
	plan := juneauNodePlan{
		SetMAC:     !bytes.Equal(state.MAC, identity.MAC),
		AddAddress: true,
	}

	for _, addr := range state.Addresses {
		if addr.IP.Equal(identity.Address.IP) && bytes.Equal(addr.Mask, identity.Address.Mask) {
			plan.AddAddress = false
			continue
		}
		// IPv6 link-local belongs to the kernel, not to a past identity.
		if addr.IP.IsLinkLocalUnicast() {
			continue
		}
		plan.DeleteAddrs = append(plan.DeleteAddrs, addr)
	}

	return plan
}

func applyJuneauNodePlan(peer netlink.Link, identity *JuneauNodeIdentity, plan juneauNodePlan) error {
	if plan.SetMAC {
		zap.S().Infof("setting %s MAC to %s", JuneauNodeHostIfaceName, identity.MAC)
		// The link has to go down to take a new MAC.
		if err := netlink.LinkSetDown(peer); err != nil {
			return fmt.Errorf("bring down %s: %w", JuneauNodeHostIfaceName, err)
		}
		if err := netlink.LinkSetHardwareAddr(peer, identity.MAC); err != nil {
			return fmt.Errorf("set MAC on %s: %w", JuneauNodeHostIfaceName, err)
		}
	}

	for _, addr := range plan.DeleteAddrs {
		zap.S().Infof("dropping stale address %s from %s", addr, JuneauNodeHostIfaceName)
		if err := netlink.AddrDel(peer, &netlink.Addr{IPNet: addr}); err != nil {
			zap.S().Warnf("delete stale address %s on %s: %v", addr, JuneauNodeHostIfaceName, err)
		}
	}

	if plan.AddAddress {
		zap.S().Infof("adding address %s to %s", identity.Address, JuneauNodeHostIfaceName)
		if err := netlink.AddrAdd(peer, &netlink.Addr{IPNet: identity.Address}); err != nil && !os.IsExist(err) {
			return fmt.Errorf("add address %s to %s: %w", identity.Address, JuneauNodeHostIfaceName, err)
		}
	}

	return nil
}

func addrIPNets(addrs []netlink.Addr) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(addrs))
	for i := range addrs {
		if addrs[i].IPNet == nil {
			continue
		}
		out = append(out, addrs[i].IPNet)
	}
	return out
}
