package link

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"

	"github.com/1outres/juneau/daemon/internal/daemon/bootstrap"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// L2GatewayIfaceName is the veth this node runs as the router port of
// one L2Network, and L2GatewayPeerIfaceName is the other end of the
// pair. Both live in the host namespace: nothing is behind the port but
// the two programs on it, and the peer is there because a veth cannot
// exist on its own.
//
// The names are keyed by VNI rather than by the name of the L2Network,
// because a network name may be up to 253 characters and an interface
// name is 15.
func L2GatewayIfaceName(vni uint32) string { return fmt.Sprintf("l2gw%d", vni) }

func L2GatewayPeerIfaceName(vni uint32) string { return L2GatewayIfaceName(vni) + "_h" }

// L2GatewayAttacher owns the veth pairs behind the gateway ports and
// the programs on them.
//
// The two programs are the two halves of a router port. pod_egress at
// the ingress is the way out of the segment: it sees what the segment
// sent to the gateway MAC and takes it through the RouteTable, the
// NATGateway, the Service path and the policy stage. l2_gateway at the
// egress is the way in: it addresses what a route sent here to the host
// that owns the destination and puts it on the segment.
//
// The daemon holds the links, so a restart drops them and the next pass
// puts them back. The veth itself is left in the kernel between passes
// and only removed when the segment stops needing it.
type L2GatewayAttacher struct {
	podEgress *program.PodEgress
	l2Gateway *program.L2Gateway

	mu    sync.Mutex
	ports map[uint32]*l2GatewayLinks
}

// l2GatewayLinks is what one gateway port owns in the kernel.
type l2GatewayLinks struct {
	ifindex uint32
	ingress ebpflink.Link
	egress  ebpflink.Link
}

func NewL2GatewayAttacher(podEgress *program.PodEgress, l2Gateway *program.L2Gateway) *L2GatewayAttacher {
	return &L2GatewayAttacher{
		podEgress: podEgress,
		l2Gateway: l2Gateway,
		ports:     make(map[uint32]*l2GatewayLinks),
	}
}

// Ensure brings the gateway port of one segment in line with the
// identity the controller published and reports the ifindex the kernel
// gave it.
//
// It is safe to call on every pass. The veth is built once and its MAC
// corrected when it does not match; the programs are attached again
// only when the pair came back under another index.
func (a *L2GatewayAttacher) Ensure(vni uint32, mac net.HardwareAddr) (uint32, error) {
	if vni == 0 {
		return 0, errors.New("vni 0 is not a network")
	}
	if len(mac) != 6 {
		return 0, fmt.Errorf("a gateway MAC is 6 bytes, got %d", len(mac))
	}

	veth, err := ensureL2GatewayVeth(vni, mac)
	if err != nil {
		return 0, err
	}
	ifindex := uint32(veth.Attrs().Index)

	a.mu.Lock()
	held, ok := a.ports[vni]
	a.mu.Unlock()
	if ok && held.ifindex == ifindex {
		return ifindex, nil
	}
	if ok {
		// The pair came back under another index, so the links point at
		// a device that is gone.
		a.detach(vni)
	}

	links, err := a.attach(ifindex)
	if err != nil {
		return 0, err
	}

	a.mu.Lock()
	a.ports[vni] = links
	a.mu.Unlock()

	zap.S().Infof("l2-gateway: %s carries the router port of VNI %d with MAC %s",
		L2GatewayIfaceName(vni), vni, mac)
	return ifindex, nil
}

// Remove detaches the programs and takes the veth pair down.
func (a *L2GatewayAttacher) Remove(vni uint32) error {
	a.detach(vni)
	return removeL2GatewayVeth(vni)
}

// CloseAll detaches every port this attacher holds. The veths are left
// where they are: the reconciler decides which segments still want one,
// and taking them out here would drop the ports of a daemon that is
// only restarting.
func (a *L2GatewayAttacher) CloseAll() error {
	a.mu.Lock()
	ports := a.ports
	a.ports = make(map[uint32]*l2GatewayLinks)
	a.mu.Unlock()

	var errs []error
	for vni, links := range ports {
		errs = append(errs, closeL2GatewayLinks(vni, links)...)
	}
	return errors.Join(errs...)
}

func (a *L2GatewayAttacher) attach(ifindex uint32) (*l2GatewayLinks, error) {
	ingress, err := attachTCX(a.podEgress.Objs.TcPodEgress, int(ifindex),
		ebpf.AttachTCXIngress, "l2-gateway-ingress")
	if err != nil {
		return nil, err
	}

	egress, err := attachTCX(a.l2Gateway.Objs.TcL2Gateway, int(ifindex),
		ebpf.AttachTCXEgress, "l2-gateway-egress")
	if err != nil {
		if ingress != nil {
			_ = ingress.Close()
		}
		return nil, err
	}

	return &l2GatewayLinks{ifindex: ifindex, ingress: ingress, egress: egress}, nil
}

func (a *L2GatewayAttacher) detach(vni uint32) {
	a.mu.Lock()
	links, ok := a.ports[vni]
	delete(a.ports, vni)
	a.mu.Unlock()
	if !ok {
		return
	}
	for _, err := range closeL2GatewayLinks(vni, links) {
		zap.S().Warnf("l2-gateway: %v", err)
	}
}

func closeL2GatewayLinks(vni uint32, links *l2GatewayLinks) []error {
	var errs []error
	if links.ingress != nil {
		if err := links.ingress.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close the ingress program of VNI %d: %w", vni, err))
		}
	}
	if links.egress != nil {
		if err := links.egress.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close the egress program of VNI %d: %w", vni, err))
		}
	}
	return errs
}

// ensureL2GatewayVeth builds the pair when it is missing and brings the
// kernel in line with the identity the controller published.
//
// The MAC goes on the BPF-side end, which is the end the segment
// addresses. The kernel reads it in eth_type_trans when a frame is
// handed to the port's ingress, so a frame sent to the gateway arrives
// as one addressed to this host rather than as one overheard from
// somebody else.
func ensureL2GatewayVeth(vni uint32, mac net.HardwareAddr) (netlink.Link, error) {
	name := L2GatewayIfaceName(vni)
	peerName := L2GatewayPeerIfaceName(vni)

	veth, err := netlink.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return nil, fmt.Errorf("lookup %s: %w", name, err)
		}
		zap.S().Infof("creating the %s veth pair with MAC %s", name, mac)
		pair := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: name, HardwareAddr: mac},
			PeerName:  peerName,
		}
		if err := netlink.LinkAdd(pair); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("create the %s veth pair: %w", name, err)
		}
		veth, err = netlink.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("lookup the created %s: %w", name, err)
		}
	}

	// A pair left over from an older daemon carries whatever MAC the
	// kernel picked, and the MAC of a gateway changes when the segment
	// drops its gateway and takes another one.
	if !bytes.Equal(veth.Attrs().HardwareAddr, mac) {
		zap.S().Infof("setting the MAC of %s to %s", name, mac)
		if err := netlink.LinkSetDown(veth); err != nil {
			return nil, fmt.Errorf("bring %s down: %w", name, err)
		}
		if err := netlink.LinkSetHardwareAddr(veth, mac); err != nil {
			return nil, fmt.Errorf("set the MAC of %s: %w", name, err)
		}
	}

	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", peerName, err)
	}

	// Both ends go up. The redirect that hands a frame to this port is
	// refused for a device that is down, and a veth only carries when
	// its peer is up as well.
	if err := netlink.LinkSetUp(veth); err != nil {
		return nil, fmt.Errorf("bring %s up: %w", name, err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		return nil, fmt.Errorf("bring %s up: %w", peerName, err)
	}

	// The peer is the end the host stack sees, and it carries no
	// address of its own. Left alone it would still send router
	// solicitations and multicast listener reports of its own onto a
	// tenant's segment, so IPv6 is turned off on both ends. A pair the
	// daemon just rebuilt comes back with the kernel defaults, which is
	// why this runs on every pass rather than once.
	for _, iface := range []string{name, peerName} {
		if err := bootstrap.DisableIPv6(iface); err != nil {
			return nil, err
		}
	}

	return veth, nil
}

// removeL2GatewayVeth takes the pair down. Removing one end removes
// both, and a pair that is already gone is not an error: an earlier
// pass may have removed it, or an operator may have.
func removeL2GatewayVeth(vni uint32) error {
	name := L2GatewayIfaceName(vni)
	veth, err := netlink.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("lookup %s: %w", name, err)
	}
	if err := netlink.LinkDel(veth); err != nil {
		return fmt.Errorf("remove %s: %w", name, err)
	}
	zap.S().Infof("l2-gateway: removed %s", name)
	return nil
}
