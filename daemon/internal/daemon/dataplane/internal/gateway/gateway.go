package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/arp"
	"github.com/vishvananda/netlink"
)

// Info describes how to reach the internet gateway from a given node
// interface. It captures the source MAC, next-hop IP and next-hop MAC so
// that FIB entries for the "internet gateway" route type can be populated
// without further netlink lookups at reconcile time.
type Info struct {
	Ifindex    int
	SourceMAC  net.HardwareAddr
	NextHopIP  net.IP
	NextHopMAC net.HardwareAddr
}

// Resolve inspects the routing table for the given interface, finds the
// default gateway, and resolves its MAC via the neighbor table or ARP.
func Resolve(ifindex int) (*Info, error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil, err
	}
	ifi, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return nil, err
	}

	route, err := defaultGatewayRoute(link)
	if err != nil {
		return nil, err
	}

	mac, ok, err := lookupNeighborMAC(ifindex, route.Gw)
	if err != nil {
		return nil, err
	}
	if !ok {
		mac, err = resolveNeighborMACWithARP(ifi, route.Gw)
		if err != nil {
			return nil, err
		}
	}

	return &Info{
		Ifindex:    ifindex,
		SourceMAC:  link.Attrs().HardwareAddr,
		NextHopIP:  route.Gw,
		NextHopMAC: mac,
	}, nil
}

func defaultGatewayRoute(link netlink.Link) (*netlink.Route, error) {
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	for i := range routes {
		route := &routes[i]
		if route.Gw == nil {
			continue
		}
		// The kernel may return the default route with Dst == nil or as
		// an explicit 0.0.0.0/0 IPNet depending on netlink attributes.
		if route.Dst == nil || isDefaultDst(route.Dst) {
			return route, nil
		}
	}

	return nil, fmt.Errorf("no default route with gateway found on ifindex %d", link.Attrs().Index)
}

func isDefaultDst(dst *net.IPNet) bool {
	if dst == nil || !dst.IP.IsUnspecified() {
		return false
	}
	ones, bits := dst.Mask.Size()
	return ones == 0 && bits != 0
}

func lookupNeighborMAC(ifindex int, gw net.IP) (net.HardwareAddr, bool, error) {
	neighs, err := netlink.NeighList(ifindex, netlink.FAMILY_V4)
	if err != nil {
		return nil, false, err
	}

	for i := range neighs {
		neigh := &neighs[i]
		if neigh.IP == nil || !neigh.IP.Equal(gw) {
			continue
		}
		if len(neigh.HardwareAddr) == 0 {
			continue
		}
		return neigh.HardwareAddr, true, nil
	}

	return nil, false, nil
}

func resolveNeighborMACWithARP(ifi *net.Interface, gw net.IP) (net.HardwareAddr, error) {
	gwAddr, ok := netip.AddrFromSlice(gw.To4())
	if !ok {
		return nil, fmt.Errorf("gateway %s is not IPv4", gw)
	}

	client, err := arp.Dial(ifi)
	if err != nil {
		return nil, fmt.Errorf("dial arp on %s: %w", ifi.Name, err)
	}
	defer func() {
		_ = client.Close()
	}()

	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}

	hwAddr, err := client.Resolve(gwAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve gateway %s MAC on %s: %w", gw, ifi.Name, err)
	}

	return hwAddr, nil
}
