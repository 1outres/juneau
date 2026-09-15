package grpc

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// hostRoute is a route in the main table of the node that sends traffic
// for one Pod address into the host side of the veth of that Pod.
//
// Only eth0 on an ElasticIP gets one. That address is unique in the
// cluster and belongs to no Vpc, so the node can route to it directly,
// and kubelet reaches the probes of the Pod over it. Every other address
// is left out on purpose: a Subnet address is reached through the data
// plane, and an L2Network always sits in a custom Vpc, where two Vpcs may
// use the same address on one node.
type hostRoute struct {
	dst *net.IPNet
}

// hostRouteToPod returns the host route one NIC needs, or nil when the
// NIC needs none.
func hostRouteToPod(nwiface *juneauv1alpha1.NetworkInterface) (*hostRoute, error) {
	if nwiface.Spec.ElasticIP == "" || nwiface.Spec.PodRef.Interface != juneauv1alpha1.PodPrimaryInterfaceName {
		return nil, nil
	}

	ip, ipnet, err := net.ParseCIDR(nwiface.Status.Address)
	if err != nil {
		return nil, fmt.Errorf("parse the ElasticIP address %q of %s: %w", nwiface.Status.Address, nwiface.Spec.PodRef.Interface, err)
	}
	ip4 := ip.To4()
	if ones, bits := ipnet.Mask.Size(); ip4 == nil || ones != net.IPv4len*8 || bits != net.IPv4len*8 {
		return nil, fmt.Errorf("the ElasticIP address %q of %s is not a single IPv4 address", nwiface.Status.Address, nwiface.Spec.PodRef.Interface)
	}
	return &hostRoute{dst: &net.IPNet{IP: ip4, Mask: ipnet.Mask}}, nil
}

func (r *hostRoute) String() string {
	return r.dst.String()
}

func (r *hostRoute) netlinkRoute(hostIfindex int) *netlink.Route {
	return &netlink.Route{
		LinkIndex: hostIfindex,
		Dst:       r.dst,
		Scope:     netlink.SCOPE_LINK,
		Table:     unix.RT_TABLE_MAIN,
	}
}

// installHostRouteToPod points the route at the given veth. It replaces a
// route to the same address that is already there, which is what makes a
// retried ADD work, and what moves the route to a new sandbox of the Pod
// that came up before the DEL of the old one.
func installHostRouteToPod(route *hostRoute, hostIfindex int) error {
	if err := netlink.RouteReplace(route.netlinkRoute(hostIfindex)); err != nil {
		return fmt.Errorf("add host route %s via ifindex %d: %w", route, hostIfindex, err)
	}
	return nil
}

// removeHostRouteToPod deletes the route only while it still leaves
// through the given veth. A route that is gone counts as removed.
func removeHostRouteToPod(route *hostRoute, hostIfindex int) error {
	err := netlink.RouteDel(route.netlinkRoute(hostIfindex))
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return fmt.Errorf("delete host route %s via ifindex %d: %w", route, hostIfindex, err)
}

// removeHostRoutesVia deletes every IPv4 route of the main table that
// leaves through one host veth of a sandbox. Juneau is the only one that
// adds routes through these veths, and a route that already points at the
// veth of a newer sandbox is not touched.
func removeHostRoutesVia(link netlink.Link) error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{LinkIndex: link.Attrs().Index, Table: unix.RT_TABLE_MAIN},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list host routes via %s: %w", link.Attrs().Name, err)
	}
	var errs []error
	for i := range routes {
		err := netlink.RouteDel(&routes[i])
		if err == nil || errors.Is(err, syscall.ESRCH) {
			continue
		}
		errs = append(errs, fmt.Errorf("delete host route %s via %s: %w", routes[i].Dst, link.Attrs().Name, err))
	}
	return errors.Join(errs...)
}

// verifyHostRouteToPod reports whether the route is there and leaves
// through the named veth.
func verifyHostRouteToPod(route *hostRoute, hostIfname string) error {
	link, err := netlink.LinkByName(hostIfname)
	if err != nil {
		return fmt.Errorf("look up host veth %s: %w", hostIfname, err)
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Dst: route.dst, Table: unix.RT_TABLE_MAIN},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list host routes to %s: %w", route, err)
	}
	for _, found := range routes {
		if found.LinkIndex == link.Attrs().Index {
			return nil
		}
	}
	return fmt.Errorf("no host route to %s leaves through %s", route, hostIfname)
}
