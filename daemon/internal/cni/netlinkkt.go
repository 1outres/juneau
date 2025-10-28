package cni

import (
	"fmt"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

func EnsureVRF(vrfName string, tableID int) (*netlink.Vrf, error) {
	link, err := netlink.LinkByName(vrfName)
	if err == nil {
		vrf, ok := link.(*netlink.Vrf)
		if !ok {
			return nil, fmt.Errorf("link %s exists but is not a VRF", vrfName)
		}
		return vrf, nil
	}

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: vrfName,
		},
		Table: uint32(tableID),
	}

	if err := netlink.LinkAdd(vrf); err != nil {
		return nil, fmt.Errorf("failed to create VRF: %v", err)
	}

	if err := netlink.LinkSetUp(vrf); err != nil {
		return nil, fmt.Errorf("failed to set VRF up: %v", err)
	}

	return vrf, nil
}

func EnsureBridge(bridgeName string, master *netlink.Vrf) (*netlink.Bridge, error) {
	link, err := netlink.LinkByName(bridgeName)
	if err == nil {
		br, ok := link.(*netlink.Bridge)
		if !ok {
			return nil, fmt.Errorf("link %s exists but is not a bridge", bridgeName)
		}
		return br, nil
	}

	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: bridgeName,
		},
	}

	if master != nil {
		br.LinkAttrs.MasterIndex = master.Index
	}

	if err := netlink.LinkAdd(br); err != nil {
		return nil, fmt.Errorf("failed to create bridge: %v", err)
	}

	if master != nil {
		if err := netlink.LinkSetMaster(br, master); err != nil {
			return nil, fmt.Errorf("failed to set bridge master to VRF: %v", err)
		}
	}

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, fmt.Errorf("failed to bring up bridge: %v", err)
	}

	return br, nil
}

func CreateVethPair(veth1, veth2 string) (*netlink.Veth, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: veth1,
		},
		PeerName: veth2,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("failed to create veth pair: %v", err)
	}

	return veth, nil
}

func MoveToNetnsAndRename(linkName, newLinkName, nsPath string) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("cannot find link %s: %v", linkName, err)
	}

	netns, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open netns %s: %v", nsPath, err)
	}
	defer netns.Close()

	err = netlink.LinkSetNsFd(link, int(netns.Fd()))
	if err != nil {
		return fmt.Errorf("failed to move link %s to netns: %v", linkName, err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetName(link, newLinkName); err != nil {
			return fmt.Errorf("failed to rename to eth0: %w", err)
		}
		return netlink.LinkSetUp(link)
	})
	if err != nil {
		return fmt.Errorf("failed to rename link %s to %s", linkName, newLinkName, err)
	}

	return nil
}

func AttachToBridge(linkName string, bridge *netlink.Bridge) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %v", linkName, err)
	}

	if err := netlink.LinkSetMaster(link, bridge); err != nil {
		return fmt.Errorf("failed to attach %s to bridge %s: %v", linkName, bridge.Attrs().Name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up link %s: %v", linkName, err)
	}

	return nil
}

func SetIPAndRoute(linkName, nsPath, ipNet, defaultGw string) error {
	netns, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open netns %s: %v", nsPath, err)
	}
	defer netns.Close()

	err = netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return err
		}

		addr, err := netlink.ParseAddr(ipNet)
		if err != nil {
			return err
		}

		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}

		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}

		_, defaultRoute, _ := net.ParseCIDR("0.0.0.0/0")

		gw := net.ParseIP(defaultGw)
		route := &netlink.Route{
			Dst:       defaultRoute,
			Gw:        gw,
			LinkIndex: link.Attrs().Index,
		}

		return netlink.RouteAdd(route)
	})
	if err != nil {
		return fmt.Errorf("failed to set IP and route for link %s: %v", linkName, err)
	}

	return nil
}
