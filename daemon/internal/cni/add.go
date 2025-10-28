package cni

import (
	"context"
	"net"

	"github.com/1outres/juneau/daemon/pkg/juneaupb"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"k8s.io/utils/ptr"
)

func (c *Cni) CmdAdd(ctx context.Context) error {
	vethHostName := c.vethHostName()
	vethPeerName := c.vethPeerName()

	// Check if the host veth exists
	vethHost, err := netlink.LinkByName(vethHostName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: vethHostName,
			},
			PeerName: vethPeerName,
		}
		if err := netlink.LinkAdd(veth); err != nil {
			zap.L().Error("failed to create veth pair", zap.Error(err))
			return &types.Error{
				Code:    types.ErrTryAgainLater,
				Msg:     "Failed to create veth pair",
				Details: err.Error(),
			}
		}
		vethHost, err = netlink.LinkByName(vethHostName)
		if err != nil {
			zap.L().Error("failed to lookup created veth", zap.Error(err))
			return &types.Error{
				Code:    types.ErrTryAgainLater,
				Msg:     "Failed to lookup created veth",
				Details: err.Error(),
			}
		}
	} else if err != nil {
		zap.L().Error("failed to lookup veth", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to lookup veth",
			Details: err.Error(),
		}
	} else {
		zap.L().Info("veth already exists", zap.String("veth", vethHost.Attrs().Name))
	}

	// If the host veth is down, bring it up
	if vethHost.Attrs().OperState != netlink.OperUp {
		if err := netlink.LinkSetUp(vethHost); err != nil {
			zap.L().Error("failed to bring up veth on host", zap.Error(err))
			return &types.Error{
				Code:    types.ErrTryAgainLater,
				Msg:     "Failed to bring up veth on host",
				Details: err.Error(),
			}
		}
	}

	// Open device netns
	netns, err := ns.GetNS(c.Netns)
	if err != nil {
		zap.L().Error("failed to open netns", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to open netns",
			Details: err.Error(),
		}
	}
	defer netns.Close()

	// If the peer veth exists in host netns, move it to device netns
	vethPeer, err := netlink.LinkByName(vethPeerName)
	if _, ok := err.(netlink.LinkNotFoundError); !ok && err != nil {
		zap.L().Error("failed to lookup peer veth", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to lookup peer veth",
			Details: err.Error(),
		}
	} else if err == nil {
		err = netlink.LinkSetNsFd(vethPeer, int(netns.Fd()))
		if err != nil {
			zap.L().Error("failed to move peer veth to netns", zap.Error(err))
			return &types.Error{
				Code:    types.ErrTryAgainLater,
				Msg:     "Failed to move peer veth to netns",
				Details: err.Error(),
			}
		}
	}

	// If the peer veth exists in device netns with the unexcepted name, rename it
	err = netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(vethPeerName)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetName(link, c.IfName); err != nil {
			return err
		}
		return nil
	})
	if _, ok := err.(netlink.LinkNotFoundError); !ok && err != nil {
		zap.L().Error("failed to rename peer veth in netns", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to rename peer veth in netns",
			Details: err.Error(),
		}
	}

	// If the peer veth does not exist in device netns, recreate it
	err = netns.Do(func(_ ns.NetNS) error {
		vethPeer, err = netlink.LinkByName(c.IfName)
		if err != nil {
			return err
		}
		return nil
	})
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		zap.L().Info("peer veth not found in netns, recreating it", zap.String("ifName", c.IfName))

		if err := netlink.LinkDel(vethHost); err != nil {
			zap.L().Error("failed to delete existing veth on host", zap.Error(err))
			return &types.Error{
				Code:    types.ErrTryAgainLater,
				Msg:     "Failed to delete existing veth on host",
				Details: err.Error(),
			}
		}
		return c.CmdAdd(ctx)
	} else if err != nil {
		zap.L().Error("failed to lookup peer veth in netns", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to lookup peer veth in netns",
			Details: err.Error(),
		}
	}

	// If the peer veth is down, bring it up
	if vethPeer.Attrs().OperState != netlink.OperUp {
		err = netns.Do(func(_ ns.NetNS) error {
			return netlink.LinkSetUp(vethPeer)
		})
		if err != nil {
			zap.L().Error("failed to bring up veth in netns", zap.Error(err))
			return &types.Error{
				Code:    types.ErrTryAgainLater,
				Msg:     "Failed to bring up veth in netns",
				Details: err.Error(),
			}
		}
	}

	// Request IP allocation
	allocateRes, err := c.IPAMClient.Allocate(ctx, &juneaupb.AllocateRequest{
		Id: &juneaupb.CNIIdentity{
			PodNamespace: c.PodNamespace,
			PodName:      c.PodName,
			PodUid:       c.PodUID,
			ContainerId:  c.ContainerID,
			IfName:       c.IfName,
		},
		MacAddress: vethPeer.Attrs().HardwareAddr.String(),
	})
	if err != nil {
		zap.L().Info("Failed to allocate IP", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to allocate IP",
			Details: err.Error(),
		}
	}
	if !allocateRes.Success {
		zap.L().Info("IP allocation failed", zap.String("message", allocateRes.Error.GetMessage()))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "IP allocation failed",
			Details: allocateRes.Error.GetMessage(),
		}
	}

	zap.L().Info("Allocated IP successfully", zap.String("ip", allocateRes.IpAssignment.Ipv4.AddressCidr))

	ip, ipnet, err := net.ParseCIDR(allocateRes.IpAssignment.Ipv4.AddressCidr)
	if err != nil {
		zap.L().Error("failed to parse allocated IP CIDR", zap.Error(err))
		return &types.Error{
			Code:    types.ErrDecodingFailure,
			Msg:     "Failed to parse allocated IP CIDR",
			Details: err.Error(),
		}
	}
	gateway := net.ParseIP(allocateRes.IpAssignment.Ipv4.Gateway)
	if gateway == nil {
		zap.L().Error("failed to parse gateway IP", zap.Error(err))
		return &types.Error{
			Code:    types.ErrDecodingFailure,
			Msg:     "Failed to parse gateway IP",
			Details: "invalid gateway IP",
		}
	}

	// Set IP address on the peer veth
	err = netns.Do(func(_ ns.NetNS) error {
		addrs, err := netlink.AddrList(vethPeer, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		addrCount := len(addrs)
		for _, addr := range addrs {
			addrOnes, _ := addr.Mask.Size()
			ipnetOnes, _ := ipnet.Mask.Size()

			if addr.IP.Equal(ip) && addrOnes == ipnetOnes {
				continue
			}

			if err := netlink.AddrDel(vethPeer, &addr); err != nil {
				return err
			}
			addrCount--
		}

		if addrCount < 1 {
			if err := netlink.AddrAdd(vethPeer, &netlink.Addr{IPNet: ipnet}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		zap.L().Error("failed to set IP address on veth", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to set IP address on veth",
			Details: err.Error(),
		}
	}

	// Set routes on the peer veth
	err = netns.Do(func(_ ns.NetNS) error {
		routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
		if err != nil {
			return err
		}

		routeCount := len(routes)
		for _, r := range routes {
			if r.Table != 254 {
				routeCount--
				continue
			}
			zap.L().Debug("examining route", zap.String("dst", r.Dst.String()), zap.String("gw", r.Gw.String()), zap.Int("linkIndex", r.LinkIndex))
			if r.Dst != nil {
				routeCount--
				continue // not default
			}

			if r.Gw != nil && r.Gw.Equal(gateway) && r.LinkIndex == vethPeer.Attrs().Index {
				continue
			}

			if err := netlink.RouteDel(&r); err != nil {
				return err
			}
			routeCount--
		}

		if routeCount < 1 {
			route := &netlink.Route{
				LinkIndex: vethPeer.Attrs().Index,
				Gw:        gateway,
				Table:     254,
			}
			if err := netlink.RouteAdd(route); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		zap.L().Error("failed to set routes on veth", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to set routes on veth",
			Details: err.Error(),
		}
	}

	zap.L().Info("CNI ADD completed successfully")

	_, defaultRoute, _ := net.ParseCIDR("0.0.0.0/0")
	return types.PrintResult(&types100.Result{
		CNIVersion: c.CNIVersion,
		Interfaces: []*types100.Interface{
			{
				Name:    c.IfName,
				Sandbox: c.Netns,
			},
		},
		IPs: []*types100.IPConfig{
			{
				Interface: ptr.To(0),
				Address: net.IPNet{
					IP:   ip,
					Mask: ipnet.Mask,
				},
				Gateway: gateway,
			},
		},
		Routes: []*types.Route{
			{
				Dst: *defaultRoute,
				GW:  gateway,
			},
		},
	}, c.CNIVersion)
}
