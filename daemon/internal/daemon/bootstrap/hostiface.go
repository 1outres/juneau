package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type HostIfaceInfo struct {
	MAC     net.HardwareAddr
	Ifindex int
}

func SetupDefaultGatewayIface(ctx context.Context, cl client.Client) (*HostIfaceInfo, error) {
	var subnet juneauv1alpha1.Subnet
	if err := cl.Get(ctx, client.ObjectKey{Name: "default"}, &subnet); err != nil {
		zap.L().Error("failed to get default Subnet", zap.Error(err))
		return nil, err
	}

	const (
		hostName = "cni_net"
		peerName = "cni_host"
	)

	zap.S().Debugf("Setting up default gateway iface with gateway: %s", subnet.Status.Gateway)

	vethHost, err := netlink.LinkByName(hostName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			veth := &netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{Name: hostName},
				PeerName:  peerName,
			}
			if err := netlink.LinkAdd(veth); err != nil {
				if !os.IsExist(err) {
					zap.L().Error("failed to create veth pair", zap.Error(err))
					return nil, err
				}
			}

			vethHost, err = netlink.LinkByName(hostName)
			if err != nil {
				zap.L().Error("failed to lookup created veth", zap.Error(err))
				return nil, err
			}
		} else {
			zap.L().Error("failed to lookup veth", zap.Error(err))
			return nil, err
		}
	}

	vethPeer, err := netlink.LinkByName(peerName)
	if err != nil {
		zap.L().Error("failed to lookup veth peer", zap.Error(err))
		return nil, err
	}

	if err := netlink.LinkSetUp(vethHost); err != nil {
		zap.L().Error("failed to bring up cni_net on host", zap.Error(err))
		return nil, err
	}
	if err := netlink.LinkSetUp(vethPeer); err != nil {
		zap.L().Error("failed to bring up cni_host on host", zap.Error(err))
		return nil, err
	}

	_, ipnet, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		zap.L().Error("failed to parse subnet CIDR", zap.Error(err))
		return nil, err
	}
	ip := net.ParseIP(subnet.Status.Gateway)
	if ip == nil {
		return nil, fmt.Errorf("invalid gateway IP: %q", subnet.Status.Gateway)
	}

	hostIfaceInfo := &HostIfaceInfo{
		MAC:     vethPeer.Attrs().HardwareAddr,
		Ifindex: vethHost.Attrs().Index,
	}

	want := &net.IPNet{IP: ip, Mask: ipnet.Mask}

	addrs, err := netlink.AddrList(vethPeer, netlink.FAMILY_ALL)
	if err != nil {
		zap.L().Error("failed to list addresses on cni_host", zap.Error(err))
		return nil, err
	}

	hasAnyAddr := false
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		hasAnyAddr = true
		if a.IPNet.IP.Equal(want.IP) && bytes.Equal(a.IPNet.Mask, want.Mask) {
			return hostIfaceInfo, nil
		}
	}

	if !hasAnyAddr {
		if err := netlink.AddrAdd(vethPeer, &netlink.Addr{IPNet: want}); err != nil {
			if !os.IsExist(err) {
				zap.L().Error("failed to add IP address to cni_host", zap.Error(err))
				return nil, err
			}
		}
	}

	return hostIfaceInfo, nil
}
