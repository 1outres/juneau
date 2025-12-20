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
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type HostIfaceInfo struct {
	MAC     net.HardwareAddr
	Ifindex int
}

func SearchMainIface(ctx context.Context, cl client.Client, nodeName string) (string, error) {
	var node corev1.Node
	if err := cl.Get(ctx, client.ObjectKey{Name: nodeName}, &node); err != nil {
		return "", err
	}

	var address net.IP
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			address = net.ParseIP(addr.Address)
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("net.Interfaces: %w", err)
	}

	for i := range ifaces {
		iface := &ifaces[i]

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if ip4.Equal(address) {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no iface found with IP %q", address.String())
}

func SetupVxlanIface(parentIface string) (int, error) {
	vxlan, err := netlink.LinkByName("juneau_vxlan")
	if _, ok := err.(netlink.LinkNotFoundError); ok {

		parent, err := netlink.LinkByName(parentIface)
		if err != nil {
			zap.L().Error("failed to lookup parent iface", zap.Error(err))
			return 0, err
		}

		vx := &netlink.Vxlan{
			LinkAttrs: netlink.LinkAttrs{
				Name: "juneau_vxlan",
			},
			VtepDevIndex: parent.Attrs().Index,
			FlowBased:    true,
			Port:         4789,
			Learning:     false,
		}
		if err := netlink.LinkAdd(vx); err != nil {
			zap.L().Error("failed to create vxlan iface", zap.Error(err))
			return 0, err
		}

		vxlan, err = netlink.LinkByName("juneau_vxlan")
		if err != nil {
			zap.L().Error("failed to lookup created vxlan iface", zap.Error(err))
			return 0, err
		}
	} else if err != nil {
		zap.L().Error("failed to lookup vxlan iface", zap.Error(err))
		return 0, err
	}

	if err := netlink.LinkSetUp(vxlan); err != nil {
		zap.L().Error("failed to bring up vxlan iface", zap.Error(err))
		return 0, err
	}

	return vxlan.Attrs().Index, nil
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

	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		if a.IPNet.IP.Equal(want.IP) && bytes.Equal(a.IPNet.Mask, want.Mask) {
			return hostIfaceInfo, nil
		}
	}

	if err := netlink.AddrAdd(vethPeer, &netlink.Addr{IPNet: want}); err != nil {
		if !os.IsExist(err) {
			zap.L().Error("failed to add IP address to cni_host", zap.Error(err))
			return nil, err
		}
	}

	return hostIfaceInfo, nil
}
