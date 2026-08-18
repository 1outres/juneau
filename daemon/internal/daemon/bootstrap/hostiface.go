package bootstrap

import (
	"context"
	"fmt"
	"net"

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
