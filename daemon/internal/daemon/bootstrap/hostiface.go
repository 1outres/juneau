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

// JuneauNodeIfaceName is the BPF-attached side of the per-node veth
// pair that acts as the host's pseudo-pod for the default Subnet.
// Renamed from the legacy "cni_net" in Phase 4b-4.
const JuneauNodeIfaceName = "juneau_node"

// JuneauNodeHostIfaceName is the peer end of the juneau_node veth pair.
// It carries the per-node reserved IP and is what the host network
// stack sees as its default-Subnet gateway.
const JuneauNodeHostIfaceName = "juneau_node_h"

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

// SetupDefaultGatewayIface creates (or reuses) the juneau_node veth
// pair, configures the per-node reserved IP on the host-facing peer,
// and returns the information downstream wiring needs.
//
// The reserved IP is read from the AllocationClaim filed by the
// controller's NodeReconciler against the default Subnet's IP pool.
// Until the claim resolves the function returns an error so the
// daemon's startup loop can retry.
func SetupDefaultGatewayIface(ctx context.Context, cl client.Client, nodeName string) (*JuneauNodeIfaceInfo, error) {
	var subnet juneauv1alpha1.Subnet
	if err := cl.Get(ctx, client.ObjectKey{Name: "default"}, &subnet); err != nil {
		zap.L().Error("failed to get default Subnet", zap.Error(err))
		return nil, err
	}

	reservedIP, err := lookupJuneauNodeReservedIP(ctx, cl, nodeName)
	if err != nil {
		return nil, err
	}

	zap.S().Debugf("Setting up juneau_node iface with reserved IP %s", reservedIP)

	vethHost, err := netlink.LinkByName(JuneauNodeIfaceName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			veth := &netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{Name: JuneauNodeIfaceName},
				PeerName:  JuneauNodeHostIfaceName,
			}
			if err := netlink.LinkAdd(veth); err != nil {
				if !os.IsExist(err) {
					zap.L().Error("failed to create juneau_node veth pair", zap.Error(err))
					return nil, err
				}
			}

			vethHost, err = netlink.LinkByName(JuneauNodeIfaceName)
			if err != nil {
				zap.L().Error("failed to lookup created juneau_node iface", zap.Error(err))
				return nil, err
			}
		} else {
			zap.L().Error("failed to lookup juneau_node iface", zap.Error(err))
			return nil, err
		}
	}

	vethPeer, err := netlink.LinkByName(JuneauNodeHostIfaceName)
	if err != nil {
		zap.L().Error("failed to lookup juneau_node host-side peer", zap.Error(err))
		return nil, err
	}

	if err := netlink.LinkSetUp(vethHost); err != nil {
		zap.L().Error("failed to bring up juneau_node", zap.Error(err))
		return nil, err
	}
	if err := netlink.LinkSetUp(vethPeer); err != nil {
		zap.L().Error("failed to bring up juneau_node host-side peer", zap.Error(err))
		return nil, err
	}

	_, ipnet, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		zap.L().Error("failed to parse subnet CIDR", zap.Error(err))
		return nil, err
	}

	info := &JuneauNodeIfaceInfo{
		HostIfaceInfo: HostIfaceInfo{
			MAC:     vethPeer.Attrs().HardwareAddr,
			Ifindex: vethHost.Attrs().Index,
		},
		HostSideMAC: vethPeer.Attrs().HardwareAddr,
		AssignedIP:  reservedIP,
	}

	want := &net.IPNet{IP: reservedIP, Mask: ipnet.Mask}

	addrs, err := netlink.AddrList(vethPeer, netlink.FAMILY_ALL)
	if err != nil {
		zap.L().Error("failed to list addresses on juneau_node host-side peer", zap.Error(err))
		return nil, err
	}

	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		if a.IPNet.IP.Equal(want.IP) && bytes.Equal(a.IPNet.Mask, want.Mask) {
			return info, nil
		}
		// Drop stale addresses: the per-node IP may have changed
		// across daemon restarts (claim recreated, etc.).
		if !a.IPNet.IP.IsLinkLocalUnicast() {
			if delErr := netlink.AddrDel(vethPeer, &netlink.Addr{IPNet: a.IPNet}); delErr != nil {
				zap.L().Warn("failed to delete stale address on juneau_node host-side peer", zap.Error(delErr))
			}
		}
	}

	if err := netlink.AddrAdd(vethPeer, &netlink.Addr{IPNet: want}); err != nil {
		if !os.IsExist(err) {
			zap.L().Error("failed to add IP address to juneau_node host-side peer", zap.Error(err))
			return nil, err
		}
	}

	return info, nil
}

// lookupJuneauNodeReservedIP fetches the per-node AllocationClaim
// produced by the controller's NodeReconciler and returns its
// allocated IP. Returns an error if the claim is missing or has not
// yet resolved.
func lookupJuneauNodeReservedIP(ctx context.Context, cl client.Client, nodeName string) (net.IP, error) {
	claimName := juneauNodeClaimName(nodeName)
	var claim juneauv1alpha1.AllocationClaim
	if err := cl.Get(ctx, client.ObjectKey{Name: claimName}, &claim); err != nil {
		return nil, fmt.Errorf("get juneau_node AllocationClaim %q: %w", claimName, err)
	}

	if claim.Status.Phase != juneauv1alpha1.AllocationClaimPhaseAllocated {
		return nil, fmt.Errorf("juneau_node AllocationClaim %q is not yet allocated (phase=%q)", claimName, claim.Status.Phase)
	}

	if claim.Status.Value.IP == "" {
		return nil, fmt.Errorf("juneau_node AllocationClaim %q has no allocated IP", claimName)
	}

	ip := net.ParseIP(claim.Status.Value.IP)
	if ip == nil {
		return nil, fmt.Errorf("juneau_node AllocationClaim %q has invalid IP %q", claimName, claim.Status.Value.IP)
	}
	return ip, nil
}

// juneauNodeClaimName mirrors controller/internal/controller.JuneauNodeClaimName.
// Duplicated here to avoid a circular dependency: the daemon imports
// only the v1alpha1 types, never the controller's reconciler package.
func juneauNodeClaimName(nodeName string) string {
	parts := []string{
		"subnet-ip-default", // SubnetIPAllocationPoolName("default")
		"node",              // GVK.Kind
		// namespace is empty for cluster-scoped Nodes
		nodeName,
		"juneaunode-assignedip", // sanitized "juneauNode.assignedIP"
	}
	for i := range parts {
		parts[i] = sanitizeAllocationName(parts[i])
	}
	out := parts[0] + "--" + parts[1] + "--" + parts[2] + "--" + parts[3]
	return out
}

// sanitizeAllocationName is the daemon-side mirror of the controller's
// allocationNameSanitizer.
func sanitizeAllocationName(s string) string {
	out := make([]rune, 0, len(s))
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			out = append(out, r+32)
			prevDash = false
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			out = append(out, r)
			prevDash = false
		case r == '-':
			if !prevDash {
				out = append(out, r)
			}
			prevDash = true
		default:
			if !prevDash {
				out = append(out, '-')
			}
			prevDash = true
		}
	}
	// trim leading/trailing dashes/dots
	start, end := 0, len(out)
	for start < end && (out[start] == '-' || out[start] == '.') {
		start++
	}
	for end > start && (out[end-1] == '-' || out[end-1] == '.') {
		end--
	}
	return string(out[start:end])
}
