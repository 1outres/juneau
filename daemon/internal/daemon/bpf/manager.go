package bpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	toolscache "k8s.io/client-go/tools/cache"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager struct {
	mu sync.Mutex

	client       client.Client
	nwepInformer cache.Informer
	nwepHandler  toolscache.ResourceEventHandlerRegistration
	rtInformer   cache.Informer
	rtHandler    toolscache.ResourceEventHandlerRegistration

	nodeName     string
	vxlanIfindex int
	hostIfindex  int
	hostMac      net.HardwareAddr

	podEgressMapSpecs *PodEgressMapSpecs

	podEgressObjs    *PodEgressObjects
	podEgressLinks   map[int]link.Link
	hostEgressObjs   *HostEgressObjects
	hostEgressLink   link.Link
	vxlanIngressObjs *VxlanIngressObjects
	vxlanIngressLink link.Link
}

func (m *Manager) Start(ctx context.Context) error {
	const pinPath = "/sys/fs/bpf/juneau"

	if err := os.RemoveAll(pinPath); err != nil {
		zap.S().Errorf("failed to remove BPF pin path: %v", err)
		return fmt.Errorf("failed to remove BPF pin path: %w", err)
	}
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		zap.S().Errorf("failed to create BPF pin path: %v", err)
		return fmt.Errorf("failed to create BPF pin path: %w", err)
	}

	spec, err := LoadPodEgress()
	if err != nil {
		return err
	}

	if err := spec.Assign(m.podEgressMapSpecs); err != nil {
		return err
	}

	if err := LoadPodEgressObjects(m.podEgressObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		zap.S().Errorf("failed to load pod egress objects: %v", err)
		return err
	}

	mac, err := HardwareAddrToUint8Array(m.hostMac)
	if err != nil {
		return err
	}

	if err := m.podEgressObjs.HostIface.Update(uint32(0), &PodEgressHostIfaceVal{
		Ifindex: uint32(m.hostIfindex),
		Mac:     mac,
	}, ebpf.UpdateAny); err != nil {
		zap.S().Errorf("failed to update HostIfindex map: %v", err)
		return err
	}

	if err := LoadHostEgressObjects(m.hostEgressObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		zap.S().Errorf("failed to load host egress objects: %v", err)
		return err
	}

	if err := m.hostEgressObjs.VxlanIfindex.Update(uint32(0), uint32(m.vxlanIfindex), ebpf.UpdateAny); err != nil {
		zap.S().Errorf("failed to update VxlanIfindex map: %v", err)
		return err
	}

	hostEgressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.hostEgressObjs.TcHostEgress,
		Interface: m.hostIfindex,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		zap.S().Errorf("failed to attach TC program to host interface: %v", err)
		return err
	}
	m.hostEgressLink = hostEgressLink
	zap.S().Infof("attached TC program to host interface (ifindex: %d)", m.hostIfindex)

	if err := LoadVxlanIngressObjects(m.vxlanIngressObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		zap.S().Errorf("failed to load vxlan ingress objects: %v", err)
		return err
	}

	vxlanIngressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.vxlanIngressObjs.TcVxlanIngressEntry,
		Interface: m.vxlanIfindex,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		zap.S().Errorf("failed to attach TC program to vxlan interface: %v", err)
		return err
	}
	m.vxlanIngressLink = vxlanIngressLink
	zap.S().Infof("attached TC program to vxlan interface (ifindex: %d)", m.vxlanIfindex)

	nwepHandler, err := addEventHandler(ctx, m.nwepInformer, m.UpsertNetworkEndpoint, m.DeleteNetworkEndpoint)
	if err != nil {
		zap.S().Errorf("failed to add event handler for NetworkEndpoint: %v", err)
		return err
	}
	m.nwepHandler = nwepHandler

	rtHandler, err := addEventHandler(ctx, m.rtInformer, m.UpsertRouteTable, m.DeleteRouteTable)
	if err != nil {
		zap.S().Errorf("failed to add event handler for RouteTable: %v", err)
		return err
	}
	m.rtHandler = rtHandler

	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, l := range m.podEgressLinks {
		l.Close()
	}

	m.podEgressObjs.Close()

	m.nwepInformer.RemoveEventHandler(m.nwepHandler)

	m.hostEgressLink.Close()
	m.hostEgressObjs.Close()

	m.vxlanIngressLink.Close()
	m.vxlanIngressObjs.Close()

	return nil
}

func (m *Manager) UpsertNetworkEndpoint(ctx context.Context, nwep *juneauv1alpha1.NetworkEndpoint) error {
	zap.S().Infof("UpsertNetworkEndpoint called for %s/%s", nwep.Namespace, nwep.Name)

	var subnet juneauv1alpha1.Subnet
	if err := m.client.Get(ctx, client.ObjectKey{Name: nwep.Spec.Subnet}, &subnet); err != nil {
		return err
	}

	netaddr, _, err := net.ParseCIDR(nwep.Spec.Address)
	if err != nil {
		return err
	}

	addr, err := IPv4ToUint32(netaddr)
	if err != nil {
		return err
	}

	netmac, err := net.ParseMAC(nwep.Spec.MACAddress)
	if err != nil {
		return err
	}

	mac, err := HardwareAddrToUint8Array(netmac)
	if err != nil {
		return err
	}

	if err := m.hostEgressObjs.ArpTable.Update(
		&HostEgressArpTableKey{
			SubnetId: subnet.Status.VNI,
			Ipaddr:   addr,
		},
		&HostEgressArpTableVal{
			Mac: mac,
		},
		ebpf.UpdateAny); err != nil {
		zap.S().Errorf("failed to update ArpTable map: %v", err)
		return err
	}

	if nwep.Spec.NodeName == m.nodeName {
		if err := m.vxlanIngressObjs.Fdb.Update(
			&HostEgressFdbKey{
				SubnetId: subnet.Status.VNI,
				Mac:      mac,
			},
			&HostEgressFdbVal{
				Ifindex: uint32(nwep.Spec.Ifindex),
			},
			ebpf.UpdateAny); err != nil {
			zap.S().Errorf("failed to update Fdb map: %v", err)
			return err
		}
		// debug log for local pod including pods,podname, subnetid,mac,ifindex
		zap.S().Debugf("Local pod added to Fdb map: pod=%s/%s, subnetid=%d, mac=%s, ifindex=%d", nwep.Namespace, nwep.Name, subnet.Status.VNI, nwep.Spec.MACAddress, nwep.Spec.Ifindex)
	} else if nwep.Status.NodeIP != "" {
		netNodeAddr := net.ParseIP(nwep.Status.NodeIP)
		if netNodeAddr == nil {
			return fmt.Errorf("failed to parse node IP: %s", nwep.Status.NodeIP)
		}

		nodeAddr, err := IPv4ToUint32(netNodeAddr)
		if err != nil {
			return err
		}

		if err := m.hostEgressObjs.Fdb.Update(
			&HostEgressFdbKey{
				SubnetId: subnet.Status.VNI,
				Mac:      mac,
			},
			&HostEgressFdbVal{
				VtepIp: nodeAddr,
			},
			ebpf.UpdateAny); err != nil {
			zap.S().Errorf("failed to update Fdb map: %v", err)
			return err
		}
	}

	// Host only

	if nwep.Spec.NodeName != m.nodeName {
		return nil
	}

	var vpc juneauv1alpha1.Vpc
	if err := m.client.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		return err
	}
	var mainTable juneauv1alpha1.RouteTable
	if err := m.client.Get(ctx, client.ObjectKey{Name: vpc.Status.MainRouteTable}, &mainTable); err != nil {
		return err
	}

	var netgwmac net.HardwareAddr
	if subnet.Status.VNI == 1 {
		netgwmac = m.hostMac
	} else {
		var err error
		netgwmac, err = net.ParseMAC(subnet.Status.GatewayMAC)
		if err != nil {
			return err
		}
	}

	gwmac, err := HardwareAddrToUint8Array(netgwmac)
	if err != nil {
		return err
	}

	_, ipnet, err := net.ParseCIDR(subnet.Spec.CIDR)
	if err != nil {
		return err
	}

	netgwaddr := net.ParseIP(subnet.Status.Gateway)
	if netgwaddr == nil {
		return fmt.Errorf("failed to parse gateway IP: %s", subnet.Status.Gateway)
	}

	gwaddr, err := IPv4ToUint32(netgwaddr)
	if err != nil {
		return err
	}

	mask, err := IPMaskToUint32(ipnet.Mask)
	if err != nil {
		return err
	}

	if err := m.podEgressObjs.IfindexSubnet.Update(
		&PodEgressIfindexSubnetKey{
			Ifindex: uint32(nwep.Spec.Ifindex),
		},
		&PodEgressIfindexSubnetVal{
			SubnetId: subnet.Status.VNI,
			TableId:  mainTable.Status.TableID,
			GwMac:    gwmac,
			GwAddr:   gwaddr,
			Mask:     mask,
		},
		ebpf.UpdateAny); err != nil {
		zap.S().Errorf("failed to update IfindexSubnet map: %v", err)
		return err
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   m.podEgressObjs.TcPodEgress,
		Interface: int(nwep.Spec.Ifindex),
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
			return nil
		}
		zap.S().Errorf("failed to attach TC program: %v", err)
		return err
	} else {
		zap.S().Infof("attached TC program to pod interface (ifindex: %d)", nwep.Spec.Ifindex)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.podEgressLinks[nwep.Spec.Ifindex] = l

	return nil
}

func (m *Manager) DeleteNetworkEndpoint(ctx context.Context, nwep *juneauv1alpha1.NetworkEndpoint) error {
	zap.S().Infof("DeleteNetworkEndpoint called for %s/%s", nwep.Namespace, nwep.Name)

	var subnet juneauv1alpha1.Subnet
	if err := m.client.Get(ctx, client.ObjectKey{Name: nwep.Spec.Subnet}, &subnet); err != nil {
		return err
	}

	netaddr, _, err := net.ParseCIDR(nwep.Spec.Address)
	if err != nil {
		return err
	}

	addr, err := IPv4ToUint32(netaddr)
	if err != nil {
		return err
	}

	if err := m.hostEgressObjs.ArpTable.Delete(&HostEgressArpTableKey{
		SubnetId: subnet.Status.VNI,
		Ipaddr:   addr,
	}); err != nil {
		zap.S().Errorf("failed to delete from ArpTable map: %v", err)
		return err
	}

	netmac, err := net.ParseMAC(nwep.Spec.MACAddress)
	if err != nil {
		return err
	}

	mac, err := HardwareAddrToUint8Array(netmac)
	if err != nil {
		return err
	}

	if err := m.hostEgressObjs.Fdb.Delete(&HostEgressFdbKey{
		SubnetId: subnet.Status.VNI,
		Mac:      mac,
	}); err != nil {
		zap.S().Errorf("failed to delete from Fdb map: %v", err)
		return err
	}

	// Host only

	if nwep.Spec.NodeName != m.nodeName {
		return nil
	}

	if err := m.podEgressObjs.IfindexSubnet.Delete(&PodEgressIfindexSubnetKey{
		Ifindex: uint32(nwep.Spec.Ifindex),
	}); err != nil {
		zap.S().Errorf("failed to delete from IfindexSubnet map: %v", err)
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if l, ok := m.podEgressLinks[nwep.Spec.Ifindex]; ok {
		l.Close()
	}
	delete(m.podEgressLinks, nwep.Spec.Ifindex)

	return nil
}

func (m *Manager) UpsertRouteTable(ctx context.Context, rt *juneauv1alpha1.RouteTable) error {
	fib, err := ebpf.NewMap(m.podEgressMapSpecs.FibInner.Copy())
	if err != nil {
		zap.S().Errorf("failed to create new FIB inner map: %v", err)
		return err
	}

	for _, route := range rt.Status.Routes {
		var subnet juneauv1alpha1.Subnet
		if err := m.client.Get(ctx, client.ObjectKey{Name: route.Subnet}, &subnet); err != nil {
			return err
		}

		netaddr, ipnet, err := net.ParseCIDR(route.Dst)
		if err != nil {
			zap.S().Errorf("failed to parse CIDR %s: %v", route.Dst, err)
			continue
		}

		addr := binary.LittleEndian.Uint32(netaddr.To4())

		prefixlen, _ := ipnet.Mask.Size()

		key := PodEgressFibKey{
			Dst:       addr,
			Prefixlen: uint32(prefixlen),
		}
		val := PodEgressFibVal{
			Dmac:     [6]uint8{},
			Smac:     [6]uint8{},
			SubnetId: subnet.Status.VNI,
			Oif:      0,
		}

		if route.Via.Type == juneauv1alpha1.ViaConnnected {

			netmac, err := net.ParseMAC(subnet.Status.GatewayMAC)
			if err != nil {
				return err
			}

			mac, err := HardwareAddrToUint8Array(netmac)
			if err != nil {
				return err
			}

			val.Smac = mac

		} else if route.Via.Type == juneauv1alpha1.ViaEndpoint {
			// TODO:
			continue
		}

		if err := fib.Update(&key, &val, ebpf.UpdateAny); err != nil {
			zap.S().Errorf("failed to update FIB inner map: %v", err)
		}
	}

	if err := m.podEgressObjs.FibMap.Update(uint32(rt.Status.TableID), uint32(fib.FD()), ebpf.UpdateAny); err != nil {
		fib.Close()
		return err
	}

	return nil
}

func (m *Manager) DeleteRouteTable(ctx context.Context, rt *juneauv1alpha1.RouteTable) error {
	if err := m.podEgressObjs.FibMap.Delete(uint32(rt.Status.TableID)); err != nil {
		return err
	}
	return nil
}

func NewManager(cl client.Client, nwepInformer cache.Informer, rtInformer cache.Informer, nodeName string, vxlanIfindex int, hostIfindex int, defaultGatewayMac net.HardwareAddr) *Manager {
	return &Manager{
		client:            cl,
		nwepInformer:      nwepInformer,
		rtInformer:        rtInformer,
		nodeName:          nodeName,
		vxlanIfindex:      vxlanIfindex,
		hostIfindex:       hostIfindex,
		hostMac:           defaultGatewayMac,
		podEgressMapSpecs: &PodEgressMapSpecs{},
		podEgressObjs:     &PodEgressObjects{},
		podEgressLinks:    make(map[int]link.Link),
		hostEgressObjs:    &HostEgressObjects{},
		vxlanIngressObjs:  &VxlanIngressObjects{},
	}
}

func addEventHandler[T any](ctx context.Context, informer cache.Informer, upsert func(context.Context, *T) error, delete func(context.Context, *T) error) (toolscache.ResourceEventHandlerRegistration, error) {
	return informer.AddEventHandlerWithResyncPeriod(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			p, ok := obj.(*T)
			if !ok {
				return
			}
			newCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := upsert(newCtx, p); err != nil {
				zap.S().Errorf("failed to upsert object: %v", err)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			p, ok := newObj.(*T)
			if !ok {
				return
			}
			newCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := upsert(newCtx, p); err != nil {
				zap.S().Errorf("failed to upsert object: %v", err)
			}
		},
		DeleteFunc: func(obj any) {
			p, ok := obj.(*T)
			if !ok {
				return
			}
			newCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := delete(newCtx, p); err != nil {
				zap.S().Errorf("failed to delete object: %v", err)
			}
		},
	}, 15*time.Minute)
}

// net.HardwareAddr -> [6]uint8
func HardwareAddrToUint8Array(mac net.HardwareAddr) ([6]uint8, error) {
	var arr [6]uint8
	if len(mac) != 6 {
		return arr, fmt.Errorf("invalid MAC address length: %d", len(mac))
	}
	copy(arr[:], mac)
	return arr, nil
}

// net.IP (IPv4) -> uint32 (eBPF map host-order value, e.g. 10.16.0.1 -> 0x0a100001)
func IPv4ToUint32(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %v", ip)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

// net.IPMask -> uint32 (eBPF map host-order value, e.g. /16 -> 0xffff0000)
func IPMaskToUint32(mask net.IPMask) (uint32, error) {
	if len(mask) != 4 {
		return 0, fmt.Errorf("invalid IPv4 mask length: %d", len(mask))
	}
	return binary.BigEndian.Uint32(mask), nil
}
