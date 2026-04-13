package bpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/mdlayher/arp"
	"github.com/vishvananda/netlink"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager struct {
	mu sync.Mutex

	client                   client.Client
	nwepInformer             cache.Informer
	nwepHandler              toolscache.ResourceEventHandlerRegistration
	eipaInformer             cache.Informer
	eipaHandler              toolscache.ResourceEventHandlerRegistration
	addressPoolInformer      cache.Informer
	addressPoolHandler       toolscache.ResourceEventHandlerRegistration
	bgpAdvertisementInformer cache.Informer
	bgpAdvertisementHandler  toolscache.ResourceEventHandlerRegistration
	subnetInformer           cache.Informer
	subnetHandler            toolscache.ResourceEventHandlerRegistration
	rtInformer               cache.Informer
	rtHandler                toolscache.ResourceEventHandlerRegistration

	nodeName           string
	vxlanIfindex       int
	hostIfindex        int
	nodeIngressIfindex int
	pinPath            string
	hostMac            net.HardwareAddr
	externalGateway    *InternetGatewayInfo

	podEgressMapSpecs *PodEgressMapSpecs

	podEgressObjs    *PodEgressObjects
	podEgressLinks   map[int]link.Link
	bgpAddressPools  map[string]PodEgressBgpAddressPoolsKey
	hostEgressObjs   *HostEgressObjects
	hostEgressLink   link.Link
	vxlanIngressObjs *VxlanIngressObjects
	vxlanIngressLink link.Link
	nodeIngressObjs  *NodeIngressObjects
	nodeIngressLink  link.Link
}

type InternetGatewayInfo struct {
	Ifindex    int
	SourceMAC  net.HardwareAddr
	NextHopIP  net.IP
	NextHopMAC net.HardwareAddr
}

const (
	fibRouteTypeConnected       = 1
	fibRouteTypeEndpoint        = 2
	fibRouteTypeInternetGateway = 3
)

func (m *Manager) Start(ctx context.Context) error {
	internetGateway, err := resolveInternetGatewayInfo(m.nodeIngressIfindex)
	if err != nil {
		zap.S().Warnf("failed to resolve internet gateway info: %v", err)
	} else {
		m.externalGateway = internetGateway
	}

	if err := os.RemoveAll(m.pinPath); err != nil {
		zap.S().Errorf("failed to remove BPF pin path: %v", err)
		return fmt.Errorf("failed to remove BPF pin path: %w", err)
	}
	if err := os.MkdirAll(m.pinPath, 0755); err != nil {
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

	if err = LoadPodEgressObjects(m.podEgressObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: m.pinPath,
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
			PinPath: m.pinPath,
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
			PinPath: m.pinPath,
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

	if err := LoadNodeIngressObjects(m.nodeIngressObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: m.pinPath,
		},
	}); err != nil {
		zap.S().Errorf("failed to load node ingress objects: %v", err)
		return err
	}

	nodeIngressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.nodeIngressObjs.TcNodeIngress,
		Interface: m.nodeIngressIfindex,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		zap.S().Errorf("failed to attach TC program to node ingress interface: %v", err)
		return err
	}
	m.nodeIngressLink = nodeIngressLink
	zap.S().Infof("attached TC program to node ingress interface (ifindex: %d)", m.nodeIngressIfindex)

	nwepHandler, err := addEventHandler(ctx, m.nwepInformer, m.UpsertNetworkEndpoint, m.DeleteNetworkEndpoint)
	if err != nil {
		zap.S().Errorf("failed to add event handler for NetworkEndpoint: %v", err)
		return err
	}
	m.nwepHandler = nwepHandler

	eipaHandler, err := addEventHandler(ctx, m.eipaInformer, m.UpsertElasticIPAttachment, m.DeleteElasticIPAttachment, m.UpdateElasticIPAttachment)
	if err != nil {
		zap.S().Errorf("failed to add event handler for ElasticIPAttachment: %v", err)
		return err
	}
	m.eipaHandler = eipaHandler

	addressPoolHandler, err := addEventHandler(ctx, m.addressPoolInformer, m.UpsertAddressPool, m.DeleteAddressPool)
	if err != nil {
		zap.S().Errorf("failed to add event handler for AddressPool: %v", err)
		return err
	}
	m.addressPoolHandler = addressPoolHandler

	bgpAdvertisementHandler, err := addEventHandler(ctx, m.bgpAdvertisementInformer, m.UpsertBGPAdvertisement, m.DeleteBGPAdvertisement)
	if err != nil {
		zap.S().Errorf("failed to add event handler for BGPAdvertisement: %v", err)
		return err
	}
	m.bgpAdvertisementHandler = bgpAdvertisementHandler

	subnetHandler, err := addEventHandler(ctx, m.subnetInformer, m.UpsertSubnet, m.DeleteSubnet)
	if err != nil {
		zap.S().Errorf("failed to add event handler for Subnet: %v", err)
		return err
	}
	m.subnetHandler = subnetHandler

	rtHandler, err := addEventHandler(ctx, m.rtInformer, m.UpsertRouteTable, m.DeleteRouteTable)
	if err != nil {
		zap.S().Errorf("failed to add event handler for RouteTable: %v", err)
		return err
	}
	m.rtHandler = rtHandler

	if err := m.rebuildBGPAddressPools(ctx); err != nil {
		return err
	}

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
	m.eipaInformer.RemoveEventHandler(m.eipaHandler)
	m.addressPoolInformer.RemoveEventHandler(m.addressPoolHandler)
	m.bgpAdvertisementInformer.RemoveEventHandler(m.bgpAdvertisementHandler)

	m.hostEgressLink.Close()
	m.hostEgressObjs.Close()

	m.vxlanIngressLink.Close()
	m.vxlanIngressObjs.Close()

	m.nodeIngressLink.Close()
	m.nodeIngressObjs.Close()

	return nil
}

func (m *Manager) UpsertSubnet(ctx context.Context, subnet *juneauv1alpha1.Subnet) error {
	zap.S().Infof("UpsertSubnet called for %s/%s", subnet.Namespace, subnet.Name)

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

	if err := m.hostEgressObjs.SubnetMap.Update(&HostEgressSubnetKey{
		SubnetId: subnet.Status.VNI,
	}, &HostEgressSubnetVal{
		TableId: mainTable.Status.TableID,
		GwMac:   gwmac,
		GwAddr:  gwaddr,
		Mask:    mask,
	}, ebpf.UpdateAny); err != nil {
		zap.S().Errorf("failed to update Subnet map: %v", err)
		return err
	}

	return nil
}

func (m *Manager) DeleteSubnet(ctx context.Context, subnet *juneauv1alpha1.Subnet) error {
	zap.S().Infof("DeleteSubnet called for %s/%s", subnet.Namespace, subnet.Name)

	if err := m.hostEgressObjs.SubnetMap.Delete(&HostEgressSubnetKey{SubnetId: subnet.Status.VNI}); err != nil {
		zap.S().Errorf("failed to delete from Subnet map: %v", err)
		return err
	}

	return nil
}

func (m *Manager) UpsertAddressPool(ctx context.Context, pool *juneauv1alpha1.AddressPool) error {
	zap.S().Infof("UpsertAddressPool called for %s", pool.Name)
	return m.rebuildBGPAddressPools(ctx)
}

func (m *Manager) DeleteAddressPool(ctx context.Context, pool *juneauv1alpha1.AddressPool) error {
	zap.S().Infof("DeleteAddressPool called for %s", pool.Name)
	return m.rebuildBGPAddressPools(ctx)
}

func (m *Manager) UpsertBGPAdvertisement(ctx context.Context, adv *juneauv1alpha1.BGPAdvertisement) error {
	zap.S().Infof("UpsertBGPAdvertisement called for %s", adv.Name)
	return m.rebuildBGPAddressPools(ctx)
}

func (m *Manager) DeleteBGPAdvertisement(ctx context.Context, adv *juneauv1alpha1.BGPAdvertisement) error {
	zap.S().Infof("DeleteBGPAdvertisement called for %s", adv.Name)
	return m.rebuildBGPAddressPools(ctx)
}

func (m *Manager) UpsertElasticIPAttachment(ctx context.Context, eipa *juneauv1alpha1.ElasticIPAttachment) error {
	zap.S().Infof("UpsertElasticIPAttachment called for %s/%s", eipa.Namespace, eipa.Name)

	if !m.shouldProgramElasticIPAttachment(eipa) {
		return m.DeleteElasticIPAttachment(ctx, eipa)
	}

	outside, inside, err := m.resolveElasticIPAttachmentNAT(ctx, eipa)
	if err != nil {
		return err
	}

	if err := m.podEgressObjs.NatDnatMap.Update(&outside, &inside, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update nat_dnat_map: %w", err)
	}

	if err := m.podEgressObjs.NatSnatMap.Update(&inside, &outside, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update nat_snat_map: %w", err)
	}

	return nil
}

func (m *Manager) DeleteElasticIPAttachment(ctx context.Context, eipa *juneauv1alpha1.ElasticIPAttachment) error {
	zap.S().Infof("DeleteElasticIPAttachment called for %s/%s", eipa.Namespace, eipa.Name)

	if eipa.Status.NodeName != m.nodeName || eipa.Status.ElasticIP == "" || eipa.Status.PodIP == "" {
		return nil
	}

	outside, inside, err := m.resolveElasticIPAttachmentNAT(ctx, eipa)
	if err != nil {
		return err
	}

	if err := m.podEgressObjs.NatDnatMap.Delete(&outside); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete nat_dnat_map: %w", err)
	}

	if err := m.podEgressObjs.NatSnatMap.Delete(&inside); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete nat_snat_map: %w", err)
	}

	return nil
}

func (m *Manager) UpdateElasticIPAttachment(ctx context.Context, oldEIPA, newEIPA *juneauv1alpha1.ElasticIPAttachment) error {
	if err := m.DeleteElasticIPAttachment(ctx, oldEIPA); err != nil {
		return err
	}
	return m.UpsertElasticIPAttachment(ctx, newEIPA)
}

func (m *Manager) shouldProgramElasticIPAttachment(eipa *juneauv1alpha1.ElasticIPAttachment) bool {
	return eipa.DeletionTimestamp == nil &&
		eipa.Status.Phase == juneauv1alpha1.ElasticIPAttachmentPhaseAttached &&
		eipa.Status.ElasticIP != "" &&
		eipa.Status.PodIP != "" &&
		eipa.Status.NodeName == m.nodeName
}

func (m *Manager) resolveElasticIPAttachmentNAT(ctx context.Context, eipa *juneauv1alpha1.ElasticIPAttachment) (PodEgressNatOutside, PodEgressNatInside, error) {
	var outside PodEgressNatOutside
	var inside PodEgressNatInside

	elasticIP := net.ParseIP(eipa.Status.ElasticIP)
	if elasticIP == nil {
		return outside, inside, fmt.Errorf("failed to parse elastic IP: %s", eipa.Status.ElasticIP)
	}
	outsideAddr, err := IPv4ToUint32(elasticIP)
	if err != nil {
		return outside, inside, err
	}

	podIP := net.ParseIP(eipa.Status.PodIP)
	if podIP == nil {
		return outside, inside, fmt.Errorf("failed to parse pod IP: %s", eipa.Status.PodIP)
	}
	insideAddr, err := IPv4ToUint32(podIP)
	if err != nil {
		return outside, inside, err
	}

	subnetName, err := m.resolveElasticIPAttachmentSubnetName(ctx, eipa)
	if err != nil {
		return outside, inside, err
	}

	var subnet juneauv1alpha1.Subnet
	if err := m.client.Get(ctx, client.ObjectKey{Name: subnetName}, &subnet); err != nil {
		return outside, inside, err
	}

	outside.Addr = outsideAddr
	inside.SubnetId = subnet.Status.VNI
	inside.Addr = insideAddr

	return outside, inside, nil
}

func (m *Manager) resolveElasticIPAttachmentSubnetName(ctx context.Context, eipa *juneauv1alpha1.ElasticIPAttachment) (string, error) {
	var nwif juneauv1alpha1.NetworkInterface
	if err := m.client.Get(ctx, client.ObjectKey{Namespace: eipa.Namespace, Name: eipa.Spec.TargetRef.NetworkInterfaceName}, &nwif); err == nil {
		if nwif.Spec.Subnet != "" {
			return nwif.Spec.Subnet, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return "", err
	}

	var nwep juneauv1alpha1.NetworkEndpoint
	if err := m.client.Get(ctx, client.ObjectKey{Namespace: eipa.Namespace, Name: eipa.Spec.TargetRef.NetworkInterfaceName}, &nwep); err != nil {
		return "", err
	}
	if nwep.Spec.Subnet == "" {
		return "", fmt.Errorf("network endpoint %s/%s has empty subnet", nwep.Namespace, nwep.Name)
	}

	return nwep.Spec.Subnet, nil
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
		return m.rebuildAllRouteTables(ctx)
	}

	var vpc juneauv1alpha1.Vpc
	if err := m.client.Get(ctx, client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		return err
	}
	var mainTable juneauv1alpha1.RouteTable
	if err := m.client.Get(ctx, client.ObjectKey{Name: vpc.Status.MainRouteTable}, &mainTable); err != nil {
		return err
	}

	if err := m.podEgressObjs.IfindexSubnet.Update(
		&PodEgressIfindexSubnetKey{
			Ifindex: uint32(nwep.Spec.Ifindex),
		},
		&PodEgressIfindexSubnetVal{
			SubnetId: subnet.Status.VNI,
		},
		ebpf.UpdateAny); err != nil {
		zap.S().Errorf("failed to update IfindexSubnet map: %v", err)
		return err
	}

	hostMAC, err := net.ParseMAC(nwep.Spec.HostMACAddress)
	if err != nil {
		return err
	}

	hostMACArray, err := HardwareAddrToUint8Array(hostMAC)
	if err != nil {
		return err
	}

	if err := m.podEgressObjs.IfindexHostMac.Update(
		&PodEgressIfindexHostMacKey{
			Ifindex: uint32(nwep.Spec.Ifindex),
		},
		&PodEgressIfindexHostMacVal{
			Mac: hostMACArray,
		},
		ebpf.UpdateAny); err != nil {
		zap.S().Errorf("failed to update IfindexHostMac map: %v", err)
		return err
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   m.podEgressObjs.TcPodEgress,
		Interface: int(nwep.Spec.Ifindex),
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
			zap.S().Debugf("TC program already attached to pod interface (ifindex: %d)", nwep.Spec.Ifindex)
		}
		if !errors.Is(err, os.ErrExist) && !errors.Is(err, syscall.EEXIST) {
			zap.S().Errorf("failed to attach TC program: %v", err)
			return err
		}
	} else {
		zap.S().Infof("attached TC program to pod interface (ifindex: %d)", nwep.Spec.Ifindex)
		m.mu.Lock()
		m.podEgressLinks[nwep.Spec.Ifindex] = l
		m.mu.Unlock()
	}

	return m.rebuildAllRouteTables(ctx)
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
		return m.rebuildAllRouteTables(ctx)
	}

	if err := m.podEgressObjs.IfindexSubnet.Delete(&PodEgressIfindexSubnetKey{
		Ifindex: uint32(nwep.Spec.Ifindex),
	}); err != nil {
		zap.S().Errorf("failed to delete from IfindexSubnet map: %v", err)
		return err
	}

	if err := m.podEgressObjs.IfindexHostMac.Delete(&PodEgressIfindexHostMacKey{
		Ifindex: uint32(nwep.Spec.Ifindex),
	}); err != nil {
		zap.S().Errorf("failed to delete from IfindexHostMac map: %v", err)
		return err
	}

	m.mu.Lock()

	if l, ok := m.podEgressLinks[nwep.Spec.Ifindex]; ok {
		l.Close()
	}
	delete(m.podEgressLinks, nwep.Spec.Ifindex)
	m.mu.Unlock()

	return m.rebuildAllRouteTables(ctx)
}

func (m *Manager) UpsertRouteTable(ctx context.Context, rt *juneauv1alpha1.RouteTable) error {
	fib, err := ebpf.NewMap(m.podEgressMapSpecs.FibInner.Copy())
	if err != nil {
		zap.S().Errorf("failed to create new FIB inner map: %v", err)
		return err
	}

	for _, route := range rt.Status.Routes {
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

		var val PodEgressFibVal
		switch route.Via.Type {
		case juneauv1alpha1.ViaConnnected:
			var subnet juneauv1alpha1.Subnet
			if err := m.client.Get(ctx, client.ObjectKey{Name: route.Subnet}, &subnet); err != nil {
				return err
			}
			if subnet.Status.VNI == 1 {
				continue
			}
			val, err = m.buildConnectedFibVal(&subnet)
			if err != nil {
				zap.S().Warnf("failed to build connected FIB route for %s: %v", route.Dst, err)
				continue
			}
		case juneauv1alpha1.ViaEndpoint:
			var subnet juneauv1alpha1.Subnet
			if err := m.client.Get(ctx, client.ObjectKey{Name: route.Subnet}, &subnet); err != nil {
				return err
			}
			if subnet.Status.VNI == 1 {
				continue
			}
			val, err = m.buildEndpointFibVal(ctx, &subnet, &route)
			if err != nil {
				zap.S().Warnf("failed to build endpoint FIB route for %s via %s: %v", route.Dst, route.Via.Endpoint, err)
				continue
			}
		case juneauv1alpha1.ViaInternetGateway:
			val, err = m.buildInternetGatewayFibVal()
			if err != nil {
				zap.S().Warnf("failed to build internet gateway FIB route for %s: %v", route.Dst, err)
				continue
			}
		default:
			zap.S().Warnf("unsupported route type %q for %s", route.Via.Type, route.Dst)
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

func (m *Manager) buildConnectedFibVal(subnet *juneauv1alpha1.Subnet) (PodEgressFibVal, error) {
	netmac, err := net.ParseMAC(subnet.Status.GatewayMAC)
	if err != nil {
		return PodEgressFibVal{}, err
	}

	mac, err := HardwareAddrToUint8Array(netmac)
	if err != nil {
		return PodEgressFibVal{}, err
	}

	return PodEgressFibVal{
		Type:     fibRouteTypeConnected,
		Dmac:     [6]uint8{},
		Smac:     mac,
		SubnetId: subnet.Status.VNI,
		Oif:      0,
	}, nil
}

func (m *Manager) buildEndpointFibVal(ctx context.Context, subnet *juneauv1alpha1.Subnet, route *juneauv1alpha1.Route) (PodEgressFibVal, error) {
	var nwep juneauv1alpha1.NetworkEndpoint
	if err := m.client.Get(ctx, client.ObjectKey{Name: route.Via.Endpoint}, &nwep); err != nil {
		return PodEgressFibVal{}, err
	}

	nextHopMAC, err := net.ParseMAC(nwep.Spec.MACAddress)
	if err != nil {
		return PodEgressFibVal{}, err
	}

	dmac, err := HardwareAddrToUint8Array(nextHopMAC)
	if err != nil {
		return PodEgressFibVal{}, err
	}

	sourceMAC, err := net.ParseMAC(subnet.Status.GatewayMAC)
	if err != nil {
		return PodEgressFibVal{}, err
	}

	smac, err := HardwareAddrToUint8Array(sourceMAC)
	if err != nil {
		return PodEgressFibVal{}, err
	}

	return PodEgressFibVal{
		Type:     fibRouteTypeEndpoint,
		Dmac:     dmac,
		Smac:     smac,
		SubnetId: subnet.Status.VNI,
		Oif:      0,
	}, nil
}

func (m *Manager) buildInternetGatewayFibVal() (PodEgressFibVal, error) {
	if m.externalGateway == nil {
		return PodEgressFibVal{}, fmt.Errorf("internet gateway info is not initialized")
	}

	smac, err := HardwareAddrToUint8Array(m.externalGateway.SourceMAC)
	if err != nil {
		return PodEgressFibVal{}, err
	}

	dmac, err := HardwareAddrToUint8Array(m.externalGateway.NextHopMAC)
	if err != nil {
		return PodEgressFibVal{}, err
	}

	return PodEgressFibVal{
		Type:     fibRouteTypeInternetGateway,
		Dmac:     dmac,
		Smac:     smac,
		SubnetId: 0,
		Oif:      uint32(m.externalGateway.Ifindex),
	}, nil
}

func resolveInternetGatewayInfo(ifindex int) (*InternetGatewayInfo, error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil, err
	}
	ifi, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return nil, err
	}

	route, err := resolveDefaultGatewayRoute(link)
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

	return &InternetGatewayInfo{
		Ifindex:    ifindex,
		SourceMAC:  link.Attrs().HardwareAddr,
		NextHopIP:  route.Gw,
		NextHopMAC: mac,
	}, nil
}

func resolveDefaultGatewayRoute(link netlink.Link) (*netlink.Route, error) {
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	for i := range routes {
		route := &routes[i]
		if route.Dst == nil && route.Gw != nil {
			return route, nil
		}
	}

	return nil, fmt.Errorf("no default route with gateway found on ifindex %d", link.Attrs().Index)
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
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}

	hwAddr, err := client.Resolve(gwAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve gateway %s MAC on %s: %w", gw, ifi.Name, err)
	}

	return hwAddr, nil
}

func (m *Manager) rebuildAllRouteTables(ctx context.Context) error {
	var routeTables juneauv1alpha1.RouteTableList
	if err := m.client.List(ctx, &routeTables); err != nil {
		return err
	}

	for i := range routeTables.Items {
		if err := m.UpsertRouteTable(ctx, &routeTables.Items[i]); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) rebuildBGPAddressPools(ctx context.Context) error {
	desired, warnings, err := m.buildDesiredBGPAddressPools(ctx)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		zap.S().Warn(warning)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for key, oldKey := range m.bgpAddressPools {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := m.podEgressObjs.BgpAddressPools.Delete(&oldKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete bgp_address_pools entry %s: %w", key, err)
		}
	}

	var one uint8 = 1
	for key, newKey := range desired {
		if oldKey, ok := m.bgpAddressPools[key]; ok && oldKey == newKey {
			continue
		}
		if err := m.podEgressObjs.BgpAddressPools.Update(&newKey, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update bgp_address_pools entry %s: %w", key, err)
		}
	}

	m.bgpAddressPools = desired
	zap.S().Infof("reconciled bgp_address_pools entries: %d", len(desired))

	return nil
}

func (m *Manager) buildDesiredBGPAddressPools(ctx context.Context) (map[string]PodEgressBgpAddressPoolsKey, []string, error) {
	var pools juneauv1alpha1.AddressPoolList
	if err := m.client.List(ctx, &pools); err != nil {
		return nil, nil, fmt.Errorf("list AddressPools: %w", err)
	}

	var advs juneauv1alpha1.BGPAdvertisementList
	if err := m.client.List(ctx, &advs); err != nil {
		return nil, nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}

	poolsByName := make(map[string]*juneauv1alpha1.AddressPool, len(pools.Items))
	for i := range pools.Items {
		pool := &pools.Items[i]
		poolsByName[pool.Name] = pool
	}

	referencedPools := make(map[string]struct{})
	for i := range advs.Items {
		adv := &advs.Items[i]
		for _, poolName := range adv.Spec.AddressPools {
			poolName = strings.TrimSpace(poolName)
			if poolName == "" {
				continue
			}
			referencedPools[poolName] = struct{}{}
		}
	}

	poolNames := make([]string, 0, len(referencedPools))
	for name := range referencedPools {
		poolNames = append(poolNames, name)
	}
	sort.Strings(poolNames)

	desired := make(map[string]PodEgressBgpAddressPoolsKey)
	var warnings []string
	for _, poolName := range poolNames {
		pool, ok := poolsByName[poolName]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("BGPAdvertisement references missing AddressPool/%s", poolName))
			continue
		}
		if pool.Spec.AdvertiseMode != juneauv1alpha1.AddressPoolAdvertiseModeBGP {
			warnings = append(warnings, fmt.Sprintf("AddressPool/%s: spec.advertiseMode=%q is not bgp", pool.Name, pool.Spec.AdvertiseMode))
			continue
		}

		for _, raw := range pool.Spec.Addresses {
			key, canonical, err := parseBGPAddressPoolPrefix(raw)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AddressPool/%s: invalid address %q: %v", pool.Name, raw, err))
				continue
			}
			desired[canonical] = key
		}
	}

	return desired, warnings, nil
}

func parseBGPAddressPoolPrefix(raw string) (PodEgressBgpAddressPoolsKey, string, error) {
	var key PodEgressBgpAddressPoolsKey

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return key, "", fmt.Errorf("empty address")
	}

	var (
		ip    net.IP
		ipnet *net.IPNet
		err   error
	)
	if strings.Contains(raw, "/") {
		ip, ipnet, err = net.ParseCIDR(raw)
		if err != nil {
			return key, "", err
		}
		ip = ip.Mask(ipnet.Mask)
		ipnet.IP = ip
	} else {
		ip = net.ParseIP(raw)
		if ip == nil {
			return key, "", fmt.Errorf("invalid IP address")
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return key, "", fmt.Errorf("IPv6 is not supported")
		}
		ip = ip4
		ipnet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return key, "", fmt.Errorf("IPv6 is not supported")
	}

	addr, err := IPv4ToLPMTrieUint32(ip4)
	if err != nil {
		return key, "", err
	}
	prefixlen, _ := ipnet.Mask.Size()

	key.Prefixlen = uint32(prefixlen)
	key.Addr = addr

	return key, ipnet.String(), nil
}

func NewManager(cl client.Client, nwepInformer cache.Informer, eipaInformer cache.Informer, addressPoolInformer cache.Informer, bgpAdvertisementInformer cache.Informer, rtInformer cache.Informer, subnetInformer cache.Informer, nodeName string, vxlanIfindex int, hostIfindex int, nodeIngressIfindex int, pinPath string, defaultGatewayMac net.HardwareAddr) *Manager {
	return &Manager{
		client:                   cl,
		nwepInformer:             nwepInformer,
		eipaInformer:             eipaInformer,
		addressPoolInformer:      addressPoolInformer,
		bgpAdvertisementInformer: bgpAdvertisementInformer,
		rtInformer:               rtInformer,
		subnetInformer:           subnetInformer,
		nodeName:                 nodeName,
		vxlanIfindex:             vxlanIfindex,
		hostIfindex:              hostIfindex,
		nodeIngressIfindex:       nodeIngressIfindex,
		pinPath:                  pinPath,
		hostMac:                  defaultGatewayMac,
		podEgressMapSpecs:        &PodEgressMapSpecs{},
		podEgressObjs:            &PodEgressObjects{},
		podEgressLinks:           make(map[int]link.Link),
		bgpAddressPools:          make(map[string]PodEgressBgpAddressPoolsKey),
		hostEgressObjs:           &HostEgressObjects{},
		vxlanIngressObjs:         &VxlanIngressObjects{},
		nodeIngressObjs:          &NodeIngressObjects{},
	}
}

func addEventHandler[T any](ctx context.Context, informer cache.Informer, upsert func(context.Context, *T) error, delete func(context.Context, *T) error, update ...func(context.Context, *T, *T) error) (toolscache.ResourceEventHandlerRegistration, error) {
	return informer.AddEventHandlerWithResyncPeriod(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			p, ok := objectAs[T](obj)
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
			oldP, ok := objectAs[T](oldObj)
			if !ok {
				return
			}
			newP, ok := objectAs[T](newObj)
			if !ok {
				return
			}
			newCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if len(update) != 0 && update[0] != nil {
				if err := update[0](newCtx, oldP, newP); err != nil {
					zap.S().Errorf("failed to update object: %v", err)
				}
				return
			}
			if err := upsert(newCtx, newP); err != nil {
				zap.S().Errorf("failed to upsert object: %v", err)
			}
		},
		DeleteFunc: func(obj any) {
			p, ok := objectAs[T](obj)
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

func objectAs[T any](obj any) (*T, bool) {
	p, ok := obj.(*T)
	if ok {
		return p, true
	}

	tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown)
	if !ok {
		return nil, false
	}

	p, ok = tombstone.Obj.(*T)
	return p, ok
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

func IPv4ToLPMTrieUint32(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %v", ip)
	}
	return binary.LittleEndian.Uint32(ip4), nil
}

// net.IPMask -> uint32 (eBPF map host-order value, e.g. /16 -> 0xffff0000)
func IPMaskToUint32(mask net.IPMask) (uint32, error) {
	if len(mask) != 4 {
		return 0, fmt.Errorf("invalid IPv4 mask length: %d", len(mask))
	}
	return binary.BigEndian.Uint32(mask), nil
}
