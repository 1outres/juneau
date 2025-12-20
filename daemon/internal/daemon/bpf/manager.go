package bpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
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

	nodeName          string
	defaultGatewayMac net.HardwareAddr

	podEgressObjs  *PodEgressObjects
	podEgressLinks map[int]link.Link
}

func (m *Manager) Start(ctx context.Context) error {
	if err := os.MkdirAll("/sys/fs/bpf/juneau", 0755); err != nil {
		zap.S().Errorf("failed to create BPF pin path: %v", err)
		return fmt.Errorf("failed to create BPF pin path: %w", err)
	}

	if err := LoadPodEgressObjects(m.podEgressObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/juneau",
		},
	}); err != nil {
		zap.S().Errorf("failed to load pod egress objects: %v", err)
		return err
	}

	h, err := addEventHandler(ctx, m.nwepInformer, m.UpsertNetworkEndpoint, m.DeleteNetworkEndpoint)
	if err != nil {
		zap.S().Errorf("failed to add event handler for NetworkEndpoint: %v", err)
	}
	m.nwepHandler = h

	return err
}

func (m *Manager) Stop() error {
	for _, l := range m.podEgressLinks {
		l.Close()
	}

	m.podEgressObjs.Close()

	m.nwepInformer.RemoveEventHandler(m.nwepHandler)

	return nil
}

func (m *Manager) UpsertNetworkEndpoint(ctx context.Context, nwep *juneauv1alpha1.NetworkEndpoint) error {
	if nwep.Spec.NodeName != m.nodeName {
		return nil
	}

	zap.S().Infof("UpsertNetworkEndpoint called for %s/%s", nwep.Namespace, nwep.Name)

	var subnet juneauv1alpha1.Subnet
	if err := m.client.Get(ctx, client.ObjectKey{Name: nwep.Spec.Subnet}, &subnet); err != nil {
		return err
	}

	var netgwmac net.HardwareAddr
	if subnet.Status.VNI == 1 {
		netgwmac = m.defaultGatewayMac
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

	ip := net.ParseIP(subnet.Status.Gateway)
	if ip == nil {
		return fmt.Errorf("failed to parse gateway IP: %s", subnet.Status.Gateway)
	}

	gwaddr, err := IPv4ToUint32(ip)
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
		zap.S().Errorf("failed to attach TC program: %v", err)
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.podEgressLinks[nwep.Spec.Ifindex] = l

	return nil
}

func (m *Manager) DeleteNetworkEndpoint(ctx context.Context, nwep *juneauv1alpha1.NetworkEndpoint) error {
	if nwep.Spec.NodeName != m.nodeName {
		return nil
	}

	zap.S().Infof("DeleteNetworkEndpoint called for %s/%s", nwep.Namespace, nwep.Name)

	if err := m.podEgressObjs.IfindexSubnet.Delete(&PodEgressIfindexSubnetKey{
		Ifindex: uint32(nwep.Spec.Ifindex),
	}); err != nil {
		zap.S().Errorf("failed to delete from IfindexSubnet map: %v", err)
		return err
	}

	if l, ok := m.podEgressLinks[nwep.Spec.Ifindex]; ok {
		l.Close()
	}
	delete(m.podEgressLinks, nwep.Spec.Ifindex)

	return nil
}

func NewManager(cl client.Client, nwepInformer cache.Informer, nodeName string, defaultGatewayMac net.HardwareAddr) *Manager {
	return &Manager{
		client:            cl,
		nwepInformer:      nwepInformer,
		nodeName:          nodeName,
		defaultGatewayMac: defaultGatewayMac,
		podEgressObjs:     &PodEgressObjects{},
		podEgressLinks:    make(map[int]link.Link),
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
