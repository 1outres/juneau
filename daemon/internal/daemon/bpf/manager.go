package bpf

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	toolscache "k8s.io/client-go/tools/cache"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"

	"github.com/cilium/ebpf"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager struct {
	mu sync.Mutex

	client       client.Client
	nwepInformer cache.Informer

	nodeName          string
	defaultGatewayMac net.HardwareAddr

	podEgressObjs *PodEgressObjects
}

func (m *Manager) Init() error {
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

	err := addEventHandler(m.nwepInformer, m.UpsertNetworkEndpoint, m.DeleteNetworkEndpoint)

	return err
}

func (m *Manager) UpsertNetworkEndpoint(subnet *juneauv1alpha1.NetworkEndpoint) error {
	zap.S().Infof("UpsertNetworkEndpoint called for %s/%s", subnet.Namespace, subnet.Name)

	return nil
}

func (m *Manager) DeleteNetworkEndpoint(subnet *juneauv1alpha1.NetworkEndpoint) error {
	zap.S().Infof("DeleteNetworkEndpoint called for %s/%s", subnet.Namespace, subnet.Name)
	return nil
}

func NewManager(cl client.Client, nwepInformer cache.Informer, nodeName string, defaultGatewayMac net.HardwareAddr) *Manager {
	return &Manager{
		client:            cl,
		nwepInformer:      nwepInformer,
		nodeName:          nodeName,
		defaultGatewayMac: defaultGatewayMac,
		podEgressObjs:     &PodEgressObjects{},
	}
}

func addEventHandler[T any](informer cache.Informer, upsert func(obj *T) error, delete func(obj *T) error) error {
	_, err := informer.AddEventHandlerWithResyncPeriod(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			p, ok := obj.(*T)
			if !ok {
				return
			}
			upsert(p)
		},
		UpdateFunc: func(oldObj, newObj any) {
			p, ok := newObj.(*T)
			if !ok {
				return
			}
			upsert(p)
		},
		DeleteFunc: func(obj any) {
			p, ok := obj.(*T)
			if !ok {
				return
			}
			delete(p)
		},
	}, 15*time.Minute)

	return err
}
