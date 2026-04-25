package dataplane

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/runner"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/link"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler"
)

// Manager wires up every eBPF program, reconciler, and TC link attacher
// that makes up the dataplane. Its sole responsibility is lifecycle:
// resolve runtime inputs, load programs, start reconcilers, tear down on
// Stop. All map-level reconciliation lives in package reconciler.
type Manager struct {
	mu sync.Mutex

	client                   client.Client
	nwepInformer             cache.Informer
	eipaInformer             cache.Informer
	addressPoolInformer      cache.Informer
	bgpAdvertisementInformer cache.Informer
	subnetInformer           cache.Informer
	rtInformer               cache.Informer
	vpcInformer              cache.Informer
	serviceInformer          cache.Informer
	endpointSliceInformer    cache.Informer

	subnetRunner      *runner.Runner
	arpRunner         *runner.Runner
	fdbRunner         *runner.Runner
	podIfaceRunner    *runner.Runner
	podAttacherRunner *runner.Runner
	fibRunner         *runner.Runner
	natRunner         *runner.Runner
	bgpPoolRunner     *runner.Runner
	serviceRunner     *runner.Runner

	podAttacher *link.PodAttacher
	fib         *reconciler.Fib

	nodeName           string
	vxlanIfindex       int
	hostIfindex        int
	nodeIngressIfindex int
	pinPath            string
	hostMac            net.HardwareAddr

	podEgress    *program.PodEgress
	podIngress   *program.PodIngress
	hostEgress   *program.HostEgress
	vxlanIngress *program.VxlanIngress
	nodeIngress  *program.NodeIngress
}

func (m *Manager) Start(ctx context.Context) error {
	if err := os.RemoveAll(m.pinPath); err != nil {
		return fmt.Errorf("failed to remove BPF pin path: %w", err)
	}
	if err := os.MkdirAll(m.pinPath, 0755); err != nil {
		return fmt.Errorf("failed to create BPF pin path: %w", err)
	}

	hostMac, err := convert.HardwareAddrToUint8Array(m.hostMac)
	if err != nil {
		return err
	}

	m.podEgress, err = program.NewPodEgress(m.pinPath, m.hostIfindex, hostMac)
	if err != nil {
		return fmt.Errorf("load pod egress program: %w", err)
	}

	m.podIngress, err = program.NewPodIngress(m.pinPath)
	if err != nil {
		return fmt.Errorf("load pod ingress program: %w", err)
	}

	m.hostEgress, err = program.NewHostEgress(m.pinPath, m.hostIfindex, m.vxlanIfindex)
	if err != nil {
		return fmt.Errorf("load host egress program: %w", err)
	}
	zap.S().Infof("attached TC program to host interface (ifindex: %d)", m.hostIfindex)

	m.vxlanIngress, err = program.NewVxlanIngress(m.pinPath, m.vxlanIfindex)
	if err != nil {
		return fmt.Errorf("load vxlan ingress program: %w", err)
	}
	zap.S().Infof("attached TC program to vxlan interface (ifindex: %d)", m.vxlanIfindex)

	m.nodeIngress, err = program.NewNodeIngress(m.pinPath, m.nodeIngressIfindex)
	if err != nil {
		return fmt.Errorf("load node ingress program: %w", err)
	}
	zap.S().Infof("attached TC program to node ingress interface (ifindex: %d)", m.nodeIngressIfindex)

	if err := m.startReconcilers(ctx); err != nil {
		return err
	}
	return nil
}

func (m *Manager) startReconcilers(ctx context.Context) error {
	subnetReconciler := reconciler.NewSubnet(m.client, m.hostEgress)
	m.subnetRunner = runner.New(subnetReconciler)
	if err := m.subnetRunner.Watch(m.subnetInformer, runner.MetaNamespaceKey); err != nil {
		return fmt.Errorf("watch Subnet: %w", err)
	}
	if m.vpcInformer != nil {
		if err := m.subnetRunner.WatchFanOut(m.vpcInformer, subnetReconciler.FanOutVpcToSubnets); err != nil {
			return fmt.Errorf("watch Vpc (subnet fan-out): %w", err)
		}
	}
	m.subnetRunner.Start(ctx, 1)

	m.arpRunner = runner.New(reconciler.NewArp(m.client, m.hostEgress))
	if err := m.arpRunner.Watch(m.nwepInformer, runner.MetaNamespaceKey); err != nil {
		return fmt.Errorf("watch NWEP (arp): %w", err)
	}
	m.arpRunner.Start(ctx, 1)

	m.fdbRunner = runner.New(reconciler.NewFdb(m.client, m.hostEgress, m.vxlanIngress, m.nodeName))
	if err := m.fdbRunner.Watch(m.nwepInformer, runner.MetaNamespaceKey); err != nil {
		return fmt.Errorf("watch NWEP (fdb): %w", err)
	}
	m.fdbRunner.Start(ctx, 1)

	m.podIfaceRunner = runner.New(reconciler.NewPodIface(m.client, m.podEgress, m.nodeName))
	if err := m.podIfaceRunner.Watch(m.nwepInformer, runner.MetaNamespaceKey); err != nil {
		return fmt.Errorf("watch NWEP (pod-iface): %w", err)
	}
	m.podIfaceRunner.Start(ctx, 1)

	m.podAttacher = link.NewPodAttacher(m.client, m.podEgress, m.podIngress, m.nodeName)
	m.podAttacherRunner = runner.New(m.podAttacher)
	if err := m.podAttacherRunner.Watch(m.nwepInformer, runner.MetaNamespaceKey); err != nil {
		return fmt.Errorf("watch NWEP (pod-attacher): %w", err)
	}
	m.podAttacherRunner.Start(ctx, 1)

	m.fib = reconciler.NewFib(m.client, m.podEgress)
	m.fibRunner = runner.New(m.fib)
	if err := m.fibRunner.Watch(m.rtInformer, runner.MetaNamespaceKey); err != nil {
		return fmt.Errorf("watch RouteTable: %w", err)
	}
	if err := m.fibRunner.WatchFanOut(m.subnetInformer, m.fib.FanOutAllRouteTables); err != nil {
		return fmt.Errorf("watch Subnet (fib fan-out): %w", err)
	}
	if err := m.fibRunner.WatchFanOut(m.nwepInformer, m.fib.FanOutAllRouteTables); err != nil {
		return fmt.Errorf("watch NWEP (fib fan-out): %w", err)
	}
	m.fibRunner.Start(ctx, 1)

	m.natRunner = runner.New(reconciler.NewNat(m.client, m.podEgress, m.nodeName))
	if err := m.natRunner.Watch(m.eipaInformer, runner.MetaNamespaceKey); err != nil {
		return fmt.Errorf("watch EIPA: %w", err)
	}
	m.natRunner.Start(ctx, 1)

	m.bgpPoolRunner = runner.New(reconciler.NewBgpPool(m.client, m.podEgress))
	bgpPoolKey := runner.ConstantKey(runner.SingletonKey)
	if err := m.bgpPoolRunner.Watch(m.addressPoolInformer, bgpPoolKey); err != nil {
		return fmt.Errorf("watch AddressPool: %w", err)
	}
	if err := m.bgpPoolRunner.Watch(m.bgpAdvertisementInformer, bgpPoolKey); err != nil {
		return fmt.Errorf("watch BGPAdvertisement: %w", err)
	}
	m.bgpPoolRunner.Enqueue(runner.SingletonKey)
	m.bgpPoolRunner.Start(ctx, 1)

	if m.serviceInformer != nil && m.endpointSliceInformer != nil {
		svc := reconciler.NewService(m.client, m.podEgress)
		m.serviceRunner = runner.New(svc)
		if err := m.serviceRunner.Watch(m.serviceInformer, runner.MetaNamespaceKey); err != nil {
			return fmt.Errorf("watch Service: %w", err)
		}
		if err := m.serviceRunner.WatchFanOut(m.endpointSliceInformer, svc.FanOutEndpointSliceToService); err != nil {
			return fmt.Errorf("watch EndpointSlice (service fan-out): %w", err)
		}
		// Subnet changes can shift which Pods are valid backends (a Pod
		// may move into/out of the Service's owning VPC).
		if err := m.serviceRunner.WatchFanOut(m.subnetInformer, svc.FanOutAllServices); err != nil {
			return fmt.Errorf("watch Subnet (service fan-out): %w", err)
		}
		// Vpc.spec.enableService toggle and VpcID allocation propagate
		// to every Service this VPC owns.
		if m.vpcInformer != nil {
			if err := m.serviceRunner.WatchFanOut(m.vpcInformer, svc.FanOutAllServices); err != nil {
				return fmt.Errorf("watch Vpc (service fan-out): %w", err)
			}
		}
		m.serviceRunner.Start(ctx, 1)
	}

	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.podAttacher != nil {
		if err := m.podAttacher.CloseAll(); err != nil {
			return err
		}
	}
	if m.fib != nil {
		if err := m.fib.CloseAll(); err != nil {
			return err
		}
	}

	if m.podEgress != nil {
		if err := m.podEgress.Close(); err != nil {
			return err
		}
	}
	if m.podIngress != nil {
		if err := m.podIngress.Close(); err != nil {
			return err
		}
	}

	runners := []*runner.Runner{
		m.subnetRunner,
		m.arpRunner,
		m.fdbRunner,
		m.podIfaceRunner,
		m.podAttacherRunner,
		m.fibRunner,
		m.natRunner,
		m.bgpPoolRunner,
		m.serviceRunner,
	}
	for _, rn := range runners {
		if rn == nil {
			continue
		}
		if err := rn.Stop(); err != nil {
			return err
		}
	}

	if m.hostEgress != nil {
		if err := m.hostEgress.Close(); err != nil {
			return err
		}
	}
	if m.vxlanIngress != nil {
		if err := m.vxlanIngress.Close(); err != nil {
			return err
		}
	}
	if m.nodeIngress != nil {
		if err := m.nodeIngress.Close(); err != nil {
			return err
		}
	}

	return nil
}

// NewManager constructs a Manager. The caller is responsible for driving
// Start and Stop around the rest of the daemon's lifecycle.
func NewManager(
	cl client.Client,
	nwepInformer cache.Informer,
	eipaInformer cache.Informer,
	addressPoolInformer cache.Informer,
	bgpAdvertisementInformer cache.Informer,
	rtInformer cache.Informer,
	subnetInformer cache.Informer,
	vpcInformer cache.Informer,
	serviceInformer cache.Informer,
	endpointSliceInformer cache.Informer,
	nodeName string,
	vxlanIfindex int,
	hostIfindex int,
	nodeIngressIfindex int,
	pinPath string,
	defaultGatewayMac net.HardwareAddr,
) *Manager {
	return &Manager{
		client:                   cl,
		nwepInformer:             nwepInformer,
		eipaInformer:             eipaInformer,
		addressPoolInformer:      addressPoolInformer,
		bgpAdvertisementInformer: bgpAdvertisementInformer,
		rtInformer:               rtInformer,
		subnetInformer:           subnetInformer,
		vpcInformer:              vpcInformer,
		serviceInformer:          serviceInformer,
		endpointSliceInformer:    endpointSliceInformer,
		nodeName:                 nodeName,
		vxlanIfindex:             vxlanIfindex,
		hostIfindex:              hostIfindex,
		nodeIngressIfindex:       nodeIngressIfindex,
		pinPath:                  pinPath,
		hostMac:                  defaultGatewayMac,
	}
}
