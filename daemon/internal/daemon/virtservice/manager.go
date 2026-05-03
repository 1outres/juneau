package virtservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/1outres/juneau/daemon/internal/daemon/virtservice/netstack"
	"github.com/1outres/juneau/daemon/internal/daemon/virtservice/packetplane"
)

// netListener is an alias for net.Listener; mirrors netipAddr and
// keeps facadeAdapter readable.
type netListener = net.Listener

// Manager owns the packet plane lifecycle (TAP, dispatcher, AF_PACKET
// sender) and exposes a Registry that virtual services bind into.
//
// Wiring it into the daemon looks like:
//
//	mgr, err := virtservice.NewManager(virtServiceMap, virtServiceFlowMap, virtservice.ManagerOptions{
//	    TAPMtu: 1450,
//	})
//	if err != nil { return err }
//	if err := mgr.Start(ctx); err != nil { return err }
//	defer mgr.Stop()
//
//	dnsService := dns.New(mgr.Registry(), ...)
//	dnsService.Start(ctx)
type Manager struct {
	opts ManagerOptions

	tap        *packetplane.TAP
	flowTable  *packetplane.FlowTable
	sender     *packetplane.Sender
	dispatcher *packetplane.Dispatcher
	netstack   *netstack.Facade
	registry   Registry
	bpfMap     *ebpf.Map

	mu       sync.Mutex
	cancel   context.CancelFunc
	dispDone chan struct{}
	started  bool
}

// ManagerOptions tunes the packet plane primitives. Pass the
// zero value for sensible defaults.
type ManagerOptions struct {
	// TAPMtu sets the TAP MTU. Should be host MTU minus VXLAN
	// overhead so DNS responses fit without fragmentation when
	// they leave the node. 0 → 1450.
	TAPMtu int
}

// NewManager assembles a Manager around the supplied BPF map handles.
// virtServiceMap and virtServiceFlowMap must be the maps loaded by the
// daemon's pod_egress program (PodEgressObjects.VirtualServiceMap and
// VirtualServiceFlowMap). Manager does not load BPF itself; the daemon
// already owns that lifecycle.
func NewManager(virtServiceMap, virtServiceFlowMap *ebpf.Map, opts ManagerOptions) (*Manager, error) {
	if virtServiceMap == nil || virtServiceFlowMap == nil {
		return nil, errors.New("virtservice: BPF maps must be non-nil")
	}
	if opts.TAPMtu == 0 {
		opts.TAPMtu = 1450
	}
	return &Manager{
		opts:      opts,
		bpfMap:    virtServiceMap,
		flowTable: packetplane.NewFlowTable(virtServiceFlowMap),
	}, nil
}

// Start brings up the TAP and AF_PACKET sender, launches the
// dispatcher, and exposes the Registry. Idempotent: calling Start
// twice returns an error.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return errors.New("virtservice: manager already started")
	}

	tap, err := packetplane.CreateTAP(m.opts.TAPMtu)
	if err != nil {
		return fmt.Errorf("create TAP: %w", err)
	}

	sender, err := packetplane.NewSender()
	if err != nil {
		_ = tap.Close()
		return fmt.Errorf("open AF_PACKET sender: %w", err)
	}

	dispatcher := packetplane.NewDispatcher(tap, m.flowTable, 0)
	ns := netstack.New(sender)

	m.tap = tap
	m.sender = sender
	m.dispatcher = dispatcher
	m.netstack = ns
	m.registry = NewRegistry(ctx, dispatcher, m.flowTable, sender, tap, m.bpfMap, &facadeAdapter{ns: ns})

	dispCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.dispDone = make(chan struct{})
	go func() {
		defer close(m.dispDone)
		if err := dispatcher.Run(dispCtx); err != nil && !errors.Is(err, context.Canceled) {
			zap.S().Errorf("virtservice: dispatcher exited with error: %v", err)
		}
	}()

	m.started = true
	zap.S().Infof("virtservice: started (TAP=%s ifindex=%d)", tap.Name(), tap.Ifindex())
	return nil
}

// Stop tears down the dispatcher, sender, TAP, and netstack. Safe to
// call before Start (no-op) and idempotent.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return nil
	}

	if m.cancel != nil {
		m.cancel()
	}
	if m.dispDone != nil {
		<-m.dispDone
	}

	var firstErr error
	if m.netstack != nil {
		if err := m.netstack.Stop(); err != nil {
			firstErr = err
		}
	}
	if m.sender != nil {
		if err := m.sender.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if m.tap != nil {
		if err := m.tap.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	m.started = false
	return firstErr
}

// facadeAdapter bridges the concrete *netstack.Facade to the
// minimal NetstackFacade interface the registry takes. Splitting
// these lets us swap a stub in unit tests without dragging gVisor
// into every test binary.
type facadeAdapter struct {
	ns *netstack.Facade
}

func (a *facadeAdapter) EnsureNIC(ctx context.Context, vpcID uint32, vip netipAddr) error {
	return a.ns.EnsureNIC(ctx, vpcID, vip)
}

func (a *facadeAdapter) RemoveVIP(vpcID uint32, vip netipAddr) error {
	return a.ns.RemoveVIP(vpcID, vip)
}

func (a *facadeAdapter) ListenTCP(vpcID uint32, vip netipAddr, port uint16) (netListener, error) {
	return a.ns.ListenTCP(vpcID, vip, port)
}

func (a *facadeAdapter) Inject(vpcID uint32, ipPacket []byte, flow packetplane.Flow) error {
	return a.ns.Inject(vpcID, ipPacket, flow)
}

// Registry returns the registry virtual services bind into. Calling
// before Start panics — services should only be created after the
// daemon has brought the dataplane up.
func (m *Manager) Registry() Registry {
	if m.registry == nil {
		panic("virtservice: Registry called before Start")
	}
	return m.registry
}

// TAPIfindex returns the kernel ifindex of the daemon's TAP device.
// Useful for diagnostic logging; control-plane code that needs the
// ifindex for BPF writes should go through the Registry instead.
func (m *Manager) TAPIfindex() int {
	if m.tap == nil {
		return 0
	}
	return m.tap.Ifindex()
}
