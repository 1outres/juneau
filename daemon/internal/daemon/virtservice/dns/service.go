package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/virtservice"
)

// Service is the per-Subnet DNS virtual service. It binds itself into
// the supplied Registry once per Subnet that has a non-empty
// Status.DNS, and rebinds when that DNS VIP / MAC changes. Owns a
// shared Resolver chain across every binding.
//
// Service is informer-driven: callers wire it as a Reconciler under
// the daemon's Runner machinery (same pattern as
// dataplane/reconciler/{subnet, arp, ...}).
type Service struct {
	client     client.Client
	registry   virtservice.Registry
	handler    *Handler
	tcpHandler *TCPHandler
	rootCtx    context.Context

	mu       sync.Mutex
	bindings map[string]subnetBinding // subnet name -> binding
}

type subnetBinding struct {
	addr          virtservice.VirtualAddr
	tcpAddr       virtservice.VirtualAddr // same VIP, proto=TCP
	tenant        virtservice.TenantID
	serviceMAC    net.HardwareAddr
	udpUnregister virtservice.Unregister
	tcpUnregister virtservice.Unregister
	tcpAcceptStop context.CancelFunc
	tcpAcceptDone chan struct{}
}

// New constructs a DNS Service over the supplied registry and resolver
// chain. rootCtx scopes accept loops the service starts on each TCP
// listener so they exit when the daemon shuts down. resolver and vpcs
// are shared between the UDP packet handler and the TCP per-connection
// handler so a single resolution policy applies across both transports.
func New(rootCtx context.Context, cl client.Client, registry virtservice.Registry, resolver Resolver, vpcs VPCResolver) *Service {
	udpH := NewHandler(resolver, vpcs)
	tcpH := NewTCPHandler(resolver, vpcs)
	return &Service{
		client:     cl,
		registry:   registry,
		handler:    udpH,
		tcpHandler: tcpH,
		rootCtx:    rootCtx,
		bindings:   map[string]subnetBinding{},
	}
}

// Name implements the Reconciler contract used by the dataplane Runner.
func (s *Service) Name() string { return "virtservice-dns" }

// Reconcile re-evaluates the DNS binding for one Subnet (key is the
// Subnet name; Subnet is cluster-scoped so namespace is empty).
func (s *Service) Reconcile(ctx context.Context, key string) error {
	_, name, err := toolscache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if name == "" {
		// Some keys arrive as "name" without a slash; fall back.
		name = key
	}

	var subnet juneauv1alpha1.Subnet
	err = s.client.Get(ctx, client.ObjectKey{Name: name}, &subnet)
	if apierrors.IsNotFound(err) {
		return s.unbindLocked(name)
	}
	if err != nil {
		return err
	}
	return s.bindOrRebind(&subnet)
}

func (s *Service) bindOrRebind(subnet *juneauv1alpha1.Subnet) error {
	desired, ok, err := s.desiredBinding(subnet)
	if err != nil {
		return err
	}

	s.mu.Lock()
	current, hadCurrent := s.bindings[subnet.Name]
	s.mu.Unlock()

	if !ok {
		if hadCurrent {
			return s.unbindLocked(subnet.Name)
		}
		return nil
	}

	if hadCurrent && bindingsEqual(current, desired) {
		return nil
	}

	// Replace: unbind old (if any) before re-registering. Do this
	// outside the snapshot lock to avoid holding it across the
	// registry call.
	if hadCurrent {
		if err := s.tearDown(current); err != nil {
			zap.S().Warnf("dns: unregister stale binding for subnet %s: %v", subnet.Name, err)
		}
		s.mu.Lock()
		delete(s.bindings, subnet.Name)
		s.mu.Unlock()
	}

	udpSpec := virtservice.ServiceSpec{
		ID:         virtservice.ServiceIDDNS,
		Tenant:     desired.tenant,
		Addr:       desired.addr,
		ServiceMAC: desired.serviceMAC,
	}
	udpUnreg, err := s.registry.RegisterUDPHandler(udpSpec, s.handler)
	if err != nil {
		return fmt.Errorf("register DNS UDP handler for subnet %s: %w", subnet.Name, err)
	}
	desired.udpUnregister = udpUnreg

	// TCP/53 mirror: same VIP + MAC + tenant, proto=TCP. The
	// gVisor netstack listener is wrapped with an accept loop that
	// dispatches each connection to TCPHandler.
	tcpSpec := virtservice.ServiceSpec{
		ID:         virtservice.ServiceIDDNS,
		Tenant:     desired.tenant,
		Addr:       desired.tcpAddr,
		ServiceMAC: desired.serviceMAC,
	}
	tcpListener, tcpUnreg, err := s.registry.ListenTCP(tcpSpec)
	if err != nil {
		// Roll back UDP so the binding stays consistent.
		_ = udpUnreg()
		return fmt.Errorf("listen DNS TCP for subnet %s: %w", subnet.Name, err)
	}
	desired.tcpUnregister = tcpUnreg

	acceptCtx, cancel := context.WithCancel(s.rootCtx)
	desired.tcpAcceptStop = cancel
	desired.tcpAcceptDone = make(chan struct{})
	go func() {
		defer close(desired.tcpAcceptDone)
		s.tcpHandler.AcceptLoop(acceptCtx, tcpListener, desired.tenant)
	}()

	s.mu.Lock()
	s.bindings[subnet.Name] = desired
	s.mu.Unlock()

	zap.S().Infof("dns: bound %s:53 udp+tcp (subnet=%s vni=%d vpc=%d)", desired.addr.IP, subnet.Name, desired.tenant.SubnetID, desired.tenant.VPCID)
	return nil
}

// desiredBinding builds the binding the registry should hold for the
// given Subnet. ok=false means "this Subnet has no virtual DNS
// service" (status.dns empty, status not ready, VPC unresolved, etc.).
func (s *Service) desiredBinding(subnet *juneauv1alpha1.Subnet) (subnetBinding, bool, error) {
	if subnet.Status.DNS == "" || subnet.Status.DNSMAC == "" || subnet.Status.VNI == 0 {
		return subnetBinding{}, false, nil
	}
	addr, err := netip.ParseAddr(subnet.Status.DNS)
	if err != nil || !addr.Is4() {
		return subnetBinding{}, false, nil
	}
	mac, err := net.ParseMAC(subnet.Status.DNSMAC)
	if err != nil {
		return subnetBinding{}, false, fmt.Errorf("parse DNSMAC: %w", err)
	}

	var vpc juneauv1alpha1.Vpc
	if err := s.client.Get(context.Background(), client.ObjectKey{Name: subnet.Spec.Vpc}, &vpc); err != nil {
		if apierrors.IsNotFound(err) {
			return subnetBinding{}, false, nil
		}
		return subnetBinding{}, false, fmt.Errorf("get vpc: %w", err)
	}
	if vpc.Status.VpcID == 0 {
		return subnetBinding{}, false, nil
	}

	return subnetBinding{
		addr: virtservice.VirtualAddr{
			IP:    addr,
			Port:  53,
			Proto: virtservice.ProtocolUDP,
		},
		tcpAddr: virtservice.VirtualAddr{
			IP:    addr,
			Port:  53,
			Proto: virtservice.ProtocolTCP,
		},
		tenant: virtservice.TenantID{
			VPCID:    vpc.Status.VpcID,
			SubnetID: subnet.Status.VNI,
		},
		serviceMAC: mac,
	}, true, nil
}

// unbindLocked removes the binding for subnetName if any. Idempotent.
func (s *Service) unbindLocked(subnetName string) error {
	s.mu.Lock()
	b, ok := s.bindings[subnetName]
	if ok {
		delete(s.bindings, subnetName)
	}
	s.mu.Unlock()
	if !ok {
		return nil
	}
	if err := s.tearDown(b); err != nil {
		return fmt.Errorf("unregister DNS binding for subnet %s: %w", subnetName, err)
	}
	zap.S().Infof("dns: unbound subnet %s", subnetName)
	return nil
}

// tearDown deregisters the UDP and TCP halves of a binding and waits
// for the TCP accept loop to drain. Errors are joined; the loop is
// always awaited so we can't leak goroutines.
func (s *Service) tearDown(b subnetBinding) error {
	var firstErr error
	if b.udpUnregister != nil {
		if err := b.udpUnregister(); err != nil {
			firstErr = err
		}
	}
	if b.tcpUnregister != nil {
		if err := b.tcpUnregister(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if b.tcpAcceptStop != nil {
		b.tcpAcceptStop()
	}
	if b.tcpAcceptDone != nil {
		<-b.tcpAcceptDone
	}
	return firstErr
}

// FanOutVpcToSubnets re-enqueues every Subnet that belongs to a Vpc
// whose .Status.VpcID or .Spec.EnableService might have changed. The
// DNS resolver caches caller-VPC identity at handler-call time so the
// only Subnet-level state to recompute is "has this Subnet's owning
// VPC come into existence yet?" — answered by re-running Reconcile.
func (s *Service) FanOutVpcToSubnets(obj any) []string {
	vpc, ok := obj.(*juneauv1alpha1.Vpc)
	if !ok {
		return nil
	}
	var list juneauv1alpha1.SubnetList
	if err := s.client.List(context.Background(), &list, client.MatchingFields{"spec.vpc": vpc.Name}); err != nil {
		zap.S().Warnf("dns: list subnets for vpc fan-out: %v", err)
		return nil
	}
	out := make([]string, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, list.Items[i].Name)
	}
	return out
}

// Stop unregisters every active binding. Useful when the daemon is
// shutting down ahead of registry teardown.
func (s *Service) Stop() error {
	s.mu.Lock()
	names := make([]string, 0, len(s.bindings))
	for name := range s.bindings {
		names = append(names, name)
	}
	s.mu.Unlock()
	var firstErr error
	for _, name := range names {
		if err := s.unbindLocked(name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func bindingsEqual(a, b subnetBinding) bool {
	if a.addr != b.addr {
		return false
	}
	if a.tcpAddr != b.tcpAddr {
		return false
	}
	if a.tenant != b.tenant {
		return false
	}
	if !macsEqual(a.serviceMAC, b.serviceMAC) {
		return false
	}
	return true
}

func macsEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
