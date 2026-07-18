package dataplane

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/link"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/mapinventory"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/policy"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler"
	servicereconciler "github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/service"
	servicelbreconciler "github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/serviceloadbalancer"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/trace"
	"github.com/1outres/juneau/daemon/internal/daemon/runner"
)

// TraceGCInterval bounds how stale an expired session may stay in BPF
// state. Sessions live in the seconds-to-minutes range; sweeping
// every second keeps map pressure tight without becoming a hot loop.
const TraceGCInterval = time.Second

// Manager wires up every eBPF program, reconciler, and TC link attacher
// that makes up the dataplane. Its sole responsibility is lifecycle:
// resolve runtime inputs, load programs, start reconcilers, tear down on
// Stop. All map-level reconciliation lives in package reconciler.
type Manager struct {
	mu sync.Mutex

	client                            client.Client
	nwepInformer                      cache.Informer
	eipaInformer                      cache.Informer
	addressPoolInformer               cache.Informer
	bgpAdvertisementInformer          cache.Informer
	subnetInformer                    cache.Informer
	rtInformer                        cache.Informer
	vpcInformer                       cache.Informer
	serviceInformer                   cache.Informer
	endpointSliceInformer             cache.Informer
	externalNetworkAttachmentInformer cache.Informer
	natGatewayInformer                cache.Informer
	serviceNATAttachmentInformer      cache.Informer
	networkInterfaceInformer          cache.Informer
	securityGroupInformer             cache.Informer
	networkACLInformer                cache.Informer
	nodeInformer                      cache.Informer

	subnetRunner        *runner.Runner
	arpRunner           *runner.Runner
	fdbRunner           *runner.Runner
	podIfaceRunner      *runner.Runner
	podAttacherRunner   *runner.Runner
	fibRunner           *runner.Runner
	natRunner           *runner.Runner
	bgpPoolRunner       *runner.Runner
	serviceRunner       *runner.Runner
	naptRunner          *runner.Runner
	serviceNATRunner    *runner.Runner
	sgRunner            *runner.Runner
	sgMembershipRunner  *runner.Runner
	aclRunner           *runner.Runner
	traceRunner         *runner.Runner
	nodeUnderlayRunner  *runner.Runner

	serviceLoadBalancerInformer cache.Informer
	serviceLBProgrammer         servicelbreconciler.Programmer
	serviceLBRunner             *runner.Runner

	traceSessionInformer cache.Informer
	traceStore           *trace.Store
	traceBus             *trace.Bus
	traceReader          *trace.Reader
	traceCancel          context.CancelFunc
	traceDone            chan struct{}

	sgStore         *policy.SGStore
	aclStore        *policy.ACLStore
	membershipStore *policy.MembershipStore

	napt *reconciler.Napt

	juNodeUnderlayIP net.IP

	conntrackCancel context.CancelFunc
	conntrackDone   chan struct{}

	affinityGCCancel context.CancelFunc
	affinityGCDone   chan struct{}

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
	vxlanIngress *program.VxlanIngress
	nodeIngress  *program.NodeIngress

	mapInventory *mapinventory.Inventory
}

func (m *Manager) Start(ctx context.Context) error {
	if err := os.RemoveAll(m.pinPath); err != nil {
		return fmt.Errorf("failed to remove BPF pin path: %w", err)
	}
	if err := os.MkdirAll(m.pinPath, 0755); err != nil {
		return fmt.Errorf("failed to create BPF pin path: %w", err)
	}

	var err error
	// host_underlay's slot is consumed by BPF as __be32 (compared to
	// iph->daddr in node_ingress, used as the saddr rewrite source in
	// pod_egress). Encode accordingly.
	var nodeUnderlayBE uint32
	if m.juNodeUnderlayIP != nil {
		nodeUnderlayBE, err = convert.IPv4ToBPFNetworkOrder(m.juNodeUnderlayIP)
		if err != nil {
			return fmt.Errorf("convert juneau_node underlay IP: %w", err)
		}
	}

	m.podEgress, err = program.NewPodEgress(m.pinPath, nodeUnderlayBE)
	if err != nil {
		return fmt.Errorf("load pod egress program: %w", err)
	}

	m.podIngress, err = program.NewPodIngress(m.pinPath)
	if err != nil {
		return fmt.Errorf("load pod ingress program: %w", err)
	}

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

	// Build the BPF map inventory used by the debug RPCs. All maps
	// are LIBBPF_PIN_BY_NAME so the pod_egress handles transitively
	// cover every map exported by the data plane.
	m.mapInventory = mapinventory.NewInventory()
	if err := mapinventory.RegisterPodEgress(m.mapInventory, m.podEgress); err != nil {
		return fmt.Errorf("register BPF map inventory: %w", err)
	}

	if err := m.startReconcilers(ctx); err != nil {
		return err
	}
	return nil
}

// MapInventory returns the BPF map descriptor registry. nil before
// Start has populated it. Consumed by the debug gRPC server.
func (m *Manager) MapInventory() *mapinventory.Inventory { return m.mapInventory }

func (m *Manager) startReconcilers(ctx context.Context) error {
	subnetReconciler := reconciler.NewSubnet(m.client, m.podEgress)
	m.subnetRunner = runner.New(subnetReconciler)
	if err := m.subnetRunner.Watch(m.subnetInformer, runner.MetaNamespaceKey); err != nil {
		return fmt.Errorf("watch Subnet: %w", err)
	}
	if m.vpcInformer != nil {
		if err := m.subnetRunner.WatchFanOut(m.vpcInformer, subnetReconciler.FanOutVpcToSubnets); err != nil {
			return fmt.Errorf("watch Vpc (subnet fan-out): %w", err)
		}
	}
	if m.rtInformer != nil {
		if err := m.subnetRunner.WatchFanOut(m.rtInformer, subnetReconciler.FanOutRouteTableToSubnets); err != nil {
			return fmt.Errorf("watch RouteTable (subnet fan-out): %w", err)
		}
	}
	if m.networkACLInformer != nil {
		// NetworkACL.status.aclID changes (initial allocation) and
		// rulesetVersion bumps must propagate into subnet_map.acl_id
		// without waiting for an unrelated Subnet event.
		if err := m.subnetRunner.WatchFanOut(m.networkACLInformer, subnetReconciler.FanOutNetworkACLToSubnets); err != nil {
			return fmt.Errorf("watch NetworkACL (subnet fan-out): %w", err)
		}
	}
	m.subnetRunner.Start(ctx, 1)

	m.arpRunner = runner.New(reconciler.NewArp(m.client, m.podEgress))
	if err := m.arpRunner.Watch(m.nwepInformer, runner.MetaNamespaceKey); err != nil {
		return fmt.Errorf("watch NWEP (arp): %w", err)
	}
	m.arpRunner.Start(ctx, 1)

	m.fdbRunner = runner.New(reconciler.NewFdb(m.client, m.podEgress, m.vxlanIngress, m.nodeName))
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

	// NodeUnderlay: cluster-wide Node.status.addresses[InternalIP] →
	// node_underlays map. Required so pod_egress can hand back the
	// reply leg of any Service flow whose forward DNAT was performed
	// by an external in-kernel kube-proxy iptables ruleset. Runs
	// unconditionally: even in a kube-proxy-free cluster the map is
	// harmless — pod → node underlay IP is not a normal juneau
	// pod-networking pattern and delegating those to the kernel is
	// what we want.
	if m.nodeInformer != nil {
		m.nodeUnderlayRunner = runner.New(reconciler.NewNodeUnderlay(m.client, m.podEgress))
		if err := m.nodeUnderlayRunner.Watch(m.nodeInformer, runner.MetaNamespaceKey); err != nil {
			return fmt.Errorf("watch Node (node-underlay): %w", err)
		}
		m.nodeUnderlayRunner.Start(ctx, 1)
	}

	if m.externalNetworkAttachmentInformer != nil {
		m.napt = reconciler.NewNapt(m.client, m.podEgress, m.nodeName)
		m.naptRunner = runner.New(m.napt)
		if err := m.naptRunner.Watch(m.externalNetworkAttachmentInformer, runner.MetaNamespaceKey); err != nil {
			return fmt.Errorf("watch ExternalNetworkAttachment: %w", err)
		}
		if m.natGatewayInformer != nil {
			if err := m.naptRunner.WatchFanOut(m.natGatewayInformer, m.napt.FanOutAllAttachments); err != nil {
				return fmt.Errorf("watch NATGateway (napt fan-out): %w", err)
			}
		}
		m.naptRunner.Start(ctx, 1)
	}

	if m.serviceNATAttachmentInformer != nil {
		serviceNAT := reconciler.NewServiceNAT(m.client, m.podEgress, m.nodeName)
		m.serviceNATRunner = runner.New(serviceNAT)
		if err := m.serviceNATRunner.Watch(m.serviceNATAttachmentInformer, runner.MetaNamespaceKey); err != nil {
			return fmt.Errorf("watch ServiceNATAttachment: %w", err)
		}
		// Vpc.Status.VpcID is the per-Node SNAT IP map key. A change
		// (allocation, deletion, status backfill) must re-fire the
		// reconciler for every attachment that references the Vpc so
		// the BPF entry tracks the live identity.
		if m.vpcInformer != nil {
			if err := m.serviceNATRunner.WatchFanOut(m.vpcInformer, serviceNAT.FanOutVpcToAttachments); err != nil {
				return fmt.Errorf("watch Vpc (service NAT fan-out): %w", err)
			}
		}
		m.serviceNATRunner.Start(ctx, 1)
	}

	// SecurityGroup rule projection. Populates sg_rule_table + sg_meta_map
	// from SecurityGroup CRDs. Runs even when networkInterfaceInformer is
	// absent (e.g. unit-test harnesses) because SG metadata is independent
	// of NetworkInterface bindings.
	if m.securityGroupInformer != nil {
		m.sgStore = policy.NewSGStore(
			m.podEgress.Objs.SgMetaMap,
			m.podEgress.Objs.SgRuleTable,
			m.podEgress.MapSpecs.SgRulesInnerProto,
		)
		sg := reconciler.NewSecurityGroup(m.client, m.sgStore)
		m.sgRunner = runner.New(sg)
		if err := m.sgRunner.Watch(m.securityGroupInformer, runner.MetaNamespaceKey); err != nil {
			return fmt.Errorf("watch SecurityGroup: %w", err)
		}
		// Peer-cross-references: a change to one SG re-evaluates every
		// other SG in the same Vpc so newly-resolvable peer references
		// propagate.
		if err := m.sgRunner.WatchFanOut(m.securityGroupInformer, sg.FanOutVpcPeers); err != nil {
			return fmt.Errorf("watch SecurityGroup (peer fan-out): %w", err)
		}
		m.sgRunner.Start(ctx, 1)
	}

	// NetworkACL rule projection. Populates acl_rule_table +
	// acl_meta_map from NetworkACL CRDs. Independent of SG: ACLs
	// attach to Subnets, not Pods, so we do not need
	// networkInterfaceInformer here.
	if m.networkACLInformer != nil {
		m.aclStore = policy.NewACLStore(
			m.podEgress.Objs.AclMetaMap,
			m.podEgress.Objs.AclRuleTable,
			m.podEgress.MapSpecs.AclRulesInnerProto,
		)
		acl := reconciler.NewNetworkACL(m.client, m.aclStore)
		m.aclRunner = runner.New(acl)
		if err := m.aclRunner.Watch(m.networkACLInformer, runner.MetaNamespaceKey); err != nil {
			return fmt.Errorf("watch NetworkACL: %w", err)
		}
		m.aclRunner.Start(ctx, 1)
	}

	// SG membership table — (vpc_id, ipv4) → SG list — built from
	// NetworkInterface.status.effectiveSecurityGroups. Cluster-wide so
	// the data plane can resolve both self and peer.
	if m.networkInterfaceInformer != nil {
		m.membershipStore = policy.NewMembershipStore(m.podEgress.Objs.SgMembershipMap)
		mem := reconciler.NewSGMembership(m.client, m.membershipStore)
		m.sgMembershipRunner = runner.New(mem)
		if err := m.sgMembershipRunner.Watch(m.networkInterfaceInformer, runner.MetaNamespaceKey); err != nil {
			return fmt.Errorf("watch NetworkInterface (sg-membership): %w", err)
		}
		if m.subnetInformer != nil {
			if err := m.sgMembershipRunner.WatchFanOut(m.subnetInformer, mem.FanOutSubnetToInterfaces); err != nil {
				return fmt.Errorf("watch Subnet (sg-membership fan-out): %w", err)
			}
		}
		if m.vpcInformer != nil {
			if err := m.sgMembershipRunner.WatchFanOut(m.vpcInformer, mem.FanOutVpcToInterfaces); err != nil {
				return fmt.Errorf("watch Vpc (sg-membership fan-out): %w", err)
			}
		}
		if m.securityGroupInformer != nil {
			if err := m.sgMembershipRunner.WatchFanOut(m.securityGroupInformer, mem.FanOutSGToInterfaces); err != nil {
				return fmt.Errorf("watch SecurityGroup (sg-membership fan-out): %w", err)
			}
		}
		m.sgMembershipRunner.Start(ctx, 1)
	}

	if m.serviceInformer != nil && m.endpointSliceInformer != nil {
		svc := servicereconciler.NewReconciler(m.client, m.podEgress, m.juNodeUnderlayIP, m.nodeName)
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
		// Vpc.spec.service config flips and VpcID allocation propagate
		// to every Service this VPC owns.
		if m.vpcInformer != nil {
			if err := m.serviceRunner.WatchFanOut(m.vpcInformer, svc.FanOutAllServices); err != nil {
				return fmt.Errorf("watch Vpc (service fan-out): %w", err)
			}
		}
		m.serviceRunner.Start(ctx, 1)
	}

	if m.serviceLoadBalancerInformer != nil {
		// Phase 7 wires the BPF-backed Programmer in production. The
		// in-memory Programmer remains useful for tests; callers that
		// want it can pre-populate m.serviceLBProgrammer before Start.
		if m.serviceLBProgrammer == nil {
			m.serviceLBProgrammer = servicelbreconciler.NewBPFProgrammer(
				m.podEgress.Objs.LbServiceMap,
				m.podEgress.Objs.LbBackendMap,
			)
		}
		lb := servicelbreconciler.NewReconciler(m.client, m.serviceLBProgrammer, m.nodeName)
		m.serviceLBRunner = runner.New(lb)
		if err := m.serviceLBRunner.Watch(m.serviceLoadBalancerInformer, runner.MetaNamespaceKey); err != nil {
			return fmt.Errorf("watch ServiceLoadBalancer: %w", err)
		}
		if m.serviceInformer != nil {
			if err := m.serviceLBRunner.WatchFanOut(m.serviceInformer, lb.FanOutServiceToSLB); err != nil {
				return fmt.Errorf("watch Service (LB fan-out): %w", err)
			}
		}
		if m.endpointSliceInformer != nil {
			if err := m.serviceLBRunner.WatchFanOut(m.endpointSliceInformer, lb.FanOutEndpointSliceToSLB); err != nil {
				return fmt.Errorf("watch EndpointSlice (LB fan-out): %w", err)
			}
		}
		if m.networkInterfaceInformer != nil {
			// Pod NetworkInterface allocation transitions a backend
			// from "non-Juneau, drop" to "Juneau, advertise"; we
			// must re-evaluate every known SLB on those events.
			if err := m.serviceLBRunner.WatchFanOut(m.networkInterfaceInformer, lb.FanOutNetworkInterfaceToSLBs); err != nil {
				return fmt.Errorf("watch NetworkInterface (LB fan-out): %w", err)
			}
		}
		m.serviceLBRunner.Start(ctx, 1)
	}

	m.startConntrackGC(ctx)
	m.startAffinityGC(ctx)

	if err := m.startTrace(ctx); err != nil {
		return fmt.Errorf("start trace plane: %w", err)
	}

	return nil
}

// startTrace wires the trace.Store, ringbuf reader, GC loop and the
// TraceSession reconciler. The trace plane is purely additive — when
// no TraceSession CRDs exist the store sits with active=0 and BPF
// programs short-circuit on the hot path.
func (m *Manager) startTrace(ctx context.Context) error {
	m.traceStore = trace.NewStore(
		m.podEgress.Objs.TraceActive,
		m.podEgress.Objs.TraceConfigMap,
		m.podEgress.Objs.TraceTupleMap,
	)
	m.traceBus = trace.NewBus()

	rd, err := trace.NewReader(m.podEgress.Objs.TraceEvents, m.traceBus)
	if err != nil {
		return fmt.Errorf("create trace ringbuf reader: %w", err)
	}
	m.traceReader = rd

	traceCtx, cancel := context.WithCancel(ctx)
	m.traceCancel = cancel
	m.traceDone = make(chan struct{})
	go func() {
		defer close(m.traceDone)
		if err := rd.Run(traceCtx); err != nil {
			zap.S().Warnw("trace: ringbuf reader exited with error", "err", err)
		}
	}()

	go m.traceGCLoop(traceCtx)

	if m.traceSessionInformer != nil {
		rec := trace.NewReconciler(m.client, m.traceStore, m.nodeName)
		m.traceRunner = runner.New(rec)
		if err := m.traceRunner.Watch(m.traceSessionInformer, runner.MetaNamespaceKey); err != nil {
			return fmt.Errorf("watch TraceSession: %w", err)
		}
		m.traceRunner.Start(ctx, 1)
	}
	return nil
}

func (m *Manager) traceGCLoop(ctx context.Context) {
	t := time.NewTicker(TraceGCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.traceStore.GC(); err != nil {
				zap.S().Warnw("trace: GC failed", "err", err)
			}
		}
	}
}

// TraceBus exposes the in-process event bus for the debug gRPC server.
// Returns nil before Start has run.
func (m *Manager) TraceBus() *trace.Bus { return m.traceBus }

// TraceStore exposes the BPF map programmer for debug RPCs that
// install learned tuples on remote nodes.
func (m *Manager) TraceStore() *trace.Store { return m.traceStore }

// startConntrackGC spawns the periodic ct_map garbage collector. It is
// not informer-driven (no resource events to react to), so it lives
// outside the Runner abstraction as a plain goroutine.
func (m *Manager) startConntrackGC(ctx context.Context) {
	gc := reconciler.NewConntrack(m.podEgress.Objs.CtMap, reconciler.ConntrackGCInterval)
	cctx, cancel := context.WithCancel(ctx)
	m.conntrackCancel = cancel
	m.conntrackDone = make(chan struct{})
	go func() {
		defer close(m.conntrackDone)
		gc.Run(cctx)
	}()
}

// startAffinityGC spawns the periodic service_affinity_map garbage
// collector. The map is LRU_HASH and the BPF fast path tolerates
// stale entries (gen + bound checks invalidate them implicitly), so
// the GC is purely an opportunistic capacity reclaim — no Service
// event drives it and there is no Runner to integrate with.
func (m *Manager) startAffinityGC(ctx context.Context) {
	gc := servicereconciler.NewAffinityGC(m.podEgress.Objs.ServiceAffinityMap, servicereconciler.AffinityGCInterval)
	cctx, cancel := context.WithCancel(ctx)
	m.affinityGCCancel = cancel
	m.affinityGCDone = make(chan struct{})
	go func() {
		defer close(m.affinityGCDone)
		gc.Run(cctx)
	}()
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.traceCancel != nil {
		m.traceCancel()
		<-m.traceDone
		m.traceCancel = nil
	}
	if m.traceReader != nil {
		_ = m.traceReader.Close()
	}

	if m.conntrackCancel != nil {
		m.conntrackCancel()
		<-m.conntrackDone
		m.conntrackCancel = nil
	}

	if m.affinityGCCancel != nil {
		m.affinityGCCancel()
		<-m.affinityGCDone
		m.affinityGCCancel = nil
	}

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

	if m.napt != nil {
		if err := m.napt.CloseAll(); err != nil {
			return err
		}
	}

	if m.sgStore != nil {
		if err := m.sgStore.CloseAll(); err != nil {
			return err
		}
	}
	if m.aclStore != nil {
		if err := m.aclStore.CloseAll(); err != nil {
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
		m.serviceLBRunner,
		m.naptRunner,
		m.serviceNATRunner,
		m.sgRunner,
		m.sgMembershipRunner,
		m.aclRunner,
		m.traceRunner,
		m.nodeUnderlayRunner,
	}
	for _, rn := range runners {
		if rn == nil {
			continue
		}
		if err := rn.Stop(); err != nil {
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

// VirtualServiceMaps returns the BPF map handles the virtual-service
// plane needs (virtual_service_map for classifier programming and
// virtual_service_flow_map for return-path metadata reads). Must only
// be called after Start has loaded the pod_egress program.
func (m *Manager) VirtualServiceMaps() (svc, flow *ebpf.Map) {
	if m.podEgress == nil {
		return nil, nil
	}
	return m.podEgress.Objs.VirtualServiceMap, m.podEgress.Objs.VirtualServiceFlowMap
}

// SubnetInformer exposes the cached Subnet informer so the
// virtual-service plane can drive its own Subnet-based reconciler
// (DNS bindings) off the same informer the dataplane already uses.
func (m *Manager) SubnetInformer() cache.Informer { return m.subnetInformer }

// VpcInformer exposes the cached Vpc informer for fan-out hooks in the
// virtual-service plane (e.g. re-evaluate DNS bindings when a Vpc's
// VpcID is allocated late).
func (m *Manager) VpcInformer() cache.Informer { return m.vpcInformer }

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
	externalNetworkAttachmentInformer cache.Informer,
	natGatewayInformer cache.Informer,
	serviceNATAttachmentInformer cache.Informer,
	networkInterfaceInformer cache.Informer,
	securityGroupInformer cache.Informer,
	networkACLInformer cache.Informer,
	serviceLoadBalancerInformer cache.Informer,
	traceSessionInformer cache.Informer,
	nodeInformer cache.Informer,
	nodeName string,
	vxlanIfindex int,
	hostIfindex int,
	nodeIngressIfindex int,
	pinPath string,
	defaultGatewayMac net.HardwareAddr,
	juNodeUnderlayIP net.IP,
) *Manager {
	return &Manager{
		client:                            cl,
		nwepInformer:                      nwepInformer,
		eipaInformer:                      eipaInformer,
		addressPoolInformer:               addressPoolInformer,
		bgpAdvertisementInformer:          bgpAdvertisementInformer,
		rtInformer:                        rtInformer,
		subnetInformer:                    subnetInformer,
		vpcInformer:                       vpcInformer,
		serviceInformer:                   serviceInformer,
		endpointSliceInformer:             endpointSliceInformer,
		externalNetworkAttachmentInformer: externalNetworkAttachmentInformer,
		natGatewayInformer:                natGatewayInformer,
		serviceNATAttachmentInformer:      serviceNATAttachmentInformer,
		networkInterfaceInformer:          networkInterfaceInformer,
		securityGroupInformer:             securityGroupInformer,
		networkACLInformer:                networkACLInformer,
		serviceLoadBalancerInformer:       serviceLoadBalancerInformer,
		traceSessionInformer:              traceSessionInformer,
		nodeInformer:                      nodeInformer,
		nodeName:                          nodeName,
		vxlanIfindex:                      vxlanIfindex,
		hostIfindex:                       hostIfindex,
		nodeIngressIfindex:                nodeIngressIfindex,
		pinPath:                           pinPath,
		hostMac:                           defaultGatewayMac,
		juNodeUnderlayIP:                  juNodeUnderlayIP,
	}
}

// ServiceLoadBalancerProgrammer exposes the in-use Programmer for
// debug/observability surfaces (e.g. kubectl-juneau topology).
// Returns nil before Start has run.
func (m *Manager) ServiceLoadBalancerProgrammer() servicelbreconciler.Programmer {
	return m.serviceLBProgrammer
}
