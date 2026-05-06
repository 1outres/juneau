package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/bootstrap"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane"
	"github.com/1outres/juneau/daemon/internal/daemon/grpc"
	"github.com/1outres/juneau/daemon/internal/daemon/runner"
	"github.com/1outres/juneau/daemon/internal/daemon/virtservice"
	"github.com/1outres/juneau/daemon/internal/daemon/virtservice/dns"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func NewApp() *cli.Command {
	return &cli.Command{
		Name: "juneaud",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "uds-path",
				Value: "/var/run/juneaud.sock",
			},
			&cli.IntFlag{
				Name:  "cni-uds-timeout-ms",
				Value: 5000,
			},
			&cli.StringFlag{
				Name:  "cni-bin-dir",
				Value: "/opt/cni/bin",
			},
			&cli.StringFlag{
				Name:  "cni-conf-dir",
				Value: "/etc/cni/net.d",
			},
			&cli.StringFlag{
				Name:     "node-name",
				Required: true,
				Sources: cli.ValueSourceChain{Chain: []cli.ValueSource{
					cli.EnvVar("NODE_NAME"),
				}},
			},
			&cli.StringFlag{
				Name:  "pod-namespace",
				Value: "kube-system",
				Usage: "Namespace where the daemon writes per-Node NetworkEndpoint resources.",
				Sources: cli.ValueSourceChain{Chain: []cli.ValueSource{
					cli.EnvVar("POD_NAMESPACE"),
				}},
			},
			&cli.StringFlag{
				Name: "vxlan-parent-iface",
			},
			&cli.StringFlag{
				Name:  "node-ingress-iface",
				Usage: "Interface to attach node-ingress BPF program to. Defaults to the node's main iface.",
			},
			&cli.StringFlag{
				Name:  "bpf-pin-path",
				Value: "/juneau-bpf/juneau",
			},
			&cli.StringFlag{
				Name:  "dns-upstream",
				Value: "8.8.8.8:53,1.1.1.1:53",
				Usage: "Comma-separated list of upstream DNS resolvers (host[:port]) the virtual DNS service forwards non-cluster names to.",
				Sources: cli.ValueSourceChain{Chain: []cli.ValueSource{
					cli.EnvVar("JUNEAU_DNS_UPSTREAM"),
				}},
			},
			&cli.IntFlag{
				Name:  "virtservice-tap-mtu",
				Value: 1450,
				Usage: "MTU for the virtual-service TAP. Default leaves headroom for VXLAN encapsulation on a 1500-byte underlay.",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			udsPath := cmd.String("uds-path")
			cniUDSTimeoutMs := cmd.Int("cni-uds-timeout-ms")
			cniBinDir := cmd.String("cni-bin-dir")
			cniConfDir := cmd.String("cni-conf-dir")
			nodeName := cmd.String("node-name")
			podNamespace := cmd.String("pod-namespace")
			vxlanParentIface := cmd.String("vxlan-parent-iface")
			nodeIngressIfaceName := cmd.String("node-ingress-iface")
			bpfPinPath := cmd.String("bpf-pin-path")
			dnsUpstream := cmd.String("dns-upstream")
			virtServiceTAPMTU := cmd.Int("virtservice-tap-mtu")

			zapcfg := zap.NewDevelopmentConfig()
			logger, err := zapcfg.Build()
			if err != nil {
				return fmt.Errorf("build logger: %w", err)
			}
			defer func() {
				_ = logger.Sync()
			}()
			zap.ReplaceGlobals(logger)

			kubecfg, err := config.GetConfig()
			if err != nil {
				return fmt.Errorf("get kubeconfig: %w", err)
			}

			scheme := runtime.NewScheme()
			if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
				return fmt.Errorf("add juneau scheme: %w", err)
			}
			if err := corev1.AddToScheme(scheme); err != nil {
				return fmt.Errorf("add corev1 scheme: %w", err)
			}
			if err := discoveryv1.AddToScheme(scheme); err != nil {
				return fmt.Errorf("add discoveryv1 scheme: %w", err)
			}

			cache, err := cache.New(kubecfg, cache.Options{
				Scheme: scheme,
				ByObject: map[client.Object]cache.ByObject{
					&juneauv1alpha1.NetworkInterface{}:          {},
					&juneauv1alpha1.NetworkEndpoint{}:           {},
					&juneauv1alpha1.ElasticIPAttachment{}:       {},
					&juneauv1alpha1.AddressPool{}:               {},
					&juneauv1alpha1.BGPAdvertisement{}:          {},
					&juneauv1alpha1.Subnet{}:                    {},
					&juneauv1alpha1.Vpc{}:                       {},
					&juneauv1alpha1.RouteTable{}:                {},
					&juneauv1alpha1.NATGateway{}:                {},
					&juneauv1alpha1.ExternalNetworkAttachment{}: {},
					&juneauv1alpha1.ServiceNATAttachment{}:      {},
					&juneauv1alpha1.SecurityGroup{}:             {},
					&juneauv1alpha1.AllocationClaim{}:           {},
					&juneauv1alpha1.NetworkACL{}:                {},
					&juneauv1alpha1.TraceSession{}:              {},
					&corev1.Service{}:                           {},
					&discoveryv1.EndpointSlice{}:                {},
				},
			})
			if err != nil {
				return fmt.Errorf("create cache: %w", err)
			}

			nwepInfromer, err := cache.GetInformer(ctx, &juneauv1alpha1.NetworkEndpoint{})
			if err != nil {
				return fmt.Errorf("get NetworkEndpoint informer: %w", err)
			}

			eipaInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.ElasticIPAttachment{})
			if err != nil {
				return fmt.Errorf("get ElasticIPAttachment informer: %w", err)
			}

			addressPoolInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.AddressPool{})
			if err != nil {
				return fmt.Errorf("get AddressPool informer: %w", err)
			}

			bgpAdvertisementInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.BGPAdvertisement{})
			if err != nil {
				return fmt.Errorf("get BGPAdvertisement informer: %w", err)
			}

			rtInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.RouteTable{})
			if err != nil {
				return fmt.Errorf("get RouteTable informer: %w", err)
			}

			subnetInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.Subnet{})
			if err != nil {
				return fmt.Errorf("get Subnet informer: %w", err)
			}

			vpcInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.Vpc{})
			if err != nil {
				return fmt.Errorf("get Vpc informer: %w", err)
			}

			serviceInformer, err := cache.GetInformer(ctx, &corev1.Service{})
			if err != nil {
				return fmt.Errorf("get Service informer: %w", err)
			}

			endpointSliceInformer, err := cache.GetInformer(ctx, &discoveryv1.EndpointSlice{})
			if err != nil {
				return fmt.Errorf("get EndpointSlice informer: %w", err)
			}

			externalNetworkAttachmentInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.ExternalNetworkAttachment{})
			if err != nil {
				return fmt.Errorf("get ExternalNetworkAttachment informer: %w", err)
			}

			natGatewayInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.NATGateway{})
			if err != nil {
				return fmt.Errorf("get NATGateway informer: %w", err)
			}

			serviceNATAttachmentInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.ServiceNATAttachment{})
			if err != nil {
				return fmt.Errorf("get ServiceNATAttachment informer: %w", err)
			}

			networkInterfaceInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.NetworkInterface{})
			if err != nil {
				return fmt.Errorf("get NetworkInterface informer: %w", err)
			}

			securityGroupInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.SecurityGroup{})
			if err != nil {
				return fmt.Errorf("get SecurityGroup informer: %w", err)
			}

			networkACLInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.NetworkACL{})
			if err != nil {
				return fmt.Errorf("get NetworkACL informer: %w", err)
			}

			traceSessionInformer, err := cache.GetInformer(ctx, &juneauv1alpha1.TraceSession{})
			if err != nil {
				return fmt.Errorf("get TraceSession informer: %w", err)
			}

			cl, err := client.New(kubecfg, client.Options{
				Scheme: scheme,
				Cache: &client.CacheOptions{
					Reader: cache,
				},
			})
			if err != nil {
				return fmt.Errorf("create client: %w", err)
			}

			if err := cache.IndexField(
				ctx,
				&juneauv1alpha1.NetworkInterface{},
				"spec.podRef.interface",
				func(obj client.Object) []string {
					nwif := obj.(*juneauv1alpha1.NetworkInterface)
					if nwif.Spec.PodRef.Interface == "" {
						return nil
					}
					return []string{nwif.Spec.PodRef.Interface}
				},
			); err != nil {
				return fmt.Errorf("index NetworkInterface by spec.podRef.interface: %w", err)
			}
			if err := cache.IndexField(
				ctx,
				&juneauv1alpha1.NetworkInterface{},
				"spec.podRef.name",
				func(obj client.Object) []string {
					nwif := obj.(*juneauv1alpha1.NetworkInterface)
					if nwif.Spec.PodRef.Name == "" {
						return nil
					}
					return []string{nwif.Spec.PodRef.Name}
				},
			); err != nil {
				return fmt.Errorf("index NetworkInterface by spec.podRef.name: %w", err)
			}
			if err := cache.IndexField(
				ctx,
				&juneauv1alpha1.NetworkInterface{},
				"spec.podRef.uid",
				func(obj client.Object) []string {
					nwif := obj.(*juneauv1alpha1.NetworkInterface)
					if nwif.Spec.PodRef.UID == "" {
						return nil
					}
					return []string{nwif.Spec.PodRef.UID}
				},
			); err != nil {
				return fmt.Errorf("index NetworkInterface by spec.podRef.uid: %w", err)
			}

			if err := cache.IndexField(
				ctx,
				&juneauv1alpha1.NetworkEndpoint{},
				"spec.podRef.interface",
				func(obj client.Object) []string {
					nwep := obj.(*juneauv1alpha1.NetworkEndpoint)
					if nwep.Spec.PodRef == nil || nwep.Spec.PodRef.Interface == "" {
						return nil
					}
					return []string{nwep.Spec.PodRef.Interface}
				},
			); err != nil {
				return fmt.Errorf("index NetworkEndpoint by spec.podRef.interface: %w", err)
			}
			if err := cache.IndexField(
				ctx,
				&juneauv1alpha1.NetworkEndpoint{},
				"spec.podRef.name",
				func(obj client.Object) []string {
					nwep := obj.(*juneauv1alpha1.NetworkEndpoint)
					if nwep.Spec.PodRef == nil || nwep.Spec.PodRef.Name == "" {
						return nil
					}
					return []string{nwep.Spec.PodRef.Name}
				},
			); err != nil {
				return fmt.Errorf("index NetworkEndpoint by spec.podRef.name: %w", err)
			}
			if err := cache.IndexField(
				ctx,
				&juneauv1alpha1.NetworkEndpoint{},
				"spec.podRef.uid",
				func(obj client.Object) []string {
					nwep := obj.(*juneauv1alpha1.NetworkEndpoint)
					if nwep.Spec.PodRef == nil || nwep.Spec.PodRef.UID == "" {
						return nil
					}
					return []string{nwep.Spec.PodRef.UID}
				},
			); err != nil {
				return fmt.Errorf("index NetworkEndpoint by spec.podRef.uid: %w", err)
			}
			if err := cache.IndexField(
				ctx,
				&juneauv1alpha1.Subnet{},
				"spec.vpc",
				func(obj client.Object) []string {
					subnet := obj.(*juneauv1alpha1.Subnet)
					if subnet.Spec.Vpc == "" {
						return nil
					}
					return []string{subnet.Spec.Vpc}
				},
			); err != nil {
				return fmt.Errorf("index Subnet by spec.vpc: %w", err)
			}

			cacheErrCh := make(chan error, 1)
			go func() {
				cacheErrCh <- cache.Start(ctx)
			}()

			if err := bootstrap.InstallCNIBinary(cniBinDir); err != nil {
				return fmt.Errorf("install CNI binary: %w", err)
			}
			zap.S().Infof("installed CNI binary to %s", cniBinDir)

			if err := bootstrap.InstallCNIConfig(cniConfDir, udsPath, cniUDSTimeoutMs); err != nil {
				return fmt.Errorf("install CNI config: %w", err)
			}
			zap.S().Infof("installed CNI config to %s", cniConfDir)

			if err := bootstrap.CopyLoopbackCNI(cniBinDir); err != nil {
				return fmt.Errorf("copy loopback CNI binary: %w", err)
			}

			if ok := cache.WaitForCacheSync(ctx); !ok {
				return fmt.Errorf("failed to sync cache")
			}

			juneauNodeIfaceInfo, err := bootstrap.SetupDefaultGatewayIface(ctx, cl, nodeName)
			if err != nil {
				return fmt.Errorf("setup default gateway iface: %w", err)
			}
			hostIfaceInfo := &juneauNodeIfaceInfo.HostIfaceInfo

			// The node's underlay IP (its NodeInternalIP) backs cross-node
			// fdb entries pointing at this node's juneau_node.
			var nodeUnderlayIP net.IP
			{
				var node corev1.Node
				if err := cl.Get(ctx, client.ObjectKey{Name: nodeName}, &node); err != nil {
					return fmt.Errorf("get Node %q for underlay IP: %w", nodeName, err)
				}
				for _, addr := range node.Status.Addresses {
					if addr.Type == corev1.NodeInternalIP {
						nodeUnderlayIP = net.ParseIP(addr.Address)
						break
					}
				}
				if nodeUnderlayIP == nil {
					return fmt.Errorf("node %q has no InternalIP", nodeName)
				}
			}

			if vxlanParentIface == "" || nodeIngressIfaceName == "" {
				mainIface, err := bootstrap.SearchMainIface(ctx, cl, nodeName)
				if err != nil {
					return fmt.Errorf("find main iface: %w", err)
				}

				if vxlanParentIface == "" {
					vxlanParentIface = mainIface
				}
				if nodeIngressIfaceName == "" {
					nodeIngressIfaceName = mainIface
				}
			}

			vxlanIfindex, err := bootstrap.SetupVxlanIface(vxlanParentIface)
			if err != nil {
				return fmt.Errorf("setup vxlan iface: %w", err)
			}

			if err := bootstrap.ConfigureSysctl(); err != nil {
				return fmt.Errorf("configure sysctl: %w", err)
			}

			if err := ensureBPFFSMounted(bpfPinPath); err != nil {
				return fmt.Errorf("ensure bpf fs mount: %w", err)
			}

			nodeIngressIface, err := net.InterfaceByName(nodeIngressIfaceName)
			if err != nil {
				return fmt.Errorf("lookup node ingress iface %q: %w", nodeIngressIfaceName, err)
			}

			bpfManager := dataplane.NewManager(cl, nwepInfromer, eipaInformer, addressPoolInformer, bgpAdvertisementInformer, rtInformer, subnetInformer, vpcInformer, serviceInformer, endpointSliceInformer, externalNetworkAttachmentInformer, natGatewayInformer, serviceNATAttachmentInformer, networkInterfaceInformer, securityGroupInformer, networkACLInformer, traceSessionInformer, nodeName, vxlanIfindex, hostIfaceInfo.Ifindex, nodeIngressIface.Index, bpfPinPath, hostIfaceInfo.MAC, nodeUnderlayIP)
			if err := bpfManager.Start(ctx); err != nil {
				return fmt.Errorf("initialize BPF manager: %w", err)
			}
			defer func() {
				_ = bpfManager.Stop()
			}()

			// Bring up the virtual-service plane (TAP, AF_PACKET sender,
			// dispatcher, registry) over the BPF maps the dataplane just
			// loaded, then bind the per-Subnet DNS service into it.
			vsServiceMap, vsFlowMap := bpfManager.VirtualServiceMaps()
			if vsServiceMap == nil || vsFlowMap == nil {
				return fmt.Errorf("virtual-service BPF maps unavailable after dataplane Start")
			}
			vsMgr, err := virtservice.NewManager(vsServiceMap, vsFlowMap, virtservice.ManagerOptions{TAPMtu: virtServiceTAPMTU})
			if err != nil {
				return fmt.Errorf("init virtservice manager: %w", err)
			}
			if err := vsMgr.Start(ctx); err != nil {
				return fmt.Errorf("start virtservice manager: %w", err)
			}
			defer func() {
				_ = vsMgr.Stop()
			}()

			dnsService, dnsRunner, err := startDNSService(ctx, cl, vsMgr.Registry(), bpfManager, dnsUpstream)
			if err != nil {
				return fmt.Errorf("start virtual DNS service: %w", err)
			}
			defer func() {
				if dnsService != nil {
					_ = dnsService.Stop()
				}
				if dnsRunner != nil {
					_ = dnsRunner.Stop()
				}
			}()

			// Publish the per-Node juneau_node NetworkEndpoint so the
			// data plane reconcilers (arp/fdb/pod-iface/attacher) can
			// program the maps. Other nodes also pick it up to populate
			// their fdb (remote) entries pointing at this node's
			// juneau_node MAC.
			if err := bootstrap.EnsureJuneauNodeEndpoint(ctx, cl, podNamespace, nodeName, juneauNodeIfaceInfo, "default"); err != nil {
				return fmt.Errorf("ensure juneau_node NetworkEndpoint: %w", err)
			}

			grpcServer := grpc.NewServer(grpc.ServerConfig{
				Client:       cl,
				TraceBus:     bpfManager.TraceBus(),
				TraceStore:   bpfManager.TraceStore(),
				MapInventory: bpfManager.MapInventory(),
				NodeName:     nodeName,
				DebugTCPAddr: grpc.DefaultDebugTCPAddr,
			})
			defer grpcServer.Stop()
			grpcServer.StartBackground(ctx)

			grpcErrCh := make(chan error, 1)
			go func() {
				grpcErrCh <- grpcServer.Run(ctx, udsPath)
			}()

			select {
			case <-ctx.Done():
				zap.S().Infof("shutting down...")
				<-grpcErrCh
				<-cacheErrCh
				return nil
			case err := <-grpcErrCh:
				cancel()
				<-cacheErrCh
				return err
			case err := <-cacheErrCh:
				cancel()
				<-grpcErrCh
				if err == nil || errors.Is(err, context.Canceled) {
					return nil
				}
				return fmt.Errorf("cache stopped: %w", err)
			}
		},
	}
}

// startDNSService assembles the resolver chain (cluster zone +
// upstream forwarder), constructs the dns.Service, and wires it into
// a Runner driven by the dataplane's Subnet informer. Vpc events
// fan out so a late VpcID allocation propagates into DNS bindings
// without waiting for an unrelated Subnet event.
//
// Returns the Service and Runner so callers can defer Stop on each
// in the right order (Service first to drop registry bindings before
// the runner exits and stops feeding Reconcile calls).
func startDNSService(ctx context.Context, cl client.Client, registry virtservice.Registry, bpfManager *dataplane.Manager, dnsUpstream string) (*dns.Service, *runner.Runner, error) {
	resolvers := []dns.Resolver{dns.NewClusterZone(cl, dns.DefaultClusterDomain, 30)}
	upstream := strings.Split(dnsUpstream, ",")
	cleaned := upstream[:0]
	for _, s := range upstream {
		if t := strings.TrimSpace(s); t != "" {
			cleaned = append(cleaned, t)
		}
	}
	if len(cleaned) > 0 {
		fwd, err := dns.NewUpstreamForwarder(cleaned, dns.DefaultUpstreamTimeout)
		if err != nil {
			return nil, nil, fmt.Errorf("configure DNS upstream forwarder: %w", err)
		}
		resolvers = append(resolvers, fwd)
	}
	chain := dns.NewChain(resolvers...)

	svc := dns.New(ctx, cl, registry, chain, dns.NewCachedVPCResolver(cl))
	r := runner.New(svc)
	if err := r.Watch(bpfManager.SubnetInformer(), runner.MetaNamespaceKey); err != nil {
		return nil, nil, fmt.Errorf("watch Subnet for DNS: %w", err)
	}
	if err := r.WatchFanOut(bpfManager.VpcInformer(), svc.FanOutVpcToSubnets); err != nil {
		return nil, nil, fmt.Errorf("watch Vpc for DNS: %w", err)
	}
	r.Start(ctx, 1)
	return svc, r, nil
}

func ensureBPFFSMounted(pinPath string) error {
	mountPath := filepath.Dir(pinPath)
	if err := os.MkdirAll(mountPath, 0o755); err != nil {
		return err
	}

	var stat unix.Statfs_t
	if err := unix.Statfs(mountPath, &stat); err == nil && stat.Type == unix.BPF_FS_MAGIC {
		return nil
	}

	if err := unix.Mount("bpffs", mountPath, "bpf", 0, ""); err != nil {
		return err
	}

	return nil
}
