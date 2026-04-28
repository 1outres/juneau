package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/bootstrap"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane"
	"github.com/1outres/juneau/daemon/internal/daemon/grpc"
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
				Name: "vxlan-parent-iface",
			},
			&cli.StringFlag{
				Name: "masquerade-iface",
			},
			&cli.StringFlag{
				Name:  "bpf-pin-path",
				Value: "/juneau-bpf/juneau",
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
			vxlanParentIface := cmd.String("vxlan-parent-iface")
			masqueradeIface := cmd.String("masquerade-iface")
			bpfPinPath := cmd.String("bpf-pin-path")

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
					&juneauv1alpha1.NetworkInterface{}:    {},
					&juneauv1alpha1.NetworkEndpoint{}:     {},
					&juneauv1alpha1.ElasticIPAttachment{}: {},
					&juneauv1alpha1.AddressPool{}:         {},
					&juneauv1alpha1.BGPAdvertisement{}:    {},
					&juneauv1alpha1.Subnet{}:              {},
					&juneauv1alpha1.Vpc{}:                 {},
					&juneauv1alpha1.RouteTable{}:          {},
					&corev1.Service{}:                     {},
					&discoveryv1.EndpointSlice{}:          {},
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
					if nwep.Spec.PodRef.Interface == "" {
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
					if nwep.Spec.PodRef.Name == "" {
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
					if nwep.Spec.PodRef.UID == "" {
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

			if vxlanParentIface == "" || masqueradeIface == "" {
				mainIface, err := bootstrap.SearchMainIface(ctx, cl, nodeName)
				if err != nil {
					return fmt.Errorf("find main iface: %w", err)
				}

				if vxlanParentIface == "" {
					vxlanParentIface = mainIface
				}
				if masqueradeIface == "" {
					masqueradeIface = mainIface
				}
			}

			vxlanIfindex, err := bootstrap.SetupVxlanIface(vxlanParentIface)
			if err != nil {
				return fmt.Errorf("setup vxlan iface: %w", err)
			}

			if err := bootstrap.ConfigureSysctl(); err != nil {
				return fmt.Errorf("configure sysctl: %w", err)
			}

			if err := bootstrap.EnsureMasqueradeRule(ctx, cl, masqueradeIface); err != nil {
				return fmt.Errorf("ensure masquerade rule: %w", err)
			}

			if err := ensureBPFFSMounted(bpfPinPath); err != nil {
				return fmt.Errorf("ensure bpf fs mount: %w", err)
			}

			nodeIngressIface, err := net.InterfaceByName(masqueradeIface)
			if err != nil {
				return fmt.Errorf("lookup node ingress iface %q: %w", masqueradeIface, err)
			}

			bpfManager := dataplane.NewManager(cl, nwepInfromer, eipaInformer, addressPoolInformer, bgpAdvertisementInformer, rtInformer, subnetInformer, vpcInformer, serviceInformer, endpointSliceInformer, externalNetworkAttachmentInformer, natGatewayInformer, nodeName, vxlanIfindex, hostIfaceInfo.Ifindex, nodeIngressIface.Index, bpfPinPath, hostIfaceInfo.MAC, juneauNodeIfaceInfo.AssignedIP, nodeUnderlayIP)
			if err := bpfManager.Start(ctx); err != nil {
				return fmt.Errorf("initialize BPF manager: %w", err)
			}
			defer func() {
				_ = bpfManager.Stop()
			}()

			grpcServer := grpc.NewServer(cl)
			defer grpcServer.Stop()

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
