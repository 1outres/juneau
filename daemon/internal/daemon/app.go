package daemon

import (
	"context"
	"os/signal"
	"syscall"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/bootstrap"
	"github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/grpc"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
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
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			udsPath := cmd.String("uds-path")
			cniUDSTimeoutMs := cmd.Int("cni-uds-timeout-ms")
			cniBinDir := cmd.String("cni-bin-dir")
			cniConfDir := cmd.String("cni-conf-dir")
			nodeName := cmd.String("node-name")
			vxlanParentIface := cmd.String("vxlan-parent-iface")
			masqueradeIface := cmd.String("masquerade-iface")

			var zapcfg zap.Config
			zapcfg = zap.NewDevelopmentConfig()
			logger, _ := zapcfg.Build()
			defer func() {
				_ = logger.Sync()
			}()
			zap.ReplaceGlobals(logger)

			kubecfg, err := config.GetConfig()
			if err != nil {
				zap.S().Fatalf("failed to get kubeconfig: %v", err)
			}

			scheme := runtime.NewScheme()
			utilruntime.Must(juneauv1alpha1.AddToScheme(scheme))
			utilruntime.Must(corev1.AddToScheme(scheme))

			cache, err := cache.New(kubecfg, cache.Options{
				Scheme: scheme,
				ByObject: map[client.Object]cache.ByObject{
					&juneauv1alpha1.NetworkInterface{}: {},
					&juneauv1alpha1.NetworkEndpoint{}:  {},
					&juneauv1alpha1.Subnet{}:           {},
				},
			})
			if err != nil {
				zap.S().Fatalf("failed to create cache: %v", err)
			}

			nwepInfromer, err := cache.GetInformer(ctx, &juneauv1alpha1.NetworkEndpoint{})
			if err != nil {
				zap.S().Fatalf("failed to get NetworkEndpoint informer: %v", err)
			}

			cl, err := client.New(kubecfg, client.Options{
				Scheme: scheme,
				Cache: &client.CacheOptions{
					Reader: cache,
				},
			})

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
				zap.S().Fatalf("failed to index NetworkInterface by spec.podRef.interface: %v", err)
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
				zap.S().Fatalf("failed to index NetworkInterface by spec.podRef.name: %v", err)
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
				zap.S().Fatalf("failed to index NetworkInterface by spec.podRef.name: %v", err)
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
				zap.S().Fatalf("failed to index NetworkEndpoint by spec.podRef.interface: %v", err)
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
				zap.S().Fatalf("failed to index NetworkEndpoint by spec.podRef.name: %v", err)
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
				zap.S().Fatalf("failed to index NetworkEndpoint by spec.podRef.name: %v", err)
			}

			go func() {
				if err := cache.Start(ctx); err != nil {
					zap.S().Fatalf("failed to start cache: %v", err)
				}
			}()

			if err := bootstrap.InstallCNIBinary(cniBinDir); err != nil {
				zap.S().Fatalf("failed to install CNI binary: %v", err)
			}
			zap.S().Infof("installed CNI binary to %s", cniBinDir)

			if err := bootstrap.InstallCNIConfig(cniConfDir, udsPath, cniUDSTimeoutMs); err != nil {
				zap.S().Fatalf("failed to install CNI config: %v", err)
			}
			zap.S().Infof("installed CNI config to %s", cniConfDir)

			if err := bootstrap.CopyLoopbackCNI(cniBinDir); err != nil {
				zap.S().Fatalf("failed to copy loopback CNI binary: %v", err)
			}

			if ok := cache.WaitForCacheSync(ctx); !ok {
				zap.S().Fatalf("failed to sync cache")
			}

			hostIfaceInfo, err := bootstrap.SetupDefaultGatewayIface(ctx, cl)
			if err != nil {
				zap.S().Fatalf("failed to setup default gateway iface: %v", err)
			}

			if vxlanParentIface == "" || masqueradeIface == "" {
				mainIface, err := bootstrap.SearchMainIface(ctx, cl, nodeName)
				if err != nil {
					zap.S().Fatalf("failed to find main iface: %v", err)
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
				zap.S().Fatalf("failed to setup vxlan iface: %v", err)
			}

			if err := bootstrap.ConfigureSysctl(); err != nil {
				zap.S().Fatalf("failed to configure sysctl: %v", err)
			}

			if err := bootstrap.EnsureMasqueradeRule(ctx, cl, masqueradeIface); err != nil {
				zap.S().Fatalf("failed to ensure masquerade rule: %v", err)
			}

			bpfManager := bpf.NewManager(cl, nwepInfromer, nodeName, vxlanIfindex, hostIfaceInfo.Ifindex, hostIfaceInfo.MAC)
			if err := bpfManager.Start(ctx); err != nil {
				zap.S().Fatalf("failed to initialize BPF manager: %v", err)
			}

			grpcServer := grpc.NewServer(cl)
			if err := grpcServer.Start(udsPath); err != nil {
				zap.S().Fatalf("failed to start gRPC server: %v", err)
			}

			ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			<-ctx.Done()
			zap.S().Infof("shutting down...")

			bpfManager.Stop()

			return nil
		},
	}
}
