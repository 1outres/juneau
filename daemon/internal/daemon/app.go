package daemon

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/1outres/juneau/daemon/internal/daemon/kubeclient"
	"github.com/1outres/juneau/daemon/internal/daemon/server"
	"github.com/1outres/juneau/daemon/pkg/juneaupb"
	"github.com/urfave/cli/v3"
	"k8s.io/client-go/rest"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func NewApp() *cli.Command {
	return &cli.Command{
		Name: "juneaud",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "uds-path",
				Value: "/var/run/juneaud.sock",
			},
			&cli.StringFlag{
				Name:  "kubeconfig",
				Value: "",
				Usage: "Path to kubeconfig file (defaults to in-cluster config)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			var zapcfg zap.Config
			zapcfg = zap.NewDevelopmentConfig()
			logger, _ := zapcfg.Build()
			defer func() {
				_ = logger.Sync()
			}()
			zap.ReplaceGlobals(logger)

			// Initialize Kubernetes client

			config, err := rest.InClusterConfig()
			if err != nil {
				zap.S().Fatalf("failed to get in-cluster config: %v", err)
			}
			kubeclient, err := kubeclient.NewClient(config)
			if err != nil {
				zap.S().Fatalf("failed to create k8s client: %v", err)
			}

			// Start informers in background
			informerCtx, cancelInformers := context.WithCancel(context.Background())
			defer cancelInformers()

			if err := kubeclient.Start(informerCtx); err != nil {
				zap.S().Errorf("informers stopped with error: %v", err)
			}

			if err := kubeclient.WaitForCacheSync(informerCtx); err != nil {
				zap.S().Fatalf("failed to sync caches: %v", err)
			}
			zap.S().Infof("k8s informers synced")

			lis, err := net.Listen("unix", cmd.String("uds-path"))
			if err != nil {
				zap.S().Fatalf("listen unix: %v", err)
			}
			if err := os.Chmod(cmd.String("uds-path"), 0660); err != nil {
				zap.S().Errorf("chmod socket: %v", err)
			}

			s := grpc.NewServer()
			juneaupb.RegisterIPAMServer(s, server.NewIPAMServer(kubeclient))

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			go func() {
				zap.S().Infof("gRPC over UDS listening on %s", cmd.String("uds-path"))
				if err := s.Serve(lis); err != nil {
					zap.S().Fatalf("serve: %v", err)
				}
			}()

			<-ctx.Done()
			zap.S().Infof("shutting down...")
			cancelInformers() // Stop informers
			s.GracefulStop()
			_ = os.RemoveAll(cmd.String("uds-path"))

			return nil
		},
	}
}
