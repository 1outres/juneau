package daemon

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/1outres/juneau/daemon/internal/daemon/bootstrap"
	"github.com/1outres/juneau/daemon/internal/daemon/grpc"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
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
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			udsPath := cmd.String("uds-path")
			cniUDSTimeoutMs := cmd.Int("cni-uds-timeout-ms")
			cniBinDir := cmd.String("cni-bin-dir")
			cniCOnfDir := cmd.String("cni-conf-dir")

			var zapcfg zap.Config
			zapcfg = zap.NewDevelopmentConfig()
			logger, _ := zapcfg.Build()
			defer func() {
				_ = logger.Sync()
			}()
			zap.ReplaceGlobals(logger)

			if err := bootstrap.InstallCNIBinary(cniBinDir); err != nil {
				zap.S().Fatalf("failed to install CNI binary: %v", err)
			}
			zap.S().Infof("installed CNI binary to %s", cniBinDir)

			if err := bootstrap.InstallCNIConfig(cniCOnfDir, udsPath, cniUDSTimeoutMs); err != nil {
				zap.S().Fatalf("failed to install CNI config: %v", err)
			}
			zap.S().Infof("installed CNI config to %s", cniCOnfDir)

			if err := bootstrap.CopyLoopbackCNI(cniBinDir); err != nil {
				zap.S().Fatalf("failed to copy loopback CNI binary: %v", err)
			}

			grpcServer := grpc.NewServer()
			if err := grpcServer.Start(udsPath); err != nil {
				zap.S().Fatalf("failed to start gRPC server: %v", err)
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			<-ctx.Done()
			zap.S().Infof("shutting down...")

			return nil
		},
	}
}
