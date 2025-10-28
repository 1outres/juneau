package daemon

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/1outres/juneau/daemon/internal/daemon/server"
	"github.com/1outres/juneau/daemon/pkg/juneaupb"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func NewApp() *cli.Command {
	return &cli.Command{
		Name: "juneaud",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "uds-path",
				Value: "/tmp/juneaud.sock",
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

			lis, err := net.Listen("unix", cmd.String("uds-path"))
			if err != nil {
				zap.S().Fatalf("listen unix: %v", err)
			}
			if err := os.Chmod(cmd.String("uds-path"), 0660); err != nil {
				zap.S().Errorf("chmod socket: %v", err)
			}

			s := grpc.NewServer()
			juneaupb.RegisterIPAMServer(s, server.NewIPAMServer())

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			go func() {
				zap.S().Infof("gRPC (UDS) listening on %s", cmd.String("uds-path"))
				if err := s.Serve(lis); err != nil {
					zap.S().Fatalf("serve: %v", err)
				}
			}()

			<-ctx.Done()
			zap.S().Infof("shutting down...")
			s.GracefulStop()
			_ = os.RemoveAll(cmd.String("uds-path"))

			return nil
		},
	}
}
