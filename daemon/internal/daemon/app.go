package daemon

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/1outres/juneau/daemon/internal/daemon/kubeclient"
	"github.com/1outres/juneau/daemon/internal/daemon/server"
	"github.com/1outres/juneau/daemon/pkg/cni"
	"github.com/1outres/juneau/daemon/pkg/juneaupb"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"k8s.io/client-go/rest"
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
				Name: "cni-bin-dir",
				Value: "/opt/cni/bin",
			},
			&cli.StringFlag{
				Name: "cni-conf-dir",
				Value: "/etc/cni/net.d",
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

			targetBin := filepath.Join(cmd.String("cni-bin-dir"), "juneau-cni")
	    targetConf := filepath.Join(cmd.String("cni-conf-dir"), "juneau.conf")

			if err := installFile("cni", targetBin, 0o755, true); err != nil {
				zap.S().Fatalf("failed to install CNI binary: %v", err)
			}
			if err := installFile("cni.conf", targetConf, 0o644, false); err != nil {
				zap.S().Fatalf("failed to install CNI config: %v", err)
			}

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

func installFile(srcFSPath string, dstPath string, mode fs.FileMode, executable bool) error {
	data, err := cni.EmbeddedFS.ReadFile(srcFSPath)
	if err != nil {
		return fmt.Errorf("read embedded file: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	if same, _ := fileContentEquals(dstPath, data); same {
		zap.S().Infof("skip (up-to-date): %s", dstPath)
		return nil
	}

	tmp := filepath.Join(filepath.Dir(dstPath), fmt.Sprintf(".%s.tmp-%d", filepath.Base(dstPath), time.Now().UnixNano()))
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp file: %w", err)
	}

	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod tmp file: %w", err)
	}

	if err := os.Rename(tmp, dstPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename to destination: %w", err)
	}

	zap.S().Infof("installed: %s (mode %o)", dstPath, mode)
	return nil
}

func fileContentEquals(path string, data []byte) (bool, error) {
	existing, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if len(existing) != len(data) {
		return false, nil
	}
	for i := range existing {
		if existing[i] != data[i] {
			return false, nil
		}
	}
	return true, nil
}
