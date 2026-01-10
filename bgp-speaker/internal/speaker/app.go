package speaker

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/1outres/juneau/bgp-speaker/internal/kube"
	"github.com/1outres/juneau/bgp-speaker/internal/reconcile"
	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func NewApp() *cli.Command {
	return &cli.Command{
		Name: "bgp-speaker",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "node-name",
				Required: true,
				Sources: cli.ValueSourceChain{Chain: []cli.ValueSource{
					cli.EnvVar("NODE_NAME"),
				}},
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			nodeName := cmd.String("node-name")

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

			rt, err := kube.NewRuntime(kubecfg, scheme)
			if err != nil {
				return err
			}

			invalidator := kube.NewInvalidator()
			if err := invalidator.RegisterHandlers(ctx, rt.Cache()); err != nil {
				return err
			}

			cacheErrCh := make(chan error, 1)
			go func() {
				cacheErrCh <- rt.Start(ctx)
			}()

			if err := rt.WaitForSync(ctx); err != nil {
				return err
			}

			invalidator.Notify()

			runner := reconcile.NewRunner(nodeName, rt.Client(), 300*time.Millisecond, reconcileOnce)
			runnerErrCh := make(chan error, 1)
			go func() {
				runnerErrCh <- runner.Start(ctx)
			}()

			zap.S().Infow("bgp-speaker running", "nodeName", nodeName)

			for {
				select {
				case <-ctx.Done():
					return nil
				case err := <-runnerErrCh:
					if err == nil {
						return errors.New("runner stopped")
					}
					return fmt.Errorf("runner stopped: %w", err)
				case err := <-cacheErrCh:
					if err == nil {
						return errors.New("cache stopped")
					}
					return fmt.Errorf("cache stopped: %w", err)
				case <-invalidator.C():
					runner.Trigger()
				}
			}
		},
	}
}
