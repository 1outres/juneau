package factory

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/kubectl-juneau/internal/factory/nodeagent"
)

// kubeFactory is the production Factory. The expensive bits (rest config,
// scheme, client) are built once and cached behind sync.Once so repeated
// flag parsing inside a single command invocation does not re-load
// kubeconfig.
type kubeFactory struct {
	configFlags *genericclioptions.ConfigFlags
	streams     genericiooptions.IOStreams

	loadOnce sync.Once
	loadErr  error
	cfg      *rest.Config
	scheme   *runtime.Scheme
	cl       client.Client

	discoveryOnce sync.Once
	discoveryErr  error
	discovery     discovery.DiscoveryInterface

	dialerOnce sync.Once
	dialerErr  error
	dialer     nodeagent.Dialer
}

func (f *kubeFactory) Streams() genericiooptions.IOStreams { return f.streams }

func (f *kubeFactory) load() error {
	f.loadOnce.Do(func() {
		cfg, err := f.configFlags.ToRESTConfig()
		if err != nil {
			f.loadErr = fmt.Errorf("load REST config: %w", err)
			return
		}

		scheme := runtime.NewScheme()
		for _, add := range []func(*runtime.Scheme) error{
			corev1.AddToScheme,
			discoveryv1.AddToScheme,
			juneauv1alpha1.AddToScheme,
		} {
			if err := add(scheme); err != nil {
				f.loadErr = fmt.Errorf("register scheme: %w", err)
				return
			}
		}

		cl, err := client.New(cfg, client.Options{Scheme: scheme})
		if err != nil {
			f.loadErr = fmt.Errorf("build kube client: %w", err)
			return
		}

		f.cfg = cfg
		f.scheme = scheme
		f.cl = cl
	})
	return f.loadErr
}

func (f *kubeFactory) RESTConfig() (*rest.Config, error) {
	if err := f.load(); err != nil {
		return nil, err
	}
	return f.cfg, nil
}

func (f *kubeFactory) Kube() (client.Client, error) {
	if err := f.load(); err != nil {
		return nil, err
	}
	return f.cl, nil
}

func (f *kubeFactory) Discovery() (discovery.DiscoveryInterface, error) {
	f.discoveryOnce.Do(func() {
		cfg, err := f.RESTConfig()
		if err != nil {
			f.discoveryErr = err
			return
		}
		dc, err := discovery.NewDiscoveryClientForConfig(cfg)
		if err != nil {
			f.discoveryErr = fmt.Errorf("build discovery client: %w", err)
			return
		}
		f.discovery = dc
	})
	return f.discovery, f.discoveryErr
}

func (f *kubeFactory) Namespace() (string, bool, error) {
	ns, overridden, err := f.configFlags.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return "", false, fmt.Errorf("resolve namespace: %w", err)
	}
	return ns, overridden, nil
}

func (f *kubeFactory) NodeAgent(ctx context.Context, node string) (nodeagent.Client, error) {
	if node == "" {
		return nil, fmt.Errorf("nodeagent: node name is required")
	}
	dialer, err := f.nodeDialer()
	if err != nil {
		return nil, err
	}
	return dialer.Dial(ctx, node)
}

func (f *kubeFactory) nodeDialer() (nodeagent.Dialer, error) {
	f.dialerOnce.Do(func() {
		cfg, err := f.RESTConfig()
		if err != nil {
			f.dialerErr = err
			return
		}
		kc, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			f.dialerErr = fmt.Errorf("build typed kube client: %w", err)
			return
		}
		f.dialer = nodeagent.NewExecDialer(cfg, kc, f.streams, nodeagent.ExecDialerOptions{})
	})
	return f.dialer, f.dialerErr
}
