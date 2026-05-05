// Package factory is the single I/O seam between command code and the
// outside world. Every command package depends on this interface, never
// on raw `client.Client` or `rest.Config` constructors. Tests substitute
// a fake Factory; production wires the kube-backed implementation.
//
// Adding a new I/O channel (gRPC to juneaud, REST to a sidecar, etc.)
// means: extend Factory with a method, return ErrNotImplemented from
// the kube impl until the real client exists, and let later
// tiers add concrete logic. No command package should ever import
// rest/client/discovery directly.
package factory

import (
	"context"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/1outres/juneau/kubectl-juneau/internal/factory/nodeagent"
)

// Factory hands out clients and runtime context. Implementations are
// expected to be cheap to construct and to lazy-load expensive
// resources (rest config, kube client) on first call.
type Factory interface {
	// Streams exposes the IO boundary so command code never has to
	// thread os.Stdout/os.Stderr explicitly.
	Streams() genericiooptions.IOStreams

	// RESTConfig returns the resolved rest.Config built from
	// kubeconfig + cobra flags. Most callers should prefer Kube()
	// instead; RESTConfig is exposed for cases that need a low-level
	// handle (port-forward, exec).
	RESTConfig() (*rest.Config, error)

	// Kube returns a typed controller-runtime client preloaded with
	// the project's CRD scheme (corev1, discoveryv1, juneau v1alpha1).
	Kube() (client.Client, error)

	// Discovery returns a Kubernetes discovery client. Useful for
	// preflight checks ("is the Juneau CRD installed?").
	Discovery() (discovery.DiscoveryInterface, error)

	// Namespace returns the current namespace from kubeconfig
	// context, honouring -n / --namespace overrides. The bool
	// indicates whether the namespace was explicitly set.
	Namespace() (string, bool, error)

	// NodeAgent returns a per-Node debug client. Construction is
	// lazy: dialing is gated on the caller actually needing a
	// connection, so commands that never call NodeAgent pay no exec
	// startup cost.
	NodeAgent(ctx context.Context, node string) (nodeagent.Client, error)
}

// New returns the production Factory backed by the supplied
// ConfigFlags + IOStreams.
func New(configFlags *genericclioptions.ConfigFlags, streams genericiooptions.IOStreams) Factory {
	return &kubeFactory{configFlags: configFlags, streams: streams}
}
