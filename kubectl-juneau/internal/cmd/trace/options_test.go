package trace

import (
	"context"
	"testing"
	"time"

	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/1outres/juneau/kubectl-juneau/internal/factory/nodeagent"
)

type fakeFactory struct {
	ns string
}

func (f *fakeFactory) Streams() genericiooptions.IOStreams {
	return genericiooptions.NewTestIOStreamsDiscard()
}
func (f *fakeFactory) RESTConfig() (*rest.Config, error) { return nil, nil }
func (f *fakeFactory) Kube() (client.Client, error)      { return nil, nil }
func (f *fakeFactory) Discovery() (discovery.DiscoveryInterface, error) {
	return nil, nil
}
func (f *fakeFactory) Namespace() (string, bool, error) { return f.ns, false, nil }
func (f *fakeFactory) NodeAgent(_ context.Context, _ string) (nodeagent.Client, error) {
	return nil, nodeagent.ErrNotImplemented
}

func newOptionsForTest() *Options {
	o := newOptions(&fakeFactory{ns: "default"})
	// Skip rand to keep test deterministic.
	o.traceID = 1
	return o
}

func TestOptionsValidateAcceptsPodToService(t *testing.T) {
	o := newOptionsForTest()
	o.SourcePod = "default/client"
	o.DestService = "default/api"
	o.Port = 443
	o.Protocol = "tcp"
	o.ObserveOnly = true
	if err := o.Validate(); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

func TestOptionsValidateRequiresExactlyOneSource(t *testing.T) {
	o := newOptionsForTest()
	o.SourcePod = "default/client"
	o.SourceIP = "10.0.0.1"
	o.DestIP = "10.0.0.2"
	o.Port = 80
	if err := o.Validate(); err == nil {
		t.Fatalf("expected error when both source pod and ip set")
	}
}

func TestOptionsValidateRequiresPortForTCP(t *testing.T) {
	o := newOptionsForTest()
	o.SourcePod = "default/client"
	o.DestIP = "10.0.0.1"
	o.Protocol = "tcp"
	if err := o.Validate(); err == nil {
		t.Fatalf("expected error when TCP without port")
	}
}

func TestOptionsValidateICMPMustHaveNoPort(t *testing.T) {
	o := newOptionsForTest()
	o.SourcePod = "default/client"
	o.DestIP = "10.0.0.1"
	o.Protocol = "icmp"
	o.Port = 8
	if err := o.Validate(); err == nil {
		t.Fatalf("expected error when ICMP has port")
	}
}

func TestOptionsValidateRejectsTimeoutGreaterThanTTL(t *testing.T) {
	o := newOptionsForTest()
	o.SourcePod = "default/client"
	o.DestIP = "10.0.0.1"
	o.Port = 80
	o.Timeout = time.Minute
	o.TTL = time.Second
	if err := o.Validate(); err == nil {
		t.Fatalf("expected error when timeout > ttl")
	}
}

func TestOptionsCompletePopulatesNamespace(t *testing.T) {
	o := newOptions(&fakeFactory{ns: "myns"})
	if err := o.Complete([]string{"pod", "client"}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if o.SourcePod != "myns/client" {
		t.Fatalf("source = %q", o.SourcePod)
	}
	if o.traceID == 0 {
		t.Fatalf("traceID should be non-zero")
	}
}
