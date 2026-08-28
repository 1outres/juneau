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

// A Pod and an address together are how an L2Network without a CIDR
// is traced: the Pod says which network, the address says which of
// its addresses. juneau hands out none there and never learns the one
// the workload picked.
func TestOptionsValidateAcceptsAPodAndAnAddressTogether(t *testing.T) {
	o := newOptionsForTest()
	o.SourcePod = "default/lab-a"
	o.SourceInterface = "eth1"
	o.SourceIP = "192.168.60.1"
	o.DestPod = "default/lab-b"
	o.DestInterface = "eth1"
	o.DestIP = "192.168.60.2"
	o.Protocol = "icmp"
	o.ObserveOnly = true
	if err := o.Validate(); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

func TestOptionsValidateRequiresASource(t *testing.T) {
	o := newOptionsForTest()
	o.DestIP = "10.0.0.2"
	o.Port = 80
	if err := o.Validate(); err == nil {
		t.Fatal("expected an error when neither source flag is given")
	}
}

func TestOptionsValidateRejectsAnInterfaceWithoutItsPod(t *testing.T) {
	for _, tt := range []struct {
		name  string
		apply func(*Options)
	}{
		{
			name:  "source",
			apply: func(o *Options) { o.SourceIP = "10.0.0.1"; o.SourceInterface = "eth1" },
		},
		{
			name:  "destination",
			apply: func(o *Options) { o.SourcePod = "default/client"; o.DestInterface = "eth1" },
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			o := newOptionsForTest()
			o.DestIP = "10.0.0.2"
			o.Port = 80
			o.ObserveOnly = true
			tt.apply(o)
			if err := o.Validate(); err == nil {
				t.Fatal("expected an error when an interface names a pod that was not given")
			}
		})
	}
}

func TestOptionsValidateRejectsAServiceWithASecondDestination(t *testing.T) {
	for _, tt := range []struct {
		name  string
		apply func(*Options)
	}{
		{name: "with a pod", apply: func(o *Options) { o.DestPod = "default/api-0" }},
		{name: "with an address", apply: func(o *Options) { o.DestIP = "10.96.0.10" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			o := newOptionsForTest()
			o.SourcePod = "default/client"
			o.DestService = "default/api"
			o.Port = 443
			o.ObserveOnly = true
			tt.apply(o)
			if err := o.Validate(); err == nil {
				t.Fatal("expected an error when a service is given a second destination")
			}
		})
	}
}
