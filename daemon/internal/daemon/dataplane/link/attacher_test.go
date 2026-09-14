package link

import (
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

func newTestPodAttacher() *PodAttacher {
	return NewPodAttacher(nil, &program.PodEgress{}, &program.PodIngress{}, &program.L2Egress{}, &program.L2Ingress{}, "node-a")
}

func TestProgramsForFollowsTheNetworkOfTheEndpoint(t *testing.T) {
	attacher := newTestPodAttacher()
	for _, tc := range []struct {
		name string
		spec juneauv1alpha1.NetworkEndpointSpec
		want string
	}{
		{name: "subnet", spec: juneauv1alpha1.NetworkEndpointSpec{Subnet: "web"}, want: "pod"},
		{name: "l2Network", spec: juneauv1alpha1.NetworkEndpointSpec{L2Network: "lab"}, want: "l2"},
		{name: "externalNetwork", spec: juneauv1alpha1.NetworkEndpointSpec{ExternalNetwork: "internet"}, want: "pod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := attacher.programsFor(&juneauv1alpha1.NetworkEndpoint{Spec: tc.spec})
			if err != nil {
				t.Fatalf("programsFor: %v", err)
			}
			if got.label != tc.want {
				t.Errorf("programs = %q, want %q", got.label, tc.want)
			}
		})
	}
}

func TestProgramsForRejectsAnEndpointOnNoNetwork(t *testing.T) {
	if _, err := newTestPodAttacher().programsFor(&juneauv1alpha1.NetworkEndpoint{}); err == nil {
		t.Fatal("expected an error for an endpoint that names no network")
	}
}
