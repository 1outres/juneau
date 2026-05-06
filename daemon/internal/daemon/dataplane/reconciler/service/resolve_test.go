package service

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestMatchEndpointsForPort_UnnamedSvcPortAcceptsAll(t *testing.T) {
	// Unnamed Service port: accept every endpoint regardless of
	// portName. Upstream validation only allows an unnamed port on a
	// single-port Service so there is no risk of cross-binding.
	eps := []endpointInfo{
		{address: "10.0.0.1", port: 80, portName: ""},
		{address: "10.0.0.2", port: 80, portName: "http"},
	}
	got := matchEndpointsForPort(eps, corev1.ServicePort{Port: 80})
	if len(got) != 2 {
		t.Errorf("unnamed svcPort must accept any endpoint, got %d", len(got))
	}
}

func TestMatchEndpointsForPort_NamedSvcPortRequiresExactName(t *testing.T) {
	// Named Service port: only endpoints whose portName matches
	// exactly are eligible. The empty-portName endpoint must be
	// rejected — under the previous fall-through it would have
	// leaked into every named port.
	eps := []endpointInfo{
		{address: "10.0.0.1", port: 80, portName: "http"},
		{address: "10.0.0.2", port: 80, portName: "metrics"},
		{address: "10.0.0.3", port: 80, portName: ""},
	}
	got := matchEndpointsForPort(eps, corev1.ServicePort{Name: "http"})
	if len(got) != 1 || got[0].address != "10.0.0.1" {
		t.Errorf("named svcPort must only accept exact-name endpoints, got %+v", got)
	}
}

func TestMatchEndpointsForPort_NamedSvcPortRejectsEmptyEndpointName(t *testing.T) {
	// Multi-port Service with all named ports: an endpoint missing
	// portName must not bind to any of them, otherwise the same
	// backend would appear under both Service ports and route
	// traffic for the wrong app to the wrong container port.
	eps := []endpointInfo{
		{address: "10.0.0.1", port: 8080, portName: ""},
	}
	httpMatched := matchEndpointsForPort(eps, corev1.ServicePort{Name: "http"})
	metricsMatched := matchEndpointsForPort(eps, corev1.ServicePort{Name: "metrics"})
	if len(httpMatched) != 0 || len(metricsMatched) != 0 {
		t.Errorf("empty endpoint portName must not bind to any named Service port: http=%d metrics=%d",
			len(httpMatched), len(metricsMatched))
	}
}

func TestMatchEndpointsForPort_NoMatchYieldsEmpty(t *testing.T) {
	eps := []endpointInfo{
		{address: "10.0.0.1", port: 80, portName: "http"},
	}
	got := matchEndpointsForPort(eps, corev1.ServicePort{Name: "metrics"})
	if len(got) != 0 {
		t.Errorf("named svcPort with no matching endpoints must return empty, got %+v", got)
	}
}
