package service

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/svcpolicy"
)

// makeBackend builds a resolved backend with sane defaults; tests
// override only the fields they care about. Keeping the constructor
// in one place keeps each test case readable as a one-line override.
func makeBackend(ip uint32, node string, ready, serving, terminating bool) resolvedBackend {
	return resolvedBackend{
		val:         bpf.PodEgressBackendVal{BackendIp: ip, BackendPort: 80, Kind: backendKindPod, BackendSubnetId: 1},
		nodeName:    node,
		ready:       ready,
		serving:     serving,
		terminating: terminating,
	}
}

func TestApplyPolicy_NoFilters_ReturnsReadyOnly(t *testing.T) {
	port := corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP}
	in := map[corev1.ServicePort][]resolvedBackend{
		port: {
			makeBackend(0x0a000001, "node-a", true, true, false),
			makeBackend(0x0a000002, "node-b", false, false, false),
		},
	}
	got := applyPolicy(in, svcpolicy.BackendSelectionPolicy{}, "node-a")
	if n := len(got[port]); n != 1 {
		t.Fatalf("want 1 backend (only Ready), got %d", n)
	}
	if got[port][0].val.BackendIp != 0x0a000001 {
		t.Errorf("wrong backend kept: %x", got[port][0].val.BackendIp)
	}
}

func TestApplyPolicy_GracefulTerminationFallback(t *testing.T) {
	port := corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP}
	// No Ready endpoint: fall back to Serving && !Terminating; drop the
	// terminating one even if it is still Serving.
	in := map[corev1.ServicePort][]resolvedBackend{
		port: {
			makeBackend(0x0a000001, "node-a", false, true, true),  // Serving but terminating → drop
			makeBackend(0x0a000002, "node-b", false, true, false), // graceful candidate
			makeBackend(0x0a000003, "node-c", false, false, false),
		},
	}
	got := applyPolicy(in, svcpolicy.BackendSelectionPolicy{}, "")
	if n := len(got[port]); n != 1 {
		t.Fatalf("expected 1 graceful backend, got %d", n)
	}
	if got[port][0].val.BackendIp != 0x0a000002 {
		t.Errorf("kept the wrong fallback: %x", got[port][0].val.BackendIp)
	}
}

func TestApplyPolicy_ReadyDominatesGraceful(t *testing.T) {
	port := corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP}
	in := map[corev1.ServicePort][]resolvedBackend{
		port: {
			makeBackend(0x0a000001, "node-a", true, true, false),
			makeBackend(0x0a000002, "node-b", false, true, false),
		},
	}
	got := applyPolicy(in, svcpolicy.BackendSelectionPolicy{}, "")
	if n := len(got[port]); n != 1 || got[port][0].val.BackendIp != 0x0a000001 {
		t.Errorf("ready endpoint should dominate graceful fallback; got %+v", got[port])
	}
}

func TestApplyPolicy_InternalLocal(t *testing.T) {
	port := corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP}
	policy := svcpolicy.BackendSelectionPolicy{InternalLocal: true}

	t.Run("only local survives", func(t *testing.T) {
		in := map[corev1.ServicePort][]resolvedBackend{
			port: {
				makeBackend(0x0a000001, "node-a", true, true, false),
				makeBackend(0x0a000002, "node-b", true, true, false),
			},
		}
		got := applyPolicy(in, policy, "node-a")
		if n := len(got[port]); n != 1 || got[port][0].nodeName != "node-a" {
			t.Errorf("expected only node-a backend, got %+v", got[port])
		}
	})

	t.Run("no local → empty (drop traffic)", func(t *testing.T) {
		in := map[corev1.ServicePort][]resolvedBackend{
			port: {
				makeBackend(0x0a000001, "node-b", true, true, false),
				makeBackend(0x0a000002, "node-c", true, true, false),
			},
		}
		got := applyPolicy(in, policy, "node-a")
		if n := len(got[port]); n != 0 {
			t.Errorf("expected empty backend list when no local endpoint, got %d", n)
		}
	})

	t.Run("local matches before condition filter (graceful local kept)", func(t *testing.T) {
		// All non-local are Ready, only local is graceful — must still
		// return the local graceful candidate, not silently swap to
		// non-local.
		in := map[corev1.ServicePort][]resolvedBackend{
			port: {
				makeBackend(0x0a000001, "node-a", false, true, false), // local, graceful
				makeBackend(0x0a000002, "node-b", true, true, false),
			},
		}
		got := applyPolicy(in, policy, "node-a")
		if n := len(got[port]); n != 1 || got[port][0].nodeName != "node-a" {
			t.Errorf("iTP=Local must not fall back to remote backend; got %+v", got[port])
		}
	})

	t.Run("empty localNode → policy skipped (defensive)", func(t *testing.T) {
		in := map[corev1.ServicePort][]resolvedBackend{
			port: {
				makeBackend(0x0a000001, "node-b", true, true, false),
			},
		}
		got := applyPolicy(in, policy, "")
		if n := len(got[port]); n != 1 {
			t.Errorf("empty localNode must skip Local filter; got %d", n)
		}
	})
}

func TestAffinitySecondsClamp(t *testing.T) {
	tests := []struct {
		name string
		in   svcpolicy.AffinityPolicy
		want uint32
	}{
		{"none", svcpolicy.AffinityPolicy{Mode: svcpolicy.AffinityNone, Timeout: time.Hour}, 0},
		{"client ip default", svcpolicy.AffinityPolicy{Mode: svcpolicy.AffinityClientIP, Timeout: 3 * time.Hour}, 10800},
		{"sub-second rounds up to 1", svcpolicy.AffinityPolicy{Mode: svcpolicy.AffinityClientIP, Timeout: 500 * time.Millisecond}, 1},
		{"zero timeout", svcpolicy.AffinityPolicy{Mode: svcpolicy.AffinityClientIP, Timeout: 0}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := affinitySecondsClamp(tc.in); got != tc.want {
				t.Errorf("affinitySecondsClamp = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestBackendSignature_StableAcrossOrder(t *testing.T) {
	port := corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP}
	svc := &corev1.Service{Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{port}}}

	a := map[corev1.ServicePort][]resolvedBackend{
		port: {
			{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000001, BackendPort: 80, BackendSubnetId: 1}},
			{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000002, BackendPort: 80, BackendSubnetId: 1}},
		},
	}
	b := map[corev1.ServicePort][]resolvedBackend{
		port: {
			{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000002, BackendPort: 80, BackendSubnetId: 1}},
			{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000001, BackendPort: 80, BackendSubnetId: 1}},
		},
	}
	if backendSignature(svc, a) != backendSignature(svc, b) {
		t.Errorf("signature must be order-independent")
	}
}

func TestBackendSignature_ChangesOnSetMutation(t *testing.T) {
	port := corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP}
	svc := &corev1.Service{Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{port}}}

	a := map[corev1.ServicePort][]resolvedBackend{
		port: {{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000001, BackendPort: 80, BackendSubnetId: 1}}},
	}
	b := map[corev1.ServicePort][]resolvedBackend{
		port: {{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000003, BackendPort: 80, BackendSubnetId: 1}}},
	}
	if backendSignature(svc, a) == backendSignature(svc, b) {
		t.Errorf("signature must change when backend IP changes")
	}
}
