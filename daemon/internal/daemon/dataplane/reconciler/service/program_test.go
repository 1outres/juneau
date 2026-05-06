package service

import (
	"encoding/binary"
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// hostU32 turns a dotted-quad string into the host-order uint32 used as
// the ClusterIp / VIP key throughout the BPF service maps.
func hostU32(t *testing.T, ip string) uint32 {
	t.Helper()
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		t.Fatalf("invalid IPv4 %q", ip)
	}
	return binary.BigEndian.Uint32(v4)
}

func makeServiceWithExternalIPs(name, ns, vpc, clusterIP string, externalIPs []string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: map[string]string{"juneau.loutres.me/vpc": vpc},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:   clusterIP,
			ClusterIPs:  []string{clusterIP},
			Ports:       []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}},
			ExternalIPs: externalIPs,
		},
	}
}

func TestVipsForService_ClusterIPOnly(t *testing.T) {
	svc := makeServiceWithExternalIPs("web", "app", "default", "10.96.0.10", nil)
	primary := hostU32(t, "10.96.0.10")

	got := vipsForService(svc, primary)
	if len(got) != 1 || got[0] != primary {
		t.Fatalf("want [primary], got %v", got)
	}
}

func TestVipsForService_AddsIPv4ExternalIPs(t *testing.T) {
	svc := makeServiceWithExternalIPs("web", "app", "default", "10.96.0.10",
		[]string{"192.0.2.10", "192.0.2.11"})
	primary := hostU32(t, "10.96.0.10")

	got := vipsForService(svc, primary)
	want := []uint32{
		primary,
		hostU32(t, "192.0.2.10"),
		hostU32(t, "192.0.2.11"),
	}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("vip[%d]: got %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestVipsForService_DedupesPrimaryAndDuplicates(t *testing.T) {
	// externalIPs contains the clusterIP as well as a duplicated entry —
	// each VIP must appear only once so the program snapshot stays
	// minimal and BPF map updates are not redundant.
	svc := makeServiceWithExternalIPs("web", "app", "default", "10.96.0.10",
		[]string{"10.96.0.10", "192.0.2.10", "192.0.2.10"})
	primary := hostU32(t, "10.96.0.10")

	got := vipsForService(svc, primary)
	if len(got) != 2 {
		t.Fatalf("want 2 unique VIPs, got %d (%v)", len(got), got)
	}
	want := []uint32{primary, hostU32(t, "192.0.2.10")}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("vip[%d]: got %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestVipsForService_SkipsNonIPv4(t *testing.T) {
	// IPv6 / malformed entries are skipped so the rest of the Service
	// still programmes correctly. Order of valid entries is preserved.
	svc := makeServiceWithExternalIPs("web", "app", "default", "10.96.0.10",
		[]string{"::1", "not-an-ip", "192.0.2.10"})
	primary := hostU32(t, "10.96.0.10")

	got := vipsForService(svc, primary)
	want := []uint32{primary, hostU32(t, "192.0.2.10")}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("vip[%d]: got %#x, want %#x", i, got[i], want[i])
		}
	}
}

// backendSignature must be invariant to externalIPs because affinity
// bindings are keyed per-VIP — adding an externalIP to an existing
// Service should not bump service_val.gen and break sticky bindings on
// the existing ClusterIP.
func TestBackendSignature_StableAcrossExternalIPsChange(t *testing.T) {
	port := corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP}
	mkSvc := func(extIPs []string) *corev1.Service {
		return &corev1.Service{
			Spec: corev1.ServiceSpec{
				Ports:       []corev1.ServicePort{port},
				ExternalIPs: extIPs,
			},
		}
	}
	backends := map[corev1.ServicePort][]resolvedBackend{
		port: {
			{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000001, BackendPort: 80, BackendSubnetId: 1}},
			{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000002, BackendPort: 80, BackendSubnetId: 1}},
		},
	}

	noExt := backendSignature(mkSvc(nil), 0, 0, backends)
	withExt := backendSignature(mkSvc([]string{"192.0.2.10"}), 0, 0, backends)
	withMore := backendSignature(mkSvc([]string{"192.0.2.10", "192.0.2.11"}), 0, 0, backends)
	if noExt != withExt || withExt != withMore {
		t.Errorf("backendSignature must not depend on externalIPs (gen would bump and break affinity)")
	}
}
