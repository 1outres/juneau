package service

import (
	"encoding/binary"
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/svcpolicy"
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

func makeLBService(name, ns, vpc, clusterIP string, ingressIPs []string, externalIPs []string) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Annotations: map[string]string{
				"juneau.loutres.me/vpc":                           vpc,
				juneauv1alpha1.ServiceAnnotationLBExternalNetwork: "ext-net",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To(juneauv1alpha1.ServiceLoadBalancerClass),
			ClusterIP:         clusterIP,
			ClusterIPs:        []string{clusterIP},
			Ports:             []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}},
			ExternalIPs:       externalIPs,
		},
	}
	for _, ip := range ingressIPs {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress,
			corev1.LoadBalancerIngress{IP: ip, IPMode: ptr.To(corev1.LoadBalancerIPModeVIP)})
	}
	return svc
}

func TestVipsForService_IncludesLoadBalancerIngress(t *testing.T) {
	svc := makeLBService("web", "app", "default", "10.96.0.10",
		[]string{"203.0.113.5"}, nil)
	primary := hostU32(t, "10.96.0.10")

	got := vipsForService(svc, primary)
	want := []uint32{primary, hostU32(t, "203.0.113.5")}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("vip[%d]: got %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestVipsForService_DedupsLBIngressAgainstExternalIPs(t *testing.T) {
	// LB controllers are free to set the same IP in spec.externalIPs and
	// status.loadBalancer.ingress (e.g. when migrating from manual EIP
	// to LB-managed addressing). The data plane must collapse them so
	// service_map writes don't duplicate the snapshot.
	shared := "203.0.113.5"
	svc := makeLBService("web", "app", "default", "10.96.0.10",
		[]string{shared}, []string{shared})
	primary := hostU32(t, "10.96.0.10")

	got := vipsForService(svc, primary)
	want := []uint32{primary, hostU32(t, shared)}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d, want %d (%v)", len(got), len(want), got)
	}
}

func TestVipsForService_SkipsIngressEntriesWithoutIPv4(t *testing.T) {
	// Hostname-only ingress entries (some upstream LB controllers emit
	// these for DNS-fronted LBs) and IPv6 entries must not crash the
	// programmer. They are silently dropped because the BPF data path
	// only handles IPv4.
	svc := makeLBService("web", "app", "default", "10.96.0.10",
		[]string{"::1", ""}, nil)
	svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress,
		corev1.LoadBalancerIngress{Hostname: "lb.example.com"})
	primary := hostU32(t, "10.96.0.10")

	got := vipsForService(svc, primary)
	if len(got) != 1 || got[0] != primary {
		t.Fatalf("expected only primary VIP, got %v", got)
	}
}

func TestServiceFlags_LoadBalancerSetWhenIngressPresent(t *testing.T) {
	svc := makeLBService("web", "app", "default", "10.96.0.10",
		[]string{"203.0.113.5"}, nil)
	flags := serviceFlags(svc, svcpolicy.BackendSelectionPolicy{}, false)
	if flags&svcFlagLoadBalancer == 0 {
		t.Errorf("expected SVC_FLAG_LOAD_BALANCER set; got flags=%#x", flags)
	}
}

func TestServiceFlags_NoLoadBalancerForClusterIP(t *testing.T) {
	svc := makeServiceWithExternalIPs("web", "app", "default", "10.96.0.10", nil)
	flags := serviceFlags(svc, svcpolicy.BackendSelectionPolicy{}, false)
	if flags&svcFlagLoadBalancer != 0 {
		t.Errorf("ClusterIP Service must not carry SVC_FLAG_LOAD_BALANCER; got flags=%#x", flags)
	}
}

func TestServiceFlags_NoLoadBalancerWhenIngressEmpty(t *testing.T) {
	// A type=LoadBalancer Service whose ingress has not been allocated
	// yet must not announce itself as ready: the flag is what tells the
	// node_ingress fast path to start serving the VIP, and serving an
	// unallocated IP would silently drop external traffic.
	svc := makeLBService("web", "app", "default", "10.96.0.10", nil, nil)
	flags := serviceFlags(svc, svcpolicy.BackendSelectionPolicy{}, false)
	if flags&svcFlagLoadBalancer != 0 {
		t.Errorf("LB Service without ingress must not carry SVC_FLAG_LOAD_BALANCER; got flags=%#x", flags)
	}
}

// TestBackendSignature_StableAcrossLBIngressChange asserts the same
// invariant as TestBackendSignature_StableAcrossExternalIPsChange but
// for status.loadBalancer.ingress: rotating the LB ingress IP set must
// not bump gen on its own, because affinity is keyed (vip, client) and
// existing bindings on the ClusterIP must survive an LB IP swap. The
// LOAD_BALANCER flag transition is the legitimate gen-bump trigger and
// is exercised by TestBackendSignature_BumpsOnLoadBalancerActivation.
func TestBackendSignature_StableAcrossLBIngressChange(t *testing.T) {
	port := corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP}
	mkSvc := func(ingress []string) *corev1.Service {
		svc := &corev1.Service{
			Spec: corev1.ServiceSpec{
				Type:  corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{port},
			},
		}
		for _, ip := range ingress {
			svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress,
				corev1.LoadBalancerIngress{IP: ip})
		}
		return svc
	}
	backends := map[corev1.ServicePort][]resolvedBackend{
		port: {
			{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000001, BackendPort: 80, BackendSubnetId: 1}},
		},
	}
	// Pin the LOAD_BALANCER flag on for both samples so we isolate the
	// signature's reaction to ingress IP churn from its reaction to the
	// flag itself.
	one := backendSignature(mkSvc([]string{"203.0.113.5"}), svcFlagLoadBalancer, 0, backends)
	two := backendSignature(mkSvc([]string{"203.0.113.6"}), svcFlagLoadBalancer, 0, backends)
	more := backendSignature(mkSvc([]string{"203.0.113.5", "203.0.113.6"}), svcFlagLoadBalancer, 0, backends)
	if one != two || two != more {
		t.Errorf("backendSignature must be invariant to LB ingress IP changes")
	}
}

func TestBackendSignature_BumpsOnLoadBalancerActivation(t *testing.T) {
	port := corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP}
	svc := &corev1.Service{Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{port}}}
	backends := map[corev1.ServicePort][]resolvedBackend{
		port: {
			{val: bpf.PodEgressBackendVal{BackendIp: 0x0a000001, BackendPort: 80, BackendSubnetId: 1}},
		},
	}
	pre := backendSignature(svc, 0, 0, backends)
	post := backendSignature(svc, svcFlagLoadBalancer, 0, backends)
	if pre == post {
		t.Errorf("backendSignature must bump gen when SVC_FLAG_LOAD_BALANCER toggles")
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
