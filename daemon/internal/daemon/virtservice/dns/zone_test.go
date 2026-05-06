package dns

import (
	"context"
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/1outres/juneau/daemon/internal/daemon/svcpolicy"
)

func newFakeClient(t *testing.T, objs ...runtime.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	_ = scheme.AddToScheme(s)
	return fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objs...).Build()
}

func makeService(ns, name, clusterIP string, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  clusterIP,
			ClusterIPs: []string{clusterIP},
		},
	}
}

func TestClusterZoneResolvesSameVPCService(t *testing.T) {
	cl := newFakeClient(t,
		makeService("ns1", "demo", "10.96.1.5",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "demo.ns1.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-a",
		CallerServiceEnabled: true,
		CallerConsume:        true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNoError {
		t.Fatalf("rcode = %d, want NoError", res.RCode)
	}
	if !res.Authoritative {
		t.Fatalf("expected authoritative response")
	}
	if len(res.Answers) != 1 {
		t.Fatalf("answers = %d, want 1: %+v", len(res.Answers), res.Answers)
	}
	if res.Answers[0].A != netip.MustParseAddr("10.96.1.5") {
		t.Errorf("A = %s, want 10.96.1.5", res.Answers[0].A)
	}
}

func TestClusterZoneSkipsOutOfZone(t *testing.T) {
	cl := newFakeClient(t)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	_, err := z.Resolve(context.Background(), Query{
		Name:  "example.com.",
		Type:  TypeA,
		Class: ClassINET,
	})
	if err != ErrNotInZone {
		t.Fatalf("expected ErrNotInZone, got %v", err)
	}
}

func TestClusterZoneAcrossVPCDeniedNXDomain(t *testing.T) {
	cl := newFakeClient(t,
		makeService("ns1", "demo", "10.96.1.5",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "demo.ns1.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-b",
		CallerServiceEnabled: true,
		CallerConsume:        true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNXDomain {
		t.Errorf("rcode = %d, want NXDomain (cross-VPC leak protection)", res.RCode)
	}
}

func TestClusterZoneSharedServiceAcrossVPC(t *testing.T) {
	cl := newFakeClient(t,
		makeService("ns1", "demo", "10.96.1.5", map[string]string{
			svcpolicy.AnnotationVpc:    "default",
			svcpolicy.AnnotationShared: "true",
		}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "demo.ns1.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-b",
		CallerServiceEnabled: true,
		CallerConsume:        true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNoError {
		t.Errorf("rcode = %d, want NoError for shared service", res.RCode)
	}
	if len(res.Answers) != 1 {
		t.Errorf("answers = %d", len(res.Answers))
	}
}

func TestClusterZoneServiceEnabledOff(t *testing.T) {
	cl := newFakeClient(t,
		makeService("ns1", "demo", "10.96.1.5",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "demo.ns1.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-a",
		CallerServiceEnabled: false,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNXDomain {
		t.Errorf("rcode = %d, want NXDomain when service routing is disabled", res.RCode)
	}
}

func TestClusterZoneAAAAReturnsNoData(t *testing.T) {
	cl := newFakeClient(t,
		makeService("ns1", "demo", "10.96.1.5", nil),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "demo.ns1.svc.cluster.local.",
		Type:                 TypeAAAA,
		Class:                ClassINET,
		CallerVPC:            "default",
		CallerServiceEnabled: true,
		CallerConsume:        true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNoError {
		t.Errorf("rcode = %d, want NoError (NODATA) for AAAA", res.RCode)
	}
	if len(res.Answers) != 0 {
		t.Errorf("answers = %d, want 0", len(res.Answers))
	}
}

func makeExternalNameService(ns, name, externalName string, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: externalName,
		},
	}
}

func TestClusterZoneResolvesExternalNameSameVPC(t *testing.T) {
	cl := newFakeClient(t,
		makeExternalNameService("app", "my-rds", "prod.rds.example.com",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "my-rds.app.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-a",
		CallerServiceEnabled: true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNoError {
		t.Fatalf("rcode = %d, want NoError", res.RCode)
	}
	if !res.Authoritative {
		t.Fatalf("expected authoritative response")
	}
	if len(res.Answers) != 1 {
		t.Fatalf("answers = %d, want 1: %+v", len(res.Answers), res.Answers)
	}
	a := res.Answers[0]
	if a.Type != TypeCNAME {
		t.Errorf("answer type = %d, want CNAME (%d)", a.Type, TypeCNAME)
	}
	if a.CNAME != "prod.rds.example.com." {
		t.Errorf("CNAME = %q, want %q", a.CNAME, "prod.rds.example.com.")
	}
}

func TestClusterZoneResolvesExternalNameAAAA(t *testing.T) {
	// Pod stub resolvers re-query the CNAME target for AAAA; the
	// upstream forwarder takes care of the actual answer. We must
	// still hand back the CNAME RR (not NODATA) for AAAA.
	cl := newFakeClient(t,
		makeExternalNameService("app", "my-rds", "prod.rds.example.com",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "my-rds.app.svc.cluster.local.",
		Type:                 TypeAAAA,
		Class:                ClassINET,
		CallerVPC:            "tenant-a",
		CallerServiceEnabled: true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNoError {
		t.Fatalf("rcode = %d, want NoError", res.RCode)
	}
	if len(res.Answers) != 1 {
		t.Fatalf("answers = %d, want 1: %+v", len(res.Answers), res.Answers)
	}
	if res.Answers[0].Type != TypeCNAME {
		t.Errorf("answer type = %d, want CNAME", res.Answers[0].Type)
	}
}

func TestClusterZoneExternalNameAcrossVPCDeniedNXDomain(t *testing.T) {
	// Same leak-protection contract as ClusterIP services: a
	// non-shared ExternalName must look identical to a missing
	// Service from another VPC.
	cl := newFakeClient(t,
		makeExternalNameService("app", "my-rds", "prod.rds.example.com",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "my-rds.app.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-b",
		CallerServiceEnabled: true,
		CallerConsume:        true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNXDomain {
		t.Errorf("rcode = %d, want NXDomain (cross-VPC leak protection)", res.RCode)
	}
}

func TestClusterZoneExternalNameSharedAcrossVPC(t *testing.T) {
	cl := newFakeClient(t,
		makeExternalNameService("app", "my-rds", "prod.rds.example.com", map[string]string{
			svcpolicy.AnnotationVpc:    "default",
			svcpolicy.AnnotationShared: "true",
		}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "my-rds.app.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-b",
		CallerServiceEnabled: true,
		CallerConsume:        true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNoError {
		t.Fatalf("rcode = %d, want NoError for shared ExternalName", res.RCode)
	}
	if len(res.Answers) != 1 || res.Answers[0].Type != TypeCNAME {
		t.Fatalf("expected single CNAME answer, got %+v", res.Answers)
	}
	if res.Answers[0].CNAME != "prod.rds.example.com." {
		t.Errorf("CNAME = %q, want %q", res.Answers[0].CNAME, "prod.rds.example.com.")
	}
}

func TestClusterZoneExternalNameEmptyTargetNXDomain(t *testing.T) {
	cl := newFakeClient(t,
		makeExternalNameService("app", "my-rds", "",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "my-rds.app.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-a",
		CallerServiceEnabled: true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNXDomain {
		t.Errorf("rcode = %d, want NXDomain for empty externalName", res.RCode)
	}
}

func TestClusterZoneExternalNameSingleLabelNXDomain(t *testing.T) {
	// Single-label targets would be expanded by the Pod stub
	// resolver's search list to surprising names; treat them as
	// misconfigured and refuse to leak.
	cl := newFakeClient(t,
		makeExternalNameService("app", "my-rds", "foo",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "my-rds.app.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-a",
		CallerServiceEnabled: true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNXDomain {
		t.Errorf("rcode = %d, want NXDomain for single-label externalName", res.RCode)
	}
}

func TestClusterZoneExternalNameTrailingDotPreserved(t *testing.T) {
	cl := newFakeClient(t,
		makeExternalNameService("app", "my-rds", "foo.bar.",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "my-rds.app.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-a",
		CallerServiceEnabled: true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNoError {
		t.Fatalf("rcode = %d, want NoError", res.RCode)
	}
	if len(res.Answers) != 1 || res.Answers[0].CNAME != "foo.bar." {
		t.Errorf("CNAME = %+v, want single answer with %q", res.Answers, "foo.bar.")
	}
}

func TestClusterZoneExternalNameServiceEnabledOff(t *testing.T) {
	// ServiceEnabled=false short-circuits in svcpolicy regardless of
	// Service type; ExternalName must follow that contract too so
	// the data-plane / DNS stories stay aligned.
	cl := newFakeClient(t,
		makeExternalNameService("app", "my-rds", "prod.rds.example.com",
			map[string]string{svcpolicy.AnnotationVpc: "tenant-a"}),
	)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "my-rds.app.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "tenant-a",
		CallerServiceEnabled: false,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNXDomain {
		t.Errorf("rcode = %d, want NXDomain when service routing is disabled", res.RCode)
	}
}

func TestClusterZoneHeadlessServiceNoData(t *testing.T) {
	svc := makeService("ns1", "headless", corev1.ClusterIPNone, nil)
	cl := newFakeClient(t, svc)
	z := NewClusterZone(cl, DefaultClusterDomain, 30)

	res, err := z.Resolve(context.Background(), Query{
		Name:                 "headless.ns1.svc.cluster.local.",
		Type:                 TypeA,
		Class:                ClassINET,
		CallerVPC:            "default",
		CallerServiceEnabled: true,
		CallerConsume:        true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeNoError || len(res.Answers) != 0 {
		t.Errorf("expected NODATA for headless, got rcode=%d, answers=%d", res.RCode, len(res.Answers))
	}
}
