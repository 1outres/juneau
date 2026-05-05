package trace

import (
	"context"
	"net/netip"
	"sort"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newSchemeForTest(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("corev1: %v", err)
	}
	if err := discoveryv1.AddToScheme(s); err != nil {
		t.Fatalf("discoveryv1: %v", err)
	}
	if err := juneauv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("juneauv1alpha1: %v", err)
	}
	return s
}

func ptrProto(p corev1.Protocol) *corev1.Protocol { return &p }
func ptrInt32(v int32) *int32                     { return &v }
func ptrString(v string) *string                  { return &v }
func ptrBool(v bool) *bool                        { return &v }

func TestServiceBackendTuplesSeedsBackendsWithTargetPort(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
				{Name: "metrics", Port: 9090, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "api-xyz",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "api"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports: []discoveryv1.EndpointPort{
			{Name: ptrString("https"), Port: ptrInt32(8443), Protocol: ptrProto(corev1.ProtocolTCP)},
			{Name: ptrString("metrics"), Port: ptrInt32(9090), Protocol: ptrProto(corev1.ProtocolTCP)},
		},
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses:  []string{"10.0.2.10"},
				Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
				NodeName:   ptrString("worker-2"),
			},
			{
				Addresses:  []string{"10.0.3.11"},
				Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
				NodeName:   ptrString("worker-3"),
			},
			{
				Addresses:  []string{"10.0.4.99"},
				Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(false)},
				NodeName:   ptrString("worker-9"),
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(newSchemeForTest(t)).WithObjects(svc, es).Build()

	o := &Options{Port: 443, Protocol: "tcp"}
	r := &resolved{
		source:      endpoint{ip: netip.MustParseAddr("10.0.1.5"), vpcID: 7},
		destination: endpoint{service: svc, ip: netip.MustParseAddr("10.96.0.10")},
	}

	tuples, nodes, err := o.serviceBackendTuples(context.Background(), cl, r)
	if err != nil {
		t.Fatalf("serviceBackendTuples: %v", err)
	}
	if len(tuples) != 2 {
		t.Fatalf("expected 2 ready-backend tuples, got %d: %+v", len(tuples), tuples)
	}
	for _, tup := range tuples {
		if tup.SrcIP != "10.0.1.5" {
			t.Errorf("SrcIP = %q, want 10.0.1.5", tup.SrcIP)
		}
		if tup.DstPort != 8443 {
			t.Errorf("DstPort = %d, want 8443 (target port for 'https')", tup.DstPort)
		}
		if tup.Protocol != juneauv1alpha1.TraceProtocolTCP {
			t.Errorf("Protocol = %q, want TCP", tup.Protocol)
		}
		if tup.VPCID != 7 || tup.Scope != juneauv1alpha1.TraceTupleScopeVPC {
			t.Errorf("scope/vpc = %v/%d", tup.Scope, tup.VPCID)
		}
	}

	sort.Strings(nodes)
	want := []string{"worker-2", "worker-3"}
	if len(nodes) != len(want) {
		t.Fatalf("nodes = %v, want %v", nodes, want)
	}
	for i := range want {
		if nodes[i] != want[i] {
			t.Fatalf("nodes[%d] = %q, want %q", i, nodes[i], want[i])
		}
	}
}

func TestServiceBackendTuplesReturnsNilWhenPortNotMatched(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(newSchemeForTest(t)).WithObjects(svc).Build()

	o := &Options{Port: 80, Protocol: "tcp"} // mismatched port
	r := &resolved{
		source:      endpoint{ip: netip.MustParseAddr("10.0.1.5"), vpcID: 7},
		destination: endpoint{service: svc},
	}
	tuples, nodes, err := o.serviceBackendTuples(context.Background(), cl, r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tuples != nil || nodes != nil {
		t.Fatalf("expected nil result for mismatched port, got tuples=%v nodes=%v", tuples, nodes)
	}
}

func TestServiceBackendTuplesIgnoresIPv6Slice(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP}},
		},
	}
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "api-v6",
			Labels: map[string]string{discoveryv1.LabelServiceName: "api"},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
		Ports: []discoveryv1.EndpointPort{
			{Name: ptrString("https"), Port: ptrInt32(8443), Protocol: ptrProto(corev1.ProtocolTCP)},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"fd00::1"}, Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(newSchemeForTest(t)).WithObjects(svc, es).Build()

	o := &Options{Port: 443, Protocol: "tcp"}
	r := &resolved{
		source:      endpoint{ip: netip.MustParseAddr("10.0.1.5"), vpcID: 7},
		destination: endpoint{service: svc},
	}
	tuples, _, err := o.serviceBackendTuples(context.Background(), cl, r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(tuples) != 0 {
		t.Fatalf("expected no IPv4 tuples for v6 slice, got %d", len(tuples))
	}
}

func TestMatchingServicePortNameICMPSkipped(t *testing.T) {
	svc := &corev1.Service{Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}},
	}}
	if _, ok := matchingServicePortName(svc, 80, "icmp"); ok {
		t.Fatalf("ICMP probes against Services should not pre-seed backends")
	}
}
