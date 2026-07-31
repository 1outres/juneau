package trace

import (
	"context"
	"fmt"
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

func TestLookupPodVPCFollowsNetworkInterfaceAttachment(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "workload",
			UID:       "pod-uid",
		},
	}
	attachment := &juneauv1alpha1.NetworkInterfaceAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "workload",
			UID:       "attachment-uid",
		},
		Spec: juneauv1alpha1.NetworkInterfaceAttachmentSpec{
			NetworkInterfaceRef: "workload",
			PodRef: juneauv1alpha1.NetworkInterfaceAttachmentPodReference{
				Name: "workload",
				UID:  "pod-uid",
			},
		},
	}
	nic := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "workload"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			Subnet: "app-subnet",
			AttachmentRef: &juneauv1alpha1.NetworkInterfaceAttachmentReference{
				Name: attachment.Name,
				UID:  attachment.UID,
			},
		},
	}
	subnet := &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "app-subnet"},
		Spec:       juneauv1alpha1.SubnetSpec{Vpc: "app-vpc"},
	}
	vpc := &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: "app-vpc"},
		Status:     juneauv1alpha1.VpcStatus{VpcID: 42},
	}
	cl := fake.NewClientBuilder().
		WithScheme(newSchemeForTest(t)).
		WithObjects(pod, attachment, nic, subnet, vpc).
		Build()

	got, err := lookupPodVPC(context.Background(), cl, pod)
	if err != nil {
		t.Fatalf("lookupPodVPC: %v", err)
	}
	if got != 42 {
		t.Fatalf("VPC ID = %d, want 42", got)
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

func TestAppendReverseTuplesMirrorsEachForward(t *testing.T) {
	fwd := []juneauv1alpha1.TraceTuple{
		{Scope: juneauv1alpha1.TraceTupleScopeVPC, VPCID: 7, SrcIP: "10.0.1.5", DstIP: "10.96.0.10", DstPort: 443, Protocol: juneauv1alpha1.TraceProtocolTCP},
		{Scope: juneauv1alpha1.TraceTupleScopeVPC, VPCID: 7, SrcIP: "10.0.1.5", DstIP: "10.0.2.10", DstPort: 8443, Protocol: juneauv1alpha1.TraceProtocolTCP},
	}
	got := appendReverseTuples(fwd)
	if len(got) != 4 {
		t.Fatalf("expected 2 forward + 2 reverse = 4 tuples, got %d: %+v", len(got), got)
	}
	if got[0] != fwd[0] || got[1] != fwd[1] {
		t.Fatalf("forward tuples must be preserved in order, got %+v", got[:2])
	}
	rev := got[2]
	if rev.SrcIP != "10.96.0.10" || rev.DstIP != "10.0.1.5" {
		t.Errorf("reverse[0] src/dst not swapped: %+v", rev)
	}
	if rev.SrcPort != 0 || rev.DstPort != 0 {
		t.Errorf("reverse[0] ports must be wildcarded to 0: %+v", rev)
	}
	if rev.Scope != juneauv1alpha1.TraceTupleScopeVPC || rev.VPCID != 7 || rev.Protocol != juneauv1alpha1.TraceProtocolTCP {
		t.Errorf("reverse[0] must carry scope/vpc/proto: %+v", rev)
	}
	if rev.Direction != juneauv1alpha1.TraceTupleDirectionReply {
		t.Errorf("reverse[0] must be tagged Reply: %+v", rev)
	}
}

func TestAppendReverseTuplesSkipsSymmetricDuplicate(t *testing.T) {
	// A symmetric wildcard tuple (src==dst, ports 0) is its own reverse
	// and must not be duplicated.
	fwd := []juneauv1alpha1.TraceTuple{
		{Scope: juneauv1alpha1.TraceTupleScopeHost, SrcIP: "10.0.0.1", DstIP: "10.0.0.1", Protocol: juneauv1alpha1.TraceProtocolICMP},
	}
	got := appendReverseTuples(fwd)
	if len(got) != 1 {
		t.Fatalf("symmetric tuple must not add a reverse mirror, got %d: %+v", len(got), got)
	}
}

func TestAppendReverseTuplesRespectsMaxCap(t *testing.T) {
	fwd := make([]juneauv1alpha1.TraceTuple, maxInitialTuples)
	for i := range fwd {
		fwd[i] = juneauv1alpha1.TraceTuple{
			Scope:    juneauv1alpha1.TraceTupleScopeHost,
			SrcIP:    "10.0.1.5",
			DstIP:    fmt.Sprintf("10.0.2.%d", i+1),
			DstPort:  443,
			Protocol: juneauv1alpha1.TraceProtocolTCP,
		}
	}
	got := appendReverseTuples(fwd)
	if len(got) != maxInitialTuples {
		t.Fatalf("must stay within the admission cap of %d, got %d", maxInitialTuples, len(got))
	}
}

func TestResolveSessionAppendsReverseTuplesForIPTrace(t *testing.T) {
	o := &Options{
		SourceIP: "10.0.1.5",
		DestIP:   "10.0.2.8",
		Port:     443,
		Protocol: "tcp",
		traceID:  0x1234,
	}
	// IP -> IP resolution touches no Kubernetes objects, so a nil client
	// is sufficient.
	r, err := o.resolveSession(context.Background(), nil)
	if err != nil {
		t.Fatalf("resolveSession: %v", err)
	}
	if len(r.initialTuples) != 2 {
		t.Fatalf("expected forward + reverse = 2 tuples, got %d: %+v", len(r.initialTuples), r.initialTuples)
	}
	fwd, rev := r.initialTuples[0], r.initialTuples[1]
	if fwd.SrcIP != "10.0.1.5" || fwd.DstIP != "10.0.2.8" || fwd.DstPort != 443 {
		t.Fatalf("forward tuple wrong: %+v", fwd)
	}
	if fwd.Direction != juneauv1alpha1.TraceTupleDirectionRequest {
		t.Errorf("forward tuple must be tagged Request: %+v", fwd)
	}
	if rev.SrcIP != "10.0.2.8" || rev.DstIP != "10.0.1.5" || rev.DstPort != 0 {
		t.Fatalf("reverse tuple wrong: %+v", rev)
	}
	if rev.Direction != juneauv1alpha1.TraceTupleDirectionReply {
		t.Errorf("reverse tuple must be tagged Reply: %+v", rev)
	}
}
