package trace

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func TestCrossVPCTuplesRescopesEachForward(t *testing.T) {
	fwd := []juneauv1alpha1.TraceTuple{
		{Scope: juneauv1alpha1.TraceTupleScopeVPC, VPCID: 7, SrcIP: "10.0.1.5", DstIP: "10.1.2.10", DstPort: 443, Protocol: juneauv1alpha1.TraceProtocolTCP, Direction: juneauv1alpha1.TraceTupleDirectionRequest},
		{Scope: juneauv1alpha1.TraceTupleScopeVPC, VPCID: 7, SrcIP: "10.0.1.5", DstIP: "10.1.2.11", DstPort: 8443, Protocol: juneauv1alpha1.TraceProtocolTCP, Direction: juneauv1alpha1.TraceTupleDirectionRequest},
	}

	got := crossVPCTuples(fwd, 9)
	if len(got) != 2 {
		t.Fatalf("expected one rescoped copy per forward tuple, got %d: %+v", len(got), got)
	}
	for i, tuple := range got {
		want := fwd[i]
		want.VPCID = 9
		if tuple != want {
			t.Errorf("copy %d = %+v, want %+v", i, tuple, want)
		}
	}
}

func TestCrossVPCTuplesSkipsSameVPC(t *testing.T) {
	fwd := []juneauv1alpha1.TraceTuple{
		{Scope: juneauv1alpha1.TraceTupleScopeVPC, VPCID: 7, SrcIP: "10.0.1.5", DstIP: "10.0.2.10", DstPort: 443, Protocol: juneauv1alpha1.TraceProtocolTCP},
	}

	if got := crossVPCTuples(fwd, 7); len(got) != 0 {
		t.Fatalf("a tuple already scoped to the Vpc must not be duplicated, got %+v", got)
	}
	if got := crossVPCTuples(fwd, 0); len(got) != 0 {
		t.Fatalf("an unresolved Vpc id must add nothing, got %+v", got)
	}
}

func TestCrossVPCTuplesRespectsMaxCap(t *testing.T) {
	fwd := make([]juneauv1alpha1.TraceTuple, maxInitialTuples)
	for i := range fwd {
		fwd[i] = juneauv1alpha1.TraceTuple{
			Scope:    juneauv1alpha1.TraceTupleScopeVPC,
			VPCID:    7,
			SrcIP:    "10.0.1.5",
			DstIP:    fmt.Sprintf("10.1.2.%d", i+1),
			DstPort:  443,
			Protocol: juneauv1alpha1.TraceProtocolTCP,
		}
	}

	if got := crossVPCTuples(fwd, 9); len(got) != 0 {
		t.Fatalf("must stay within the admission cap of %d, got %d extra tuples", maxInitialTuples, len(got))
	}
}

func TestResolveSessionScopesTuplesToBothVPCs(t *testing.T) {
	objects := []client.Object{
		crossVPCPod("client", "10.0.1.5", "uid-client", "worker-1"),
		crossVPCPod("server", "10.1.2.10", "uid-server", "worker-2"),
	}
	objects = append(objects, crossVPCNetwork("client", "uid-client", "subnet-a", "vpc-a", 7)...)
	objects = append(objects, crossVPCNetwork("server", "uid-server", "subnet-b", "vpc-b", 9)...)

	cl := fake.NewClientBuilder().WithScheme(newSchemeForTest(t)).WithObjects(objects...).Build()

	o := &Options{
		SourcePod:       "client",
		DestPod:         "server",
		sourceNamespace: "default",
		destNamespace:   "default",
		Port:            443,
		Protocol:        "tcp",
		traceID:         0x2345,
	}

	r, err := o.resolveSession(context.Background(), cl)
	if err != nil {
		t.Fatalf("resolveSession: %v", err)
	}

	requests := map[uint32]bool{}
	replies := map[uint32]bool{}
	for _, tuple := range r.initialTuples {
		switch tuple.Direction {
		case juneauv1alpha1.TraceTupleDirectionRequest:
			requests[tuple.VPCID] = true
		case juneauv1alpha1.TraceTupleDirectionReply:
			replies[tuple.VPCID] = true
		}
	}
	if !requests[7] || !requests[9] {
		t.Errorf("request tuples must cover both VPCs, got %+v", r.initialTuples)
	}
	if !replies[7] || !replies[9] {
		t.Errorf("reply mirrors must cover both VPCs, got %+v", r.initialTuples)
	}
}

func crossVPCPod(name, ip, uid, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID(uid)},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{PodIP: ip},
	}
}

func crossVPCNetwork(name, uid, subnet, vpc string, vpcID uint32) []client.Object {
	return []client.Object{
		&juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{
				PodRef: juneauv1alpha1.NetworkInterfacePodReference{UID: uid, Name: name, Interface: "eth0"},
				Subnet: subnet,
			},
		},
		&juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnet},
			Spec:       juneauv1alpha1.SubnetSpec{Vpc: vpc},
		},
		&juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpc},
			Status:     juneauv1alpha1.VpcStatus{VpcID: vpcID},
		},
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

func TestLookupPodVPCFollowsThePrimaryNIC(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web", UID: "uid-web"},
		Status:     corev1.PodStatus{PodIP: "10.16.0.5"},
	}
	objects := []client.Object{
		pod,
		&juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.data0"},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{
				PodRef: juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-web", Name: "web", Interface: "data0"},
				Subnet: "subnet-storage",
			},
		},
		&juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.eth0"},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{
				PodRef: juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-web", Name: "web", Interface: "eth0"},
				Subnet: "subnet-web",
			},
		},
		&juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: "subnet-web"},
			Spec:       juneauv1alpha1.SubnetSpec{Vpc: "vpc-web"},
		},
		&juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: "subnet-storage"},
			Spec:       juneauv1alpha1.SubnetSpec{Vpc: "vpc-storage"},
		},
		&juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc-web"}, Status: juneauv1alpha1.VpcStatus{VpcID: 7}},
		&juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc-storage"}, Status: juneauv1alpha1.VpcStatus{VpcID: 9}},
	}
	cl := fake.NewClientBuilder().WithScheme(newSchemeForTest(t)).WithObjects(objects...).Build()

	got, err := lookupPodVPC(context.Background(), cl, pod)
	if err != nil {
		t.Fatalf("lookupPodVPC: %v", err)
	}
	if got != 7 {
		t.Fatalf("got VPC id %d, want the id %d of the primary NIC", got, 7)
	}
}

func TestLookupPodVPCIgnoresAPodWithoutPrimaryNIC(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web", UID: "uid-web"},
	}
	objects := []client.Object{
		pod,
		&juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.data0"},
			Spec: juneauv1alpha1.NetworkInterfaceSpec{
				PodRef: juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-web", Name: "web", Interface: "data0"},
				Subnet: "subnet-storage",
			},
		},
		&juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: "subnet-storage"},
			Spec:       juneauv1alpha1.SubnetSpec{Vpc: "vpc-storage"},
		},
		&juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc-storage"}, Status: juneauv1alpha1.VpcStatus{VpcID: 9}},
	}
	cl := fake.NewClientBuilder().WithScheme(newSchemeForTest(t)).WithObjects(objects...).Build()

	if _, err := lookupPodVPC(context.Background(), cl, pod); err == nil {
		t.Fatal("expected an error when the pod has no primary NIC")
	}
}

// ---- NIC-scoped resolution ---------------------------------------------

func l2TraceObjects() []client.Object {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "lab-a", UID: "uid-lab-a"},
		Spec:       corev1.PodSpec{NodeName: "worker-1"},
		Status:     corev1.PodStatus{PodIP: "10.242.0.5"},
	}
	primary := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "lab-a.eth0"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			Subnet: "lab-subnet",
			PodRef: juneauv1alpha1.NetworkInterfacePodReference{
				Name: "lab-a", Interface: "eth0", UID: "uid-lab-a",
			},
		},
		Status: juneauv1alpha1.NetworkInterfaceStatus{Address: "10.242.0.5/24"},
	}
	// An L2Network without a CIDR hands out no address, so status is
	// empty and only the user knows what the workload picked.
	extra := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "lab-a.eth1"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			L2Network: "lab-net",
			PodRef: juneauv1alpha1.NetworkInterfacePodReference{
				Name: "lab-a", Interface: "eth1", UID: "uid-lab-a",
			},
		},
	}
	subnet := &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-subnet"},
		Spec:       juneauv1alpha1.SubnetSpec{Vpc: "lab-vpc", CIDR: "10.242.0.0/24"},
	}
	// The segment sits in a Vpc of its own, so a trace that read the
	// Vpc off the Pod instead of off the NIC comes back with 11 where
	// the L2 hooks stamp 22.
	l2net := &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-net"},
		Spec:       juneauv1alpha1.L2NetworkSpec{Vpc: "lab-l2-vpc"},
		Status:     juneauv1alpha1.L2NetworkStatus{VNI: 4242},
	}
	vpc := &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-vpc"},
		Status:     juneauv1alpha1.VpcStatus{VpcID: 11},
	}
	l2vpc := &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-l2-vpc"},
		Status:     juneauv1alpha1.VpcStatus{VpcID: 22},
	}
	return []client.Object{pod, primary, extra, subnet, l2net, vpc, l2vpc}
}

func newL2TraceClient(t *testing.T) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(newSchemeForTest(t)).WithObjects(l2TraceObjects()...).Build()
}

// The L2 hooks stamp their events with the Vpc of the L2Network, so a
// trace of that NIC has to carry the same id. Reading it off the Pod
// instead would give the Vpc of eth0's Subnet, which happens to match
// here only because both sit in one Vpc — the address would not.
func TestResolveSessionScopesToTheNamedNIC(t *testing.T) {
	cl := newL2TraceClient(t)
	o := &Options{
		SourcePod:       "default/lab-a",
		SourceInterface: "eth1",
		SourceIP:        "192.168.60.1",
		DestIP:          "192.168.60.2",
		Protocol:        "icmp",
		sourceNamespace: "default",
		destNamespace:   "default",
		traceID:         1,
	}

	r, err := o.resolveSession(context.Background(), cl)
	if err != nil {
		t.Fatalf("resolveSession: %v", err)
	}
	if r.source.vpcID != 22 {
		t.Errorf("source vpcID = %d, want the Vpc of the L2Network (22)", r.source.vpcID)
	}
	if got := r.source.ip.String(); got != "192.168.60.1" {
		t.Errorf("source ip = %q, want the address the user gave", got)
	}
	if r.source.nodeName != "worker-1" {
		t.Errorf("source node = %q, want worker-1", r.source.nodeName)
	}
	if len(r.initialTuples) == 0 {
		t.Fatal("no tuples")
	}
	first := r.initialTuples[0]
	if first.Scope != juneauv1alpha1.TraceTupleScopeVPC || first.VPCID != 22 {
		t.Errorf("primary tuple scope/vpc = %v/%d, want VPC/22", first.Scope, first.VPCID)
	}
	if first.SrcIP != "192.168.60.1" || first.DstIP != "192.168.60.2" {
		t.Errorf("primary tuple = %s -> %s", first.SrcIP, first.DstIP)
	}
}

// Without an address the trace has nothing to key on. Saying so, and
// naming the flag that fixes it, beats keying the session on the
// address of a NIC the user did not ask about.
func TestResolveSessionAsksForAnAddressAnL2NetworkNeverHandedOut(t *testing.T) {
	cl := newL2TraceClient(t)
	o := &Options{
		SourcePod:       "default/lab-a",
		SourceInterface: "eth1",
		DestIP:          "192.168.60.2",
		Protocol:        "icmp",
		sourceNamespace: "default",
		destNamespace:   "default",
		traceID:         1,
	}

	_, err := o.resolveSession(context.Background(), cl)
	if err == nil {
		t.Fatal("expected an error when the NIC carries no address")
	}
	if !strings.Contains(err.Error(), "--from-ip") {
		t.Errorf("error should name the flag that fixes it, got %v", err)
	}
}

// A NIC on a Subnet needs no --from-ip: juneau handed it an address
// and writes it on the NetworkInterface.
func TestResolveSessionReadsTheAddressOfANicOnASubnet(t *testing.T) {
	cl := newL2TraceClient(t)
	o := &Options{
		SourcePod:       "default/lab-a",
		SourceInterface: "eth0",
		DestIP:          "10.242.0.9",
		Protocol:        "icmp",
		sourceNamespace: "default",
		destNamespace:   "default",
		traceID:         1,
	}

	r, err := o.resolveSession(context.Background(), cl)
	if err != nil {
		t.Fatalf("resolveSession: %v", err)
	}
	if got := r.source.ip.String(); got != "10.242.0.5" {
		t.Errorf("source ip = %q, want the address on the NetworkInterface", got)
	}
	if r.source.vpcID != 11 {
		t.Errorf("source vpcID = %d, want 11", r.source.vpcID)
	}
}

// A NIC the Pod does not have is a mistake in the command, not a
// reason to answer about a different NIC.
func TestResolveSessionRejectsANicThePodDoesNotHave(t *testing.T) {
	cl := newL2TraceClient(t)
	o := &Options{
		SourcePod:       "default/lab-a",
		SourceInterface: "eth7",
		DestIP:          "10.242.0.9",
		Protocol:        "icmp",
		sourceNamespace: "default",
		destNamespace:   "default",
		traceID:         1,
	}

	_, err := o.resolveSession(context.Background(), cl)
	if err == nil {
		t.Fatal("expected an error for a NIC the pod does not have")
	}
	if !strings.Contains(err.Error(), "eth7") {
		t.Errorf("error should name the NIC that is missing, got %v", err)
	}
}

// Naming no NIC keeps what the command has always done: the Pod's own
// address, and the Vpc of the network its primary NIC joined.
func TestResolveSessionWithoutANicTracesThePodItself(t *testing.T) {
	cl := newL2TraceClient(t)
	o := &Options{
		SourcePod:       "default/lab-a",
		DestIP:          "10.242.0.9",
		Protocol:        "icmp",
		sourceNamespace: "default",
		destNamespace:   "default",
		traceID:         1,
	}

	r, err := o.resolveSession(context.Background(), cl)
	if err != nil {
		t.Fatalf("resolveSession: %v", err)
	}
	if got := r.source.ip.String(); got != "10.242.0.5" {
		t.Errorf("source ip = %q, want the pod address", got)
	}
	if r.source.vpcID != 11 {
		t.Errorf("source vpcID = %d, want 11", r.source.vpcID)
	}
	if r.source.ifname != "" {
		t.Errorf("ifname = %q, want empty", r.source.ifname)
	}
}

// The destination side takes the same pair of flags, so a trace of one
// L2 segment can name both ends of it.
func TestResolveSessionScopesTheDestinationNICToo(t *testing.T) {
	cl := newL2TraceClient(t)
	peer := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "lab-b", UID: "uid-lab-b"},
		Spec:       corev1.PodSpec{NodeName: "worker-2"},
		Status:     corev1.PodStatus{PodIP: "10.242.0.6"},
	}
	peerNIC := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "lab-b.eth1"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			L2Network: "lab-net",
			PodRef: juneauv1alpha1.NetworkInterfacePodReference{
				Name: "lab-b", Interface: "eth1", UID: "uid-lab-b",
			},
		},
	}
	if err := cl.Create(context.Background(), peer); err != nil {
		t.Fatalf("create peer pod: %v", err)
	}
	if err := cl.Create(context.Background(), peerNIC); err != nil {
		t.Fatalf("create peer nic: %v", err)
	}

	o := &Options{
		SourcePod:       "default/lab-a",
		SourceInterface: "eth1",
		SourceIP:        "192.168.60.1",
		DestPod:         "default/lab-b",
		DestInterface:   "eth1",
		DestIP:          "192.168.60.2",
		Protocol:        "icmp",
		sourceNamespace: "default",
		destNamespace:   "default",
		traceID:         1,
	}

	r, err := o.resolveSession(context.Background(), cl)
	if err != nil {
		t.Fatalf("resolveSession: %v", err)
	}
	if r.destination.vpcID != 22 {
		t.Errorf("destination vpcID = %d, want the Vpc of the L2Network (22)", r.destination.vpcID)
	}
	if got := r.destination.ip.String(); got != "192.168.60.2" {
		t.Errorf("destination ip = %q", got)
	}
	sort.Strings(r.nodes)
	if len(r.nodes) != 2 || r.nodes[0] != "worker-1" || r.nodes[1] != "worker-2" {
		t.Errorf("nodes = %v, want both worker-1 and worker-2", r.nodes)
	}
}

func TestNicAddressReadsBothFormsAndReportsNone(t *testing.T) {
	for _, tt := range []struct {
		name  string
		raw   string
		want  string
		valid bool
	}{
		{name: "cidr", raw: "10.242.0.5/24", want: "10.242.0.5", valid: true},
		{name: "bare", raw: "10.242.0.5", want: "10.242.0.5", valid: true},
		{name: "none", raw: "", valid: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nwif := &juneauv1alpha1.NetworkInterface{
				ObjectMeta: metav1.ObjectMeta{Name: "lab-a.eth1"},
				Status:     juneauv1alpha1.NetworkInterfaceStatus{Address: tt.raw},
			}
			addr, err := nicAddress(nwif)
			if err != nil {
				t.Fatalf("nicAddress: %v", err)
			}
			if addr.IsValid() != tt.valid {
				t.Fatalf("valid = %t, want %t", addr.IsValid(), tt.valid)
			}
			if tt.valid && addr.String() != tt.want {
				t.Errorf("addr = %q, want %q", addr.String(), tt.want)
			}
		})
	}
}

func TestNicAddressRejectsSomethingItCannotRead(t *testing.T) {
	nwif := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-a.eth1"},
		Status:     juneauv1alpha1.NetworkInterfaceStatus{Address: "not-an-address"},
	}
	if _, err := nicAddress(nwif); err == nil {
		t.Fatal("expected an error for an unreadable address")
	}
}
