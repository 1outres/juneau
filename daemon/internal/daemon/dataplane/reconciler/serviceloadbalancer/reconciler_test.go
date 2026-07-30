package serviceloadbalancer

import (
	"context"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newFakeClient builds a controller-runtime fake client preloaded
// with the supplied objects and the field index the LB reconciler
// relies on (NetworkInterfaceAttachment.spec.podRef.name).
func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(juneau): %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(corev1): %v", err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(discoveryv1): %v", err)
	}
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithIndex(&juneauv1alpha1.NetworkInterfaceAttachment{}, "spec.podRef.name", func(obj client.Object) []string {
			attachment := obj.(*juneauv1alpha1.NetworkInterfaceAttachment)
			if attachment.Spec.PodRef.Name == "" {
				return nil
			}
			return []string{attachment.Spec.PodRef.Name}
		}).
		Build()
}

func newSLB(name, namespace, vip string, advertisingNodes []string, ports []juneauv1alpha1.ServiceLoadBalancerPort) *juneauv1alpha1.ServiceLoadBalancer {
	return &juneauv1alpha1.ServiceLoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: juneauv1alpha1.ServiceLoadBalancerSpec{
			ServiceRef:      juneauv1alpha1.ServiceLoadBalancerServiceReference{Name: name},
			ExternalNetwork: "public",
		},
		Status: juneauv1alpha1.ServiceLoadBalancerStatus{
			VIP:              vip,
			AdvertisingNodes: advertisingNodes,
			Ports:            ports,
		},
	}
}

func newParentService(name, namespace string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass:     ptr.To(juneauv1alpha1.LoadBalancerClass),
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			Selector:              map[string]string{"app": name},
		},
	}
}

func newSlice(svcName, sliceName, namespace string, eps []discoveryv1.Endpoint, ports []discoveryv1.EndpointPort) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: sliceName, Namespace: namespace,
			Labels: map[string]string{kubernetesServiceLabel: svcName},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       ports,
		Endpoints:   eps,
	}
}

func newJuneauPod(podName, namespace, ip, subnet string, vni uint32) []client.Object {
	subnetObj := &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: subnet},
		Status:     juneauv1alpha1.SubnetStatus{VNI: vni},
	}
	iface := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: podName + "-iface", Namespace: namespace},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			Subnet: subnet,
		},
	}
	attachment := &juneauv1alpha1.NetworkInterfaceAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: podName + "-attachment", Namespace: namespace},
		Spec: juneauv1alpha1.NetworkInterfaceAttachmentSpec{
			NetworkInterfaceRef: iface.Name,
			NodeName:            "node-a",
			PodRef: juneauv1alpha1.NetworkInterfaceAttachmentPodReference{
				UID:       "uid-" + podName,
				Name:      podName,
				Interface: "eth0",
			},
		},
	}
	_ = ip
	return []client.Object{subnetObj, iface, attachment}
}

func TestLBReconciler_ProgramsLocalBackends(t *testing.T) {
	t.Parallel()

	const ns, svcName, node = "app", "web", "node-a"
	ports := []juneauv1alpha1.ServiceLoadBalancerPort{
		{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: 8080},
	}
	slb := newSLB(svcName, ns, "203.0.113.10", []string{node, "node-c"}, ports)
	svc := newParentService(svcName, ns)
	objs := []client.Object{slb, svc}
	objs = append(objs, newJuneauPod("web-1", ns, "10.99.0.1", "subnet-a", 100)...)
	slice := newSlice(svcName, "web-slice-a", ns,
		[]discoveryv1.Endpoint{
			{
				Addresses:  []string{"10.99.0.1"},
				NodeName:   ptr.To(node),
				Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
				TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: "web-1"},
			},
			{
				Addresses:  []string{"10.99.0.2"},
				NodeName:   ptr.To("node-c"),
				Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
			},
		},
		[]discoveryv1.EndpointPort{
			{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(int32(8080))},
		},
	)
	objs = append(objs, slice)

	cl := newFakeClient(t, objs...)
	prog := NewInMemoryProgrammer()
	r := NewReconciler(cl, prog, node)

	if err := r.Reconcile(context.Background(), ns+"/"+svcName); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	snap := prog.Snapshot()
	got, ok := snap[ns+"/"+svcName]
	if !ok {
		t.Fatalf("expected programmer to record key %s/%s, got keys=%v", ns, svcName, snap)
	}
	if got.VIP.String() != "203.0.113.10" {
		t.Errorf("VIP: %s", got.VIP)
	}
	if !got.Advertising {
		t.Error("expected Advertising=true on advertising node")
	}
	if len(got.Ports) != 1 || got.Ports[0].Port != 80 || got.Ports[0].TargetPort != 8080 {
		t.Errorf("Ports: %+v", got.Ports)
	}
	if len(got.Backends) != 1 {
		t.Fatalf("Backends: want 1 (node-a only), got %d (%+v)", len(got.Backends), got.Backends)
	}
	if got.Backends[0].PodIP.String() != "10.99.0.1" || got.Backends[0].SubnetID != 100 {
		t.Errorf("Backend[0]: %+v", got.Backends[0])
	}
}

func TestLBReconciler_DropsHostNetworkBackends(t *testing.T) {
	t.Parallel()

	const ns, svcName, node = "app", "web", "node-a"
	slb := newSLB(svcName, ns, "203.0.113.10", []string{node},
		[]juneauv1alpha1.ServiceLoadBalancerPort{
			{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: 8080},
		},
	)
	svc := newParentService(svcName, ns)
	// No NetworkInterface for this Pod → host-network / non-Juneau.
	slice := newSlice(svcName, "web-slice-a", ns,
		[]discoveryv1.Endpoint{
			{
				Addresses:  []string{"10.99.0.1"},
				NodeName:   ptr.To(node),
				Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
				TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: "web-1"},
			},
		},
		[]discoveryv1.EndpointPort{
			{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(int32(8080))},
		},
	)

	cl := newFakeClient(t, slb, svc, slice)
	prog := NewInMemoryProgrammer()
	r := NewReconciler(cl, prog, node)
	if err := r.Reconcile(context.Background(), ns+"/"+svcName); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	snap := prog.Snapshot()[ns+"/"+svcName]
	if len(snap.Backends) != 0 {
		t.Errorf("expected 0 backends for host-network endpoint, got %v", snap.Backends)
	}
}

func TestLBReconciler_DeletesEntryWhenSLBGone(t *testing.T) {
	t.Parallel()

	const ns, svcName, node = "app", "web", "node-a"
	prog := NewInMemoryProgrammer()
	cl := newFakeClient(t)
	r := NewReconciler(cl, prog, node)

	// First, put something in the snapshot via direct Apply, then
	// reconcile the missing key — it must clear.
	_ = prog.Apply(ns+"/"+svcName, &LBService{Key: ns + "/" + svcName})
	if err := r.Reconcile(context.Background(), ns+"/"+svcName); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := prog.Snapshot()[ns+"/"+svcName]; ok {
		t.Errorf("expected programmer to drop key when SLB is gone")
	}
}

func TestLBReconciler_NotAdvertisingWhenNodeAbsent(t *testing.T) {
	t.Parallel()

	const ns, svcName, node = "app", "web", "node-a"
	slb := newSLB(svcName, ns, "203.0.113.10", []string{"node-c"},
		[]juneauv1alpha1.ServiceLoadBalancerPort{
			{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: 8080},
		},
	)
	svc := newParentService(svcName, ns)

	cl := newFakeClient(t, slb, svc)
	prog := NewInMemoryProgrammer()
	r := NewReconciler(cl, prog, node)
	if err := r.Reconcile(context.Background(), ns+"/"+svcName); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := prog.Snapshot()[ns+"/"+svcName]
	if got.Advertising {
		t.Error("expected Advertising=false on non-advertising node")
	}
}

func TestLBReconciler_NoEntryUntilVIPAllocated(t *testing.T) {
	t.Parallel()

	const ns, svcName, node = "app", "web", "node-a"
	// VIP empty → reconciler must clear (or never write) the entry.
	slb := newSLB(svcName, ns, "", []string{node},
		[]juneauv1alpha1.ServiceLoadBalancerPort{
			{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: 8080},
		},
	)
	svc := newParentService(svcName, ns)
	cl := newFakeClient(t, slb, svc)
	prog := NewInMemoryProgrammer()
	r := NewReconciler(cl, prog, node)
	if err := r.Reconcile(context.Background(), ns+"/"+svcName); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := prog.Snapshot()[ns+"/"+svcName]; ok {
		t.Error("expected no entry when VIP is empty")
	}
}
