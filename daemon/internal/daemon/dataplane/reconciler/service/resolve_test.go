package service

import (
	"context"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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

func TestFindPrimaryInterfaceForPod_PicksTheNICServiceTrafficLandsOn(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(juneau): %v", err)
	}
	extra := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.data0"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			PodRef:   juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-1", Name: "web", Interface: "data0"},
			NodeName: "node-a",
			Subnet:   "storage",
		},
	}
	primary := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web.eth0"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			PodRef:   juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-1", Name: "web", Interface: "eth0"},
			NodeName: "node-a",
			Subnet:   "web",
		},
	}
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(extra, primary).
		WithIndex(&juneauv1alpha1.NetworkInterface{}, "spec.podRef.name", func(obj client.Object) []string {
			return []string{obj.(*juneauv1alpha1.NetworkInterface).Spec.PodRef.Name}
		}).
		WithIndex(&juneauv1alpha1.NetworkInterface{}, "spec.podRef.interface", func(obj client.Object) []string {
			return []string{obj.(*juneauv1alpha1.NetworkInterface).Spec.PodRef.Interface}
		}).
		Build()

	r := &Reconciler{client: cl}
	got, err := r.findPrimaryInterfaceForPod(context.Background(), "default", "web")
	if err != nil {
		t.Fatalf("findPrimaryInterfaceForPod: %v", err)
	}
	if got == nil {
		t.Fatal("expected the primary NetworkInterface, got none")
	}
	if got.Spec.Subnet != "web" {
		t.Fatalf("got the NIC on subnet %q, want the primary NIC on %q", got.Spec.Subnet, "web")
	}
}

func TestFindPrimaryInterfaceForPod_PodWithoutPrimaryNIC(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(juneau): %v", err)
	}
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&juneauv1alpha1.NetworkInterface{}, "spec.podRef.name", func(obj client.Object) []string {
			return []string{obj.(*juneauv1alpha1.NetworkInterface).Spec.PodRef.Name}
		}).
		WithIndex(&juneauv1alpha1.NetworkInterface{}, "spec.podRef.interface", func(obj client.Object) []string {
			return []string{obj.(*juneauv1alpha1.NetworkInterface).Spec.PodRef.Interface}
		}).
		Build()

	r := &Reconciler{client: cl}
	got, err := r.findPrimaryInterfaceForPod(context.Background(), "default", "web")
	if err != nil {
		t.Fatalf("findPrimaryInterfaceForPod: %v", err)
	}
	if got != nil {
		t.Fatalf("expected no NetworkInterface, got %+v", got)
	}
}
