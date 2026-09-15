package grpc

import (
	"context"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestCNIServer(t *testing.T, objects ...client.Object) *CNIServer {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add juneau scheme: %v", err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	return newCNIServer(cl, cl, nil)
}

func TestPodInterfaceMTUFollowsTheNetworkOfTheNIC(t *testing.T) {
	segment := &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: "segment"},
		Status:     juneauv1alpha1.L2NetworkStatus{MTU: 1400},
	}
	server := newTestCNIServer(t, segment)

	for _, tc := range []struct {
		name string
		spec juneauv1alpha1.NetworkInterfaceSpec
		want int
	}{
		{name: "subnet", spec: juneauv1alpha1.NetworkInterfaceSpec{Subnet: "web"}, want: 0},
		{name: "l2Network", spec: juneauv1alpha1.NetworkInterfaceSpec{L2Network: "segment"}, want: 1400},
		{name: "elasticIP", spec: juneauv1alpha1.NetworkInterfaceSpec{ElasticIP: "public"}, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nwiface := &juneauv1alpha1.NetworkInterface{Spec: tc.spec}
			got, err := server.podInterfaceMTU(context.Background(), nwiface)
			if err != nil {
				t.Fatalf("podInterfaceMTU: %v", err)
			}
			if got != tc.want {
				t.Errorf("MTU = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPodInterfaceMTURejectsANICOnNoNetwork(t *testing.T) {
	server := newTestCNIServer(t)
	nwiface := &juneauv1alpha1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "web.eth0"}}
	if _, err := server.podInterfaceMTU(context.Background(), nwiface); err == nil {
		t.Fatal("expected an error for a NIC that names no network")
	}
}
