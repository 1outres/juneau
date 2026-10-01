package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNDoesNotAdvertiseServicesWithoutSourcePreservingReturnPath(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = juneau.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = discoveryv1.AddToScheme(scheme)
	ready := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "customer"}, Spec: juneau.VpcSpec{Service: &juneau.VpcServiceSpec{Consume: true}}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant"}, Spec: juneau.VPNSpec{Vpc: "customer", Subnet: "inside"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "inside", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "customer", CIDR: "10.0.0.0/24"}, Status: juneau.SubnetStatus{Conditions: ready}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "customer"}, Status: juneau.RouteTableStatus{Conditions: ready, Routes: []juneau.Route{{Dst: "10.0.0.0/24", Subnet: "inside", Via: juneau.RouteVia{Type: juneau.ViaConnected}}, {Dst: "10.96.0.0/12", Via: juneau.RouteVia{Type: juneau.ViaService}}}}}
	own := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "own", Namespace: "ns", Annotations: map[string]string{"juneau.loutres.me/vpc": "customer"}}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.10"}}
	shared := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "ns", Annotations: map[string]string{"juneau.loutres.me/vpc": "other", "juneau.loutres.me/shared-service": "true", "juneau.loutres.me/shared-service-allowed-consumer-vpcs": " customer , another "}}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.11"}}
	denied := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "denied", Namespace: "ns", Annotations: map[string]string{"juneau.loutres.me/vpc": "other", "juneau.loutres.me/shared-service": "true", "juneau.loutres.me/shared-service-allowed-consumer-vpcs": "another"}}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.12"}}
	private := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "private", Namespace: "ns", Annotations: map[string]string{"juneau.loutres.me/vpc": "other"}}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.13"}}
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, vpn, subnet, table, own, shared, denied, private).Build()}
	_, adv, err := r.gatewayRoutes(context.Background(), vpn, vpc, subnet)
	if err != nil {
		t.Fatal(err)
	}
	if len(adv) != 1 || adv[0] != "10.0.0.0/24" {
		t.Fatalf("advertised %v", adv)
	}
}
