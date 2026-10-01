package controller

import (
	"context"
	"reflect"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNDefaultRouteKeepsLocalServiceAdvertisementWhenReady(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{juneau.AddToScheme, corev1.AddToScheme, discoveryv1.AddToScheme} {
		if err := register(scheme); err != nil {
			t.Fatal(err)
		}
	}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant"}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "inside"}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Spec: juneau.VpcSpec{Service: &juneau.VpcServiceSpec{Consume: true}}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "inside", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.215.10.0/24"}, Status: juneau.SubnetStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	vpnRoute := juneau.Route{Dst: "0.0.0.0/0", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "tenant", Name: "branch"}}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{vpnRoute}}, Status: juneau.RouteTableStatus{PendingVPN: "tenant/branch", Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, Reason: routeTableReasonVPNEndpointPending, ObservedGeneration: 1}}, Routes: []juneau.Route{{Dst: "10.215.10.0/24", Subnet: "inside", Via: juneau.RouteVia{Type: juneau.ViaConnected}}, {Dst: "10.96.0.0/12", Via: juneau.RouteVia{Type: juneau.ViaService}}}}}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: "ns", Annotations: map[string]string{serviceVpcAnnotation: "vpc"}}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.10", ClusterIPs: []string{"10.96.0.10"}, Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}}}}
	port := int32(80)
	proto := corev1.ProtocolTCP
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: "ns", Labels: map[string]string{discoveryv1.LabelServiceName: "local"}}, AddressType: discoveryv1.AddressTypeIPv4, Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: &proto}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.215.10.5"}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: "backend"}}}}
	nic := &juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "backend.eth0", Namespace: "ns", Generation: 1}, Spec: juneau.NetworkInterfaceSpec{Subnet: "inside", PodRef: juneau.NetworkInterfacePodReference{Name: "backend", Interface: juneau.PodPrimaryInterfaceName}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, ObservedGeneration: 1, Address: "10.215.10.5/24"}}
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(table).WithObjects(table, service, slice, nic).Build()}
	check := func() {
		t.Helper()
		got, err := r.serviceAdvertisements(ctx, vpn, vpc, table, map[string]*juneau.Subnet{"inside": subnet}, []string{"0.0.0.0/0"})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, []string{"10.96.0.10/32"}) {
			t.Fatalf("default VPN route lost local Service while RouteTable Ready=%t: %v", conditionReady(table.Status.Conditions, juneau.RouteTableStatusReady, table.Generation), got)
		}
	}
	check()
	table.Status.PendingVPN = ""
	table.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	table.Status.Routes = append(table.Status.Routes, vpnRoute)
	if err := r.Status().Update(ctx, table); err != nil {
		t.Fatal(err)
	}
	check()
}
