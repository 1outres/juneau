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

func TestVPNAdvertisesOnlyLocalServicesWithBackendReturnAndApprovedEndpoints(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{juneau.AddToScheme, corev1.AddToScheme, discoveryv1.AddToScheme} {
		if err := register(scheme); err != nil {
			t.Fatal(err)
		}
	}
	ready := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant"}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "gateway"}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Spec: juneau.VpcSpec{Service: &juneau.VpcServiceSpec{Consume: true}, EndpointPool: &juneau.VpcEndpointPoolSpec{CIDRs: []string{"10.200.0.0/24"}}}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	gateway := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.0.0/24"}, Status: juneau.SubnetStatus{Conditions: ready}}
	backend := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "backend", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.1.0/24", RouteTable: "backend-table"}, Status: juneau.SubnetStatus{Conditions: ready}}
	via := juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Name: vpn.Name, Namespace: vpn.Namespace}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc"}, Status: juneau.RouteTableStatus{Conditions: ready, Routes: []juneau.Route{{Dst: "10.0.1.0/24", Subnet: "backend", Via: juneau.RouteVia{Type: juneau.ViaConnected}}, {Dst: "10.96.0.0/12", Via: juneau.RouteVia{Type: juneau.ViaService}}, {Dst: "10.200.0.0/24", Via: juneau.RouteVia{Type: juneau.ViaVpcEndpoint}}}}}
	backendTable := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "backend-table", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: via}}}, Status: juneau.RouteTableStatus{Conditions: ready, Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: via}}}}
	own := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "own", Namespace: "ns", Annotations: map[string]string{serviceVpcAnnotation: "vpc"}}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.10", ClusterIPs: []string{"10.96.0.10"}, Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}}}}
	shared := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "ns", Annotations: map[string]string{serviceVpcAnnotation: "other", "juneau.loutres.me/shared-service": "true"}}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.11", ClusterIPs: []string{"10.96.0.11"}, Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}}}}
	port := int32(8080)
	proto := corev1.ProtocolTCP
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "slice", Namespace: "ns", Labels: map[string]string{discoveryv1.LabelServiceName: "own"}}, AddressType: discoveryv1.AddressTypeIPv4, Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: &proto}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.3"}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: "backend-pod"}}}}
	nic := &juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "backend-pod.eth0", Namespace: "ns", Generation: 1}, Spec: juneau.NetworkInterfaceSpec{Subnet: "backend", PodRef: juneau.NetworkInterfacePodReference{Name: "backend-pod", Interface: juneau.PodPrimaryInterfaceName}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, ObservedGeneration: 1, Address: "10.0.1.3/24"}}
	endpoint := &juneau.VpcEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "approved", Generation: 1}, Spec: juneau.VpcEndpointSpec{Vpc: "vpc", Service: juneau.VpcEndpointServiceReference{Namespace: "ns", Name: "own"}}, Status: juneau.VpcEndpointStatus{Address: "10.200.0.5", Conditions: []metav1.Condition{{Type: juneau.VpcEndpointConditionReady, Status: metav1.ConditionTrue, ObservedGeneration: 1}, {Type: juneau.VpcEndpointConditionServiceAccepted, Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	denied := endpoint.DeepCopy()
	denied.Name = "denied"
	denied.Status.Address = "10.200.0.6"
	denied.Status.Conditions[1].Status = metav1.ConditionFalse
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, vpc, gateway, backend, table, backendTable, own, shared, slice, nic, endpoint, denied).Build()}
	check := func(want []string) {
		t.Helper()
		got, err := r.serviceAdvertisements(context.Background(), vpn, vpc, table, map[string]*juneau.Subnet{"gateway": gateway, "backend": backend}, []string{"192.0.2.0/24"})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("advertised %v want %v", got, want)
		}
	}
	check([]string{"10.96.0.10/32", "10.200.0.5/32"})
	backendTable.Status.Routes[0].Via.VPN.Name = "another"
	if err := r.Update(context.Background(), backendTable); err != nil {
		t.Fatal(err)
	}
	check(nil)
}
