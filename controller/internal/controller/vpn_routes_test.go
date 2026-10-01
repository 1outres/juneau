package controller

import (
	"context"
	"reflect"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNRoutePlanUsesEffectiveTableAndReachableReadySubnets(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ready := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant"}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "gateway"}}
	gateway := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.0.0/24", RouteTable: "custom"}, Status: juneau.SubnetStatus{Conditions: ready}}
	inside := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "inside", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.1.0/24"}, Status: juneau.SubnetStatus{Conditions: ready}}
	pending := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "pending", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.2.0/24"}}
	foreign := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "foreign", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "else", CIDR: "172.16.0.0/24"}, Status: juneau.SubnetStatus{Conditions: ready}}
	specRoute := juneau.Route{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "tenant", Name: "branch"}}}
	otherRoute := juneau.Route{Dst: "198.51.100.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "tenant", Name: "other"}}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "custom", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{specRoute, otherRoute}}, Status: juneau.RouteTableStatus{Conditions: ready, Routes: []juneau.Route{
		{Dst: "10.0.0.0/24", Via: juneau.RouteVia{Type: juneau.ViaConnected}, Subnet: "gateway"},
		{Dst: "10.0.1.0/24", Via: juneau.RouteVia{Type: juneau.ViaConnected}, Subnet: "inside"},
		{Dst: "10.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaConnected}, Subnet: "pending"},
		{Dst: "0.0.0.0/0", Via: juneau.RouteVia{Type: juneau.ViaNATGateway}},
		{Dst: "172.16.0.0/24", Via: juneau.RouteVia{Type: juneau.ViaVpcPeering, VpcPeering: "direct"}, Subnet: "foreign"},
		{Dst: "10.10.0.0/16", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "tenant", Name: "other"}}},
		specRoute,
	}}}
	main := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{{Dst: "203.0.113.0/24", Via: specRoute.Via}}}, Status: juneau.RouteTableStatus{Conditions: ready}}
	direct := &juneau.VpcPeering{ObjectMeta: metav1.ObjectMeta{Name: "direct", Generation: 1}, Spec: juneau.VpcPeeringSpec{Requester: juneau.VpcPeeringEndpoint{Vpc: "vpc"}, Accepter: juneau.VpcPeeringEndpoint{Vpc: "else"}}, Status: juneau.VpcPeeringStatus{Conditions: ready}}
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, vpn, gateway, inside, pending, foreign, table, main, direct).Build()}
	remote, advertised, err := r.gatewayRoutes(context.Background(), vpn, vpc, gateway)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(remote, []string{"192.0.2.0/24", "203.0.113.0/24"}) {
		t.Fatalf("remote: %v", remote)
	}
	if !reflect.DeepEqual(advertised, []string{"10.0.0.0/24", "10.0.1.0/24", "172.16.0.0/24"}) {
		t.Fatalf("advertised: %v", advertised)
	}
}
