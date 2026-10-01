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

func TestVPNAdvertisesReadyLocalAndDirectRemoteRoutesAndWithdraws(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ready := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "ns"}, Spec: juneau.VPNSpec{Vpc: "own", Subnet: "gw"}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "own"}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	gw := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "own", CIDR: "10.0.0.0/24", RouteTable: "custom"}, Status: juneau.SubnetStatus{Conditions: ready}}
	local := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "local", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "own", CIDR: "10.0.1.0/24"}, Status: juneau.SubnetStatus{Conditions: ready}}
	peer := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "peer-subnet", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "peer", CIDR: "172.16.0.0/24"}, Status: juneau.SubnetStatus{Conditions: ready}}
	peering := &juneau.VpcPeering{ObjectMeta: metav1.ObjectMeta{Name: "direct", Generation: 1}, Spec: juneau.VpcPeeringSpec{Requester: juneau.VpcPeeringEndpoint{Vpc: "own"}, Accepter: juneau.VpcPeeringEndpoint{Vpc: "peer"}}, Status: juneau.VpcPeeringStatus{Conditions: ready}}
	route := juneau.Route{Dst: peer.Spec.CIDR, Subnet: peer.Name, Via: juneau.RouteVia{Type: juneau.ViaVpcPeering, VpcPeering: peering.Name}}
	custom := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "custom", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "own", Routes: []juneau.Route{route}}, Status: juneau.RouteTableStatus{Conditions: ready, Routes: []juneau.Route{route}}}
	main := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "own"}, Status: juneau.RouteTableStatus{Conditions: ready}}
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, vpc, gw, local, peer, peering, custom, main).Build()}
	check := func(want []string) {
		t.Helper()
		_, adv, err := r.gatewayRoutes(context.Background(), vpn, vpc, gw)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(adv, want) {
			t.Fatalf("advertised %v, want %v", adv, want)
		}
	}
	check([]string{"10.0.0.0/24", "10.0.1.0/24", "172.16.0.0/24"})
	local.Spec.CIDR = "10.0.2.0/24"
	local.Generation = 2
	local.Status.Conditions[0].ObservedGeneration = 2
	if err := r.Update(context.Background(), local); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(context.Background(), peering); err != nil {
		t.Fatal(err)
	}
	check([]string{"10.0.0.0/24", "10.0.2.0/24"})
}
