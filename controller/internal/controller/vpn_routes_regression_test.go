package controller

import (
	"context"
	"reflect"
	"strings"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNRoutesAcrossTablesAndGatewayPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ready := []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionTrue, ObservedGeneration: 1, Reason: "Ready"}}
	own := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "branch"}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{MainRouteTable: "gateway"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.0.0/24"}, Status: juneau.SubnetStatus{Conditions: ready}}
	route := func(dst, name string) juneau.Route {
		return juneau.Route{Dst: dst, Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "ns", Name: name}}}
	}
	gateway := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{route("0.0.0.0/0", "branch"), route("198.51.100.0/24", "other")}}, Status: juneau.RouteTableStatus{Conditions: ready}}
	second := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "second", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{route("192.0.2.0/24", "branch")}}, Status: juneau.RouteTableStatus{Conditions: ready}}
	third := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "third", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{route("192.0.2.0/24", "other"), route("203.0.113.0/24", "branch")}}, Status: juneau.RouteTableStatus{Conditions: ready}}
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, subnet, gateway, second, third).WithStatusSubresource(gateway).Build()}
	if _, _, err := r.gatewayRoutes(context.Background(), own, vpc, subnet); err == nil || !strings.Contains(err.Error(), "198.51.100.0/24") {
		t.Fatalf("gateway overlap must fail closed: %v", err)
	}
	gateway.Spec.Routes[0] = route("192.0.2.0/24", "branch")
	if err := r.Update(context.Background(), gateway); err != nil {
		t.Fatal(err)
	}
	remotes, _, err := r.gatewayRoutes(context.Background(), own, vpc, subnet)
	if err != nil || !reflect.DeepEqual(remotes, []string{"192.0.2.0/24", "203.0.113.0/24"}) {
		t.Fatalf("deduplicated remote routes = %v, %v", remotes, err)
	}
	gateway.Spec.Routes[0] = route("0.0.0.0/0", "branch")
	gateway.Spec.Routes[1] = route("198.51.100.0/24", "branch")
	if err := r.Update(context.Background(), gateway); err != nil {
		t.Fatal(err)
	}
	remotes, _, err = r.gatewayRoutes(context.Background(), own, vpc, subnet)
	if err != nil || !reflect.DeepEqual(remotes, []string{"0.0.0.0/0", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}) {
		t.Fatalf("explicit default and specifics = %v, %v", remotes, err)
	}
	gateway.Spec.Routes[1] = route("198.51.100.0/24", "other")
	if err := r.Update(context.Background(), gateway); err != nil {
		t.Fatal(err)
	}
	gateway.Status.Conditions = []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionFalse, ObservedGeneration: 1, Reason: routeTableReasonVPNEndpointPending, Message: "changed text"}}
	if err := r.Status().Update(context.Background(), gateway); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.gatewayRoutes(context.Background(), own, vpc, subnet); err == nil {
		t.Fatal("unidentified pending VPN must not pass")
	}
	gateway.Status.Conditions[0].Status = metav1.ConditionTrue
	gateway.Status.PendingVPN = ""
	if err := r.Status().Update(context.Background(), gateway); err != nil {
		t.Fatal(err)
	}
	gateway.Spec.Routes = []juneau.Route{route("192.0.2.0/24", "other")}
	if err := r.Update(context.Background(), gateway); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.gatewayRoutes(context.Background(), own, vpc, subnet); err == nil || !strings.Contains(err.Error(), "192.0.2.0/24") {
		t.Fatalf("other VPN on gateway subnet must block route collected from another table: %v", err)
	}
}
