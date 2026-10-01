package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNStartsWhileItsOwnRouteWaitsForEndpoint(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant"}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "inside"}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "inside", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.0.0/24"}, Status: juneau.SubnetStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "tenant", Name: "branch"}}}}}, Status: juneau.RouteTableStatus{PendingVPN: "tenant/branch", Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, ObservedGeneration: 1, Reason: routeTableReasonVPNEndpointPending, Message: "Gateway endpoint is pending"}}, Routes: []juneau.Route{{Dst: "10.0.0.0/24", Subnet: "inside", Via: juneau.RouteVia{Type: juneau.ViaConnected}}}}}
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, vpc, subnet, table).Build()}
	remote, adv, err := r.gatewayRoutes(context.Background(), vpn, vpc, subnet)
	if err != nil || len(remote) != 1 || len(adv) != 1 {
		t.Fatalf("route bootstrap: remote=%v advertised=%v err=%v", remote, adv, err)
	}
	table.Status.PendingVPN = "tenant/other"
	if err := r.Update(context.Background(), table); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.gatewayRoutes(context.Background(), vpn, vpc, subnet); err == nil {
		t.Fatal("must not start while another gateway blocks the table")
	}
}
