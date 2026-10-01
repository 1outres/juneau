package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRouteTableVPNBootstrapRecoveryAndRotation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "ns", UID: "branch-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "gw"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.0.0/24"}, Status: juneau.SubnetStatus{Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	own := juneau.Route{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "ns", Name: "branch"}}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{own}}, Status: juneau.RouteTableStatus{TableID: 9}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, subnet, vpc, table).WithStatusSubresource(table).WithIndex(&juneau.Subnet{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.Subnet).Spec.Vpc} }).WithIndex(&juneau.L2Network{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.L2Network).Spec.Vpc} }).Build()
	rt := &RouteTableReconciler{Client: cl, Scheme: scheme}
	gateway := &VPNReconciler{Client: cl}
	for i := 0; i < 2; i++ {
		if _, err := rt.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "main"}}); err != nil {
			t.Fatal(err)
		}
		if err := cl.Get(ctx, client.ObjectKey{Name: "main"}, table); err != nil {
			t.Fatal(err)
		}
		if !vpnTableReady(table, vpn) || table.Status.PendingVPN != "ns/branch" || table.Status.Conditions[0].Reason != routeTableReasonVPNEndpointPending || len(table.Status.Routes) != 1 || table.Status.Routes[0].Via.Type != juneau.ViaConnected {
			t.Fatalf("bootstrap status = %+v", table.Status)
		}
		remote, _, err := gateway.gatewayRoutes(ctx, vpn, vpc, subnet)
		if err != nil || len(remote) != 1 || remote[0] != own.Dst {
			t.Fatalf("bootstrap routes = %v, %v", remote, err)
		}
		table.Spec.Routes = nil
		if err := cl.Update(ctx, table); err != nil {
			t.Fatal(err)
		}
		if _, err := rt.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "main"}}); err != nil {
			t.Fatal(err)
		}
		if err := cl.Get(ctx, client.ObjectKey{Name: "main"}, table); err != nil {
			t.Fatal(err)
		}
		if !conditionReady(table.Status.Conditions, juneau.RouteTableStatusReady, table.Generation) || table.Status.PendingVPN != "" {
			t.Fatalf("table did not recover: %+v", table.Status)
		}
		table.Spec.Routes = []juneau.Route{own}
		if err := cl.Update(ctx, table); err != nil {
			t.Fatal(err)
		}
	}
	table.Spec.Routes = append(table.Spec.Routes, juneau.Route{Dst: "198.51.100.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "ns", Name: "missing"}}})
	if err := cl.Update(ctx, table); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "main"}}); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(ctx, client.ObjectKey{Name: "main"}, table); err != nil {
		t.Fatal(err)
	}
	if vpnTableReady(table, vpn) || table.Status.PendingVPN != "" {
		t.Fatalf("unrelated failure allowed bootstrap: %+v", table.Status)
	}
	if _, _, err := gateway.gatewayRoutes(ctx, vpn, vpc, subnet); err == nil {
		t.Fatal("unrelated failure allowed gateway startup")
	}
}
