package controller

import (
	"context"
	"reflect"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestTwoVPNsBootstrapInSameVpc(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "inside", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.10.0.0/24"}, Status: juneau.SubnetStatus{VNI: 12, Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	a := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "site", UID: "a", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "inside"}}
	b := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "site", UID: "b", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "inside"}}
	route := func(dst, name string) juneau.Route {
		return juneau.Route{Dst: dst, Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: name}}}
	}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{route("192.0.2.0/24", "a"), route("198.19.54.0/24", "b")}}, Status: juneau.RouteTableStatus{TableID: 9}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, subnet, a, b, table).WithStatusSubresource(table).WithIndex(&juneau.Subnet{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.Subnet).Spec.Vpc} }).WithIndex(&juneau.L2Network{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.L2Network).Spec.Vpc} }).Build()
	rt := &RouteTableReconciler{Client: cl, Scheme: scheme}
	for i := 0; i < 2; i++ {
		if _, err := rt.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "main"}}); err != nil {
			t.Fatal(err)
		}
		if err := cl.Get(ctx, client.ObjectKey{Name: "main"}, table); err != nil {
			t.Fatal(err)
		}
		if table.Status.Conditions[0].Reason != routeTableReasonVPNEndpointPending || table.Status.PendingVPN != "" || !reflect.DeepEqual(table.Status.PendingVPNs, []string{"site/a", "site/b"}) || len(table.Status.Routes) != 1 || table.Status.Routes[0].Via.Type != juneau.ViaConnected {
			t.Fatalf("multi-site bootstrap status: %+v", table.Status)
		}
		for index, vpn := range []*juneau.VPN{a, b} {
			if !vpnTableReady(table, vpn) {
				t.Fatalf("VPN %s blocked by other pending VPN", vpn.Name)
			}
			remote, _, err := (&VPNReconciler{Client: cl}).gatewayRoutes(ctx, vpn, vpc, subnet)
			if err != nil || len(remote) != 1 || remote[0] != table.Spec.Routes[index].Dst {
				t.Fatalf("VPN %s remote routes: %v, %v", vpn.Name, remote, err)
			}
		}
	}
	if !vpcPendingOnGatewayVPN(ctx, cl, &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc", Generation: 1}, Status: juneau.VpcStatus{VpcID: 1, MainRouteTable: "main", Conditions: []metav1.Condition{{Type: juneau.VpcStatusReady, Status: metav1.ConditionFalse, Reason: vpcReasonRouteTableNotReady, ObservedGeneration: 1}}}}, subnet) {
		t.Fatal("pending VPN does not permit subnet bootstrap")
	}
	table.Spec.Routes = append(table.Spec.Routes, route("203.0.113.0/24", "missing"))
	if err := cl.Update(ctx, table); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "main"}}); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(ctx, client.ObjectKey{Name: "main"}, table); err != nil {
		t.Fatal(err)
	}
	if table.Status.PendingVPN != "" || len(table.Status.PendingVPNs) != 0 || vpnTableReady(table, a) || vpnTableReady(table, b) {
		t.Fatalf("unrelated failure allowed bootstrap: %+v", table.Status)
	}
}

func TestReadyVPNRouteSurvivesOtherVPNBootstrap(t *testing.T) {
	a := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "site"}, Spec: juneau.VPNSpec{Subnet: "inside"}}
	b := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "site"}, Spec: juneau.VPNSpec{Subnet: "inside"}}
	own := juneau.Route{Dst: "192.0.2.0/24", Subnet: "inside", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: "a"}}}
	pending := juneau.Route{Dst: "198.19.54.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: "b"}}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Generation: 1}, Spec: juneau.RouteTableSpec{Routes: []juneau.Route{own, pending}}, Status: juneau.RouteTableStatus{PendingVPN: "site/b", Routes: []juneau.Route{own}, Conditions: []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionFalse, Reason: routeTableReasonVPNEndpointPending, ObservedGeneration: 1}}}}
	if !vpnTableReady(table, a) || !vpnTableReady(table, b) {
		t.Fatal("ready VPN and pending VPN must both continue to operate")
	}
	table.Status.Routes = nil
	if vpnTableReady(table, a) {
		t.Fatal("unresolved route must not grant VPN A access to VPN B's endpoint")
	}
	table.Spec.Routes = []juneau.Route{own}
	if vpnTableReady(table, b) {
		t.Fatal("pending key without its spec route must not grant access")
	}
	table.Spec.Routes = []juneau.Route{own, pending}
	table.Status.PendingVPNs = []string{"site/a", "site/b"}
	if vpnTableReady(table, b) {
		t.Fatal("two conflicting pending status fields must not grant access")
	}
}
