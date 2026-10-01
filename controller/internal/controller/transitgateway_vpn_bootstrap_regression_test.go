package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestTransitGatewayVPNPendingReasonAndRecovery(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "ns", UID: "vpn-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "gw"}}
	ref := &juneau.VPNReference{Namespace: "ns", Name: "branch"}
	rt := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: ref}}}}, Status: juneau.RouteTableStatus{PendingVPN: "ns/branch", Conditions: []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionFalse, Reason: routeTableReasonVPNEndpointPending, ObservedGeneration: 1}}}}
	tgw := &juneau.TransitGateway{ObjectMeta: metav1.ObjectMeta{Name: "tgw"}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	gw := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw"}, Spec: juneau.SubnetSpec{Vpc: "vpc"}}
	att := &juneau.TransitGatewayAttachment{ObjectMeta: metav1.ObjectMeta{Name: "attached", Generation: 1}, Spec: juneau.TransitGatewayAttachmentSpec{Vpc: "vpc", TransitGateway: "tgw"}, Status: juneau.TransitGatewayAttachmentStatus{Conditions: []metav1.Condition{{Type: juneau.TransitGatewayAttachmentStatusReady, Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	table := &juneau.TransitGatewayRouteTable{ObjectMeta: metav1.ObjectMeta{Name: "association", Generation: 1}, Spec: juneau.TransitGatewayRouteTableSpec{TransitGateway: "tgw", Routes: []juneau.TransitGatewayRoute{{Dst: "192.0.2.0/24", Attachment: "attached"}}}, Status: juneau.TransitGatewayRouteTableStatus{TableID: 11}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, rt, tgw, vpc, gw, att, table).WithStatusSubresource(rt, table).Build()
	r := &TransitGatewayRouteTableReconciler{Client: cl, Scheme: scheme}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "association"}}); err != nil {
			t.Fatal(err)
		}
		if err := cl.Get(ctx, client.ObjectKey{Name: "association"}, table); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	if table.Status.PendingVPN != "ns/branch" || table.Status.Conditions[0].Reason != transitGatewayRouteTableReasonVPNRoutePending {
		t.Fatalf("transit pending status: %+v", table.Status)
	}
	table.Spec.Routes = nil
	if err := cl.Update(ctx, table); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if !conditionReady(table.Status.Conditions, juneau.TransitGatewayRouteTableStatusReady, table.Generation) || table.Status.PendingVPN != "" {
		t.Fatalf("transit did not recover: %+v", table.Status)
	}
	table.Spec.Routes = []juneau.TransitGatewayRoute{{Dst: "192.0.2.0/24", Attachment: "attached"}, {Dst: "198.51.100.0/24", Attachment: "missing"}}
	if err := cl.Update(ctx, table); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if table.Status.PendingVPN != "" || table.Status.Conditions[0].Reason == transitGatewayRouteTableReasonVPNRoutePending {
		t.Fatalf("unrelated transit failure allowed bootstrap: %+v", table.Status)
	}
}
