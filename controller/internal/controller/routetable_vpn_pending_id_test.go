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

func TestRouteTableAllocatesIDBeforeWaitingForVPNEndpoint(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant", UID: "vpn-uid"}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "inside"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "inside"}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.0.0/24"}, Status: juneau.SubnetStatus{Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionTrue}}}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{VpcID: 8, MainRouteTable: "main"}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main"}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "tenant", Name: "branch"}}}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(table, &juneau.AllocationClaim{}).WithObjects(vpn, subnet, vpc, table).WithIndex(&juneau.Subnet{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.Subnet).Spec.Vpc} }).WithIndex(&juneau.L2Network{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.L2Network).Spec.Vpc} }).Build()
	r := &RouteTableReconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: table.Name}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	claimName := newAllocationClaim(allocationPoolRouteTableID, juneau.GroupVersion.WithKind("RouteTable"), "", table.Name, "status.tableID").Name
	var claim juneau.AllocationClaim
	if err := c.Get(ctx, client.ObjectKey{Name: claimName}, &claim); err != nil {
		t.Fatalf("pending VPN prevented RouteTable ID allocation: %v", err)
	}
	claim.Status.Phase = juneau.AllocationClaimPhaseAllocated
	claim.Status.Value.Number = 17
	if err := c.Status().Update(ctx, &claim); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(table), table); err != nil {
		t.Fatal(err)
	}
	if table.Status.TableID != 17 || table.Status.PendingVPN != "tenant/branch" {
		t.Fatalf("pending VPN must retain assigned table ID: %+v", table.Status)
	}
}
