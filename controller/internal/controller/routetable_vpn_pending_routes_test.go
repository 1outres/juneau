package controller

import (
	"context"
	"net"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPendingVPNKeepsResolvedNonVPNRoutes(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Spec: juneau.VpcSpec{Service: &juneau.VpcServiceSpec{Consume: true}}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.1.0.0/24"}, Status: juneau.SubnetStatus{Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "test", UID: "vpn-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "gateway"}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "table", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "test", Name: "branch"}}}}}, Status: juneau.RouteTableStatus{TableID: 5}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, subnet, vpn, table).WithStatusSubresource(table).WithIndex(&juneau.Subnet{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.Subnet).Spec.Vpc} }).WithIndex(&juneau.L2Network{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.L2Network).Spec.Vpc} }).Build()
	_, serviceCIDR, err := net.ParseCIDR("10.96.0.0/12")
	if err != nil {
		t.Fatal(err)
	}
	r := &RouteTableReconciler{Client: cl, Scheme: scheme, ServiceCIDR: serviceCIDR}
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "table"}}); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(ctx, client.ObjectKey{Name: "table"}, table); err != nil {
		t.Fatal(err)
	}
	if table.Status.PendingVPN != "test/branch" || len(table.Status.Routes) != 2 || table.Status.Routes[0].Dst != subnet.Spec.CIDR || table.Status.Routes[0].Via.Type != juneau.ViaConnected || table.Status.Routes[1].Dst != serviceCIDR.String() || table.Status.Routes[1].Via.Type != juneau.ViaService {
		t.Fatalf("pending routes = %+v", table.Status)
	}
}
