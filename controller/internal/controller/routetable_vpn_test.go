package controller

import (
	"context"
	"strings"
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

func TestUnprovisionedVPNRouteIsNotPublished(t *testing.T) {
	for _, tc := range []struct {
		name, table, dst string
		gateway          uint32
		extraDefault     bool
		missingVPN       bool
	}{
		{"site", "site-routes", "192.168.0.0/24", 0, false, false},
		{"default route cannot fall back to default NAT", "default", "0.0.0.0/0", 27, false, false},
		{"site route cannot fall back to internet gateway", "site-routes", "192.168.0.0/24", 0, true, false},
		{"missing VPN cannot fall back", "site-routes", "192.168.0.0/24", 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			if err := juneau.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
			table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: tc.table}, Spec: juneau.RouteTableSpec{Vpc: "default", Routes: []juneau.Route{{Dst: tc.dst, Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: "branch"}}}}}, Status: juneau.RouteTableStatus{TableID: 3, Routes: []juneau.Route{{Dst: tc.dst, Via: juneau.RouteVia{Type: juneau.ViaInternetGateway}}}}}
			if tc.extraDefault {
				table.Spec.Routes = append([]juneau.Route{{Dst: "0.0.0.0/0", Via: juneau.RouteVia{Type: juneau.ViaInternetGateway}}}, table.Spec.Routes...)
			}
			objects := []client.Object{vpc, table}
			if !tc.missingVPN {
				objects = append(objects, &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "site"}, Spec: juneau.VPNSpec{Vpc: "default"}})
			}
			if tc.gateway != 0 {
				objects = append(objects, &juneau.NATGateway{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: juneau.NATGatewayStatus{GatewayID: tc.gateway}})
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithStatusSubresource(table).WithIndex(&juneau.Subnet{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.Subnet).Spec.Vpc} }).WithIndex(&juneau.L2Network{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.L2Network).Spec.Vpc} }).Build()
			r := &RouteTableReconciler{Client: c, Scheme: scheme}
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: table.Name}})
			if err != nil {
				t.Fatal(err)
			}
			var result juneau.RouteTable
			if err := c.Get(ctx, client.ObjectKey{Name: table.Name}, &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Status.Routes) != 0 {
				t.Fatalf("unexpected installed routes: %+v", result.Status.Routes)
			}
			wantMessage := "not Ready"
			if tc.missingVPN {
				wantMessage = "not found"
			}
			if len(result.Status.Conditions) == 0 || result.Status.Conditions[0].Status != metav1.ConditionFalse || !strings.Contains(result.Status.Conditions[0].Message, wantMessage) {
				t.Fatalf("expected explicit NotReady: %+v", result.Status.Conditions)
			}
			if tc.missingVPN {
				if result.Status.PendingVPN != "" || result.Status.Conditions[0].Reason != routeTableReasonNotReady {
					t.Fatalf("missing VPN allowed bootstrap: %+v", result.Status)
				}
			} else if result.Status.PendingVPN != "site/branch" || result.Status.Conditions[0].Reason != routeTableReasonVPNEndpointPending {
				t.Fatalf("unexpected bootstrap status: %+v", result.Status)
			}
		})
	}
}
