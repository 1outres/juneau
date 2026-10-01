package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNRouteBootstrapKeepsExistingGatewayConfigurationUntilTableRecovers(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant"}}
	vpc := &juneau.Vpc{Status: juneau.VpcStatus{MainRouteTable: "main"}}
	subnet := &juneau.Subnet{}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "tenant", Name: "branch"}}}}}, Status: juneau.RouteTableStatus{PendingVPN: "tenant/branch", Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, Reason: routeTableReasonVPNEndpointPending, ObservedGeneration: 1, Message: "Endpoint pending"}}}}
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(table).Build()}
	pending, err := r.gatewayTablePendingOnVPN(context.Background(), vpn, vpc, subnet)
	if err != nil || !pending {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	original := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Env: []corev1.EnvVar{{Name: "VPN_REMOTE_ROUTES", Value: "[\"192.0.2.0/24\"]"}, {Name: "VPN_ADVERTISED_ROUTES", Value: "[\"10.0.0.0/24\",\"10.96.0.10/32\"]"}, {Name: "PUBLIC_IP", Value: "203.0.113.1"}}}}}}
	desired := original.DeepCopy()
	desired.Spec.Containers[0].Env[0].Value = "[]"
	desired.Spec.Containers[0].Env[1].Value = "[\"10.0.0.0/24\"]"
	preserveGatewayRoutes(desired, original)
	for i := range original.Spec.Containers[0].Env {
		if desired.Spec.Containers[0].Env[i].Value != original.Spec.Containers[0].Env[i].Value {
			t.Fatalf("bootstrap changed env %s", desired.Spec.Containers[0].Env[i].Name)
		}
	}
	table.Status.Conditions[0].Status = metav1.ConditionTrue
	if err := r.Update(context.Background(), table); err != nil {
		t.Fatal(err)
	}
	pending, err = r.gatewayTablePendingOnVPN(context.Background(), vpn, vpc, subnet)
	if err != nil || pending {
		t.Fatalf("ready table pending=%v err=%v", pending, err)
	}
}
