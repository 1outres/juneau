package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNPreservesGatewayBGPWhileTransitReturnRouteWaitsForItsOwnGateway(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "ns"}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	subnet := &juneau.Subnet{}
	ownRoute := juneau.Route{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: vpn.Namespace, Name: vpn.Name}}}
	route := juneau.Route{Dst: "172.16.0.0/24", Via: juneau.RouteVia{Type: juneau.ViaTransitGateway, TransitGateway: "tgw"}, TransitGatewayRouteTable: "association"}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{ownRoute}}, Status: juneau.RouteTableStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}, Routes: []juneau.Route{route}}}
	transit := &juneau.TransitGatewayRouteTable{ObjectMeta: metav1.ObjectMeta{Name: "association", Generation: 1}, Spec: juneau.TransitGatewayRouteTableSpec{TransitGateway: "tgw", Routes: []juneau.TransitGatewayRoute{{Dst: ownRoute.Dst, Attachment: "source"}}}, Status: juneau.TransitGatewayRouteTableStatus{PendingVPN: "ns/branch", Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, ObservedGeneration: 1, Reason: transitGatewayRouteTableReasonVPNRoutePending, Message: "message is not a contract"}}}}
	attachment := &juneau.TransitGatewayAttachment{ObjectMeta: metav1.ObjectMeta{Name: "source", Generation: 1}, Spec: juneau.TransitGatewayAttachmentSpec{Vpc: "vpc", TransitGateway: "tgw"}, Status: juneau.TransitGatewayAttachmentStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}}}
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, vpc, table, transit, attachment).Build()}
	pending, err := r.transitTablePendingOnVPN(context.Background(), vpn, vpc, subnet)
	if err != nil || !pending {
		t.Fatalf("own transit dependency pending=%v err=%v", pending, err)
	}
	transit.Status.Conditions[0].Status = metav1.ConditionTrue
	if err := r.Update(context.Background(), transit); err != nil {
		t.Fatal(err)
	}
	pending, err = r.transitTablePendingOnVPN(context.Background(), vpn, vpc, subnet)
	if err != nil || pending {
		t.Fatalf("ready transit dependency pending=%v err=%v", pending, err)
	}
}
