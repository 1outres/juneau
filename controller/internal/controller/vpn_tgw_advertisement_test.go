package controller

import (
	"context"
	"reflect"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNAdvertisesOnlyResolvedTransitSubnetNotTransitVPNOrDefault(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ready := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant"}, Spec: juneau.VPNSpec{Vpc: "own", Subnet: "gateway"}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "own"}, Status: juneau.VpcStatus{MainRouteTable: "main"}}
	gateway := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "own", CIDR: "10.0.0.0/24"}, Status: juneau.SubnetStatus{Conditions: ready}}
	target := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "target", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "other", CIDR: "172.16.0.0/24"}, Status: juneau.SubnetStatus{Conditions: ready}}
	transit := &juneau.TransitGateway{ObjectMeta: metav1.ObjectMeta{Name: "tgw", Generation: 1}, Status: juneau.TransitGatewayStatus{Conditions: ready}}
	sourceAttachment := &juneau.TransitGatewayAttachment{ObjectMeta: metav1.ObjectMeta{Name: "source", Generation: 1}, Spec: juneau.TransitGatewayAttachmentSpec{Vpc: "own", TransitGateway: "tgw", Association: "association"}, Status: juneau.TransitGatewayAttachmentStatus{Conditions: ready}}
	destAttachment := &juneau.TransitGatewayAttachment{ObjectMeta: metav1.ObjectMeta{Name: "dest", Generation: 1}, Spec: juneau.TransitGatewayAttachmentSpec{Vpc: "other", TransitGateway: "tgw"}, Status: juneau.TransitGatewayAttachmentStatus{Conditions: ready}}
	assoc := &juneau.TransitGatewayRouteTable{ObjectMeta: metav1.ObjectMeta{Name: "association", Generation: 1}, Spec: juneau.TransitGatewayRouteTableSpec{TransitGateway: "tgw"}, Status: juneau.TransitGatewayRouteTableStatus{Conditions: ready, Routes: []juneau.ResolvedTransitGatewayRoute{{Dst: target.Spec.CIDR, Subnet: target.Name, Attachment: destAttachment.Name}, {Dst: "192.0.2.0/24", Subnet: "other-vpn", Attachment: destAttachment.Name, VPN: &juneau.VPNReference{Name: "other", Namespace: "tenant"}}}}}
	routes := []juneau.Route{{Dst: target.Spec.CIDR, Via: juneau.RouteVia{Type: juneau.ViaTransitGateway, TransitGateway: "tgw"}, TransitGatewayRouteTable: assoc.Name}, {Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaTransitGateway, TransitGateway: "tgw"}, TransitGatewayRouteTable: assoc.Name}, {Dst: "0.0.0.0/0", Via: juneau.RouteVia{Type: juneau.ViaTransitGateway, TransitGateway: "tgw"}, TransitGatewayRouteTable: assoc.Name}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "own"}, Status: juneau.RouteTableStatus{Conditions: ready, Routes: routes}}
	r := &VPNReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, vpc, gateway, target, transit, sourceAttachment, destAttachment, assoc, table).Build()}
	check := func(want []string) {
		t.Helper()
		_, got, err := r.gatewayRoutes(context.Background(), vpn, vpc, gateway)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("advertised %v, want %v", got, want)
		}
	}
	check([]string{"10.0.0.0/24", "172.16.0.0/24"})
	destAttachment.Status.Conditions[0].Status = metav1.ConditionFalse
	if err := r.Update(context.Background(), destAttachment); err != nil {
		t.Fatal(err)
	}
	check([]string{"10.0.0.0/24"})
}
