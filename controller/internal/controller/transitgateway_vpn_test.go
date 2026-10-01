package controller

import (
	"context"
	"strings"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestTransitStaticVPNRouteNeedsManualVPNVpcRoute(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ready := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "site", UID: "vpn-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "home", Subnet: "gw"}, Status: juneau.VPNStatus{ObservedGeneration: 1, Conditions: ready}}
	gw := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "home", CIDR: "10.1.0.0/24"}, Status: juneau.SubnetStatus{VNI: 17, GatewayMAC: "02:00:00:00:00:01", Conditions: ready}}
	home := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "home"}, Status: juneau.VpcStatus{MainRouteTable: "home"}}
	rt := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "home", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "home", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: "branch"}}}}}, Status: juneau.RouteTableStatus{Conditions: ready}}
	att := juneau.TransitGatewayAttachment{ObjectMeta: metav1.ObjectMeta{Name: "attached", Generation: 1}, Spec: juneau.TransitGatewayAttachmentSpec{Vpc: "home", TransitGateway: "tgw"}, Status: juneau.TransitGatewayAttachmentStatus{Conditions: ready}}
	controller := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(vpn), Namespace: "site", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: juneau.GroupVersion.String(), Kind: "VPN", Name: vpn.Name, UID: vpn.UID, Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	nic := &juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: networkInterfaceNameForPod(pod.Name, "eth0"), Namespace: "site", Generation: 1}, Spec: juneau.NetworkInterfaceSpec{NodeName: "node-a", Subnet: "gw", PodRef: juneau.NetworkInterfacePodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, ObservedGeneration: 1, Address: "10.1.0.5/24"}}
	ep := &juneau.NetworkEndpoint{ObjectMeta: metav1.ObjectMeta{Name: pod.Name + ".eth0", Namespace: "site"}, Spec: juneau.NetworkEndpointSpec{Kind: juneau.EndpointKindPod, NodeName: "node-a", Subnet: "gw", Address: "10.1.0.5/24", MACAddress: "02:00:00:00:00:05", PodRef: &juneau.NetworkEndpointPodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, gw, home, rt, pod, nic, ep).Build()
	r := &TransitGatewayRouteTableReconciler{Client: cl}
	table := &juneau.TransitGatewayRouteTable{Spec: juneau.TransitGatewayRouteTableSpec{TransitGateway: "tgw"}}
	route := juneau.TransitGatewayRoute{Dst: "192.0.2.0/24", Attachment: "attached"}
	resolved, message, err := r.resolveStaticRoute(context.Background(), table, route, []juneau.TransitGatewayAttachment{att})
	if err != nil || message != "" || resolved.Subnet != "gw" || resolved.VPN == nil || resolved.VPN.Name != "branch" {
		t.Fatalf("explicit VPN transit route = %+v, %q, %v", resolved, message, err)
	}
	rt.Spec.Routes = nil
	if err := cl.Update(context.Background(), rt); err != nil {
		t.Fatal(err)
	}
	_, message, err = r.resolveStaticRoute(context.Background(), table, route, []juneau.TransitGatewayAttachment{att})
	if err != nil || !strings.Contains(message, "VPN route") {
		t.Fatalf("missing explicit route accepted: %q, %v", message, err)
	}
	rt.Spec.Routes = []juneau.Route{{Dst: route.Dst, Via: juneau.RouteVia{Type: juneau.ViaInternetGateway}}}
	if err := cl.Update(context.Background(), rt); err != nil {
		t.Fatal(err)
	}
	_, message, err = r.resolveStaticRoute(context.Background(), table, route, []juneau.TransitGatewayAttachment{att})
	if err != nil || !strings.Contains(message, "VPN route") {
		t.Fatalf("non-VPN route accepted: %q, %v", message, err)
	}
	att.Spec.Vpc = "other"
	_, message, err = r.resolveStaticRoute(context.Background(), table, route, []juneau.TransitGatewayAttachment{att})
	if err == nil && message == "" {
		t.Fatalf("foreign attachment accepted: %q, %v", message, err)
	}
}

func TestTransitVPNRouteUsesEffectiveGatewayReturnRoute(t *testing.T) {
	ref := &juneau.VPNReference{Namespace: "site", Name: "branch"}
	table := &juneau.RouteTable{Spec: juneau.RouteTableSpec{Routes: []juneau.Route{{Dst: "0.0.0.0/0", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: ref}}}}}
	if got := transitVPNRoute(table, "192.0.2.0/24"); got == nil || got.Via.VPN.Name != "branch" {
		t.Fatalf("explicit VPN default route not resolved: %+v", got)
	}
	table.Spec.Routes = append(table.Spec.Routes, juneau.Route{Dst: "192.0.2.0/25", Via: juneau.RouteVia{Type: juneau.ViaInternetGateway}})
	if got := transitVPNRoute(table, "192.0.2.0/24"); got != nil {
		t.Fatalf("partially shadowed route accepted: %+v", got)
	}
	table.Spec.Routes[1].Dst = "192.0.2.0/24"
	if got := transitVPNRoute(table, "192.0.2.0/24"); got != nil {
		t.Fatalf("more specific non-VPN route accepted: %+v", got)
	}
}

func TestTransitNeverPropagatesVPNRoute(t *testing.T) {
	attachment := juneau.TransitGatewayAttachment{ObjectMeta: metav1.ObjectMeta{Name: "home"}, Spec: juneau.TransitGatewayAttachmentSpec{TransitGateway: "tgw", Propagations: []string{"rt"}}, Status: juneau.TransitGatewayAttachmentStatus{Prefixes: []juneau.TransitGatewayAttachmentPrefix{{CIDR: "10.1.0.0/24", Subnet: "gw"}}}}
	table := &juneau.TransitGatewayRouteTable{ObjectMeta: metav1.ObjectMeta{Name: "rt"}, Spec: juneau.TransitGatewayRouteTableSpec{TransitGateway: "tgw"}}
	routes, conflicts := propagatedRoutes(table, []juneau.TransitGatewayAttachment{attachment})
	if len(conflicts) != 0 || len(routes) != 1 || routes["192.0.2.0/24"].Dst != "" {
		t.Fatalf("VPN propagated: %v, %v", routes, conflicts)
	}
}
