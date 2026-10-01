package controller

import (
	"context"
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

func TestPeeringReturnRouteRequiresExplicitPeerVPNRoute(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = juneau.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	ready := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "site", UID: "vpn-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "home", Subnet: "gw"}, Status: juneau.VPNStatus{ObservedGeneration: 1, Conditions: ready}}
	controller := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(vpn), Namespace: "site", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: juneau.GroupVersion.String(), Kind: "VPN", Name: vpn.Name, UID: vpn.UID, Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	nic := &juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: networkInterfaceNameForPod(pod.Name, "eth0"), Namespace: "site", Generation: 1}, Spec: juneau.NetworkInterfaceSpec{NodeName: "node-a", Subnet: "gw", PodRef: juneau.NetworkInterfacePodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, ObservedGeneration: 1, Address: "10.1.0.5/24"}}
	ep := &juneau.NetworkEndpoint{ObjectMeta: metav1.ObjectMeta{Name: pod.Name + ".eth0", Namespace: "site"}, Spec: juneau.NetworkEndpointSpec{Kind: juneau.EndpointKindPod, NodeName: "node-a", Subnet: "gw", Address: "10.1.0.5/24", MACAddress: "02:00:00:00:00:05", PodRef: &juneau.NetworkEndpointPodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}}
	gw := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "home", CIDR: "10.1.0.0/24"}, Status: juneau.SubnetStatus{VNI: 17, GatewayMAC: "02:00:00:00:00:01", Conditions: ready}}
	peer := &juneau.VpcPeering{ObjectMeta: metav1.ObjectMeta{Name: "direct", Generation: 1}, Spec: juneau.VpcPeeringSpec{Requester: juneau.VpcPeeringEndpoint{Vpc: "home"}, Accepter: juneau.VpcPeeringEndpoint{Vpc: "other"}}, Status: juneau.VpcPeeringStatus{Conditions: ready}}
	home := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "home", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "home", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: "branch"}}}}}, Status: juneau.RouteTableStatus{TableID: 8, ObservedGeneration: 1, Conditions: ready, Routes: []juneau.Route{{Dst: "192.0.2.0/24", Subnet: "gw", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: "branch"}}}}}}
	route := juneau.Route{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVpcPeering, VpcPeering: "direct"}}
	other := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "other", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "other", Routes: []juneau.Route{route}}, Status: juneau.RouteTableStatus{TableID: 9}}
	objects := []client.Object{vpn, pod, nic, ep, gw, peer, home, other, &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "home"}}, &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "other"}}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithStatusSubresource(other).WithIndex(&juneau.Subnet{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.Subnet).Spec.Vpc} }).WithIndex(&juneau.L2Network{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.L2Network).Spec.Vpc} }).Build()
	r := &RouteTableReconciler{Client: cl, Scheme: scheme}
	got, err := r.resolvePeeringVPNRoute(context.Background(), "other", "home", route)
	if err != nil || got.Subnet != "gw" || got.Via.VPN == nil || got.Via.VPN.Name != "branch" {
		t.Fatalf("valid peer return route = %+v, %v", got, err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: other.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(context.Background(), client.ObjectKey{Name: other.Name}, other); err != nil {
		t.Fatal(err)
	}
	resolved := getRoute(other.Status.Routes, route.Dst)
	if resolved == nil || resolved.Subnet != "gw" || resolved.Via.VPN == nil || resolved.Via.VPN.Name != vpn.Name {
		t.Fatalf("peering return route not installed: %+v", other.Status.Routes)
	}
	home.Spec.Routes = nil
	if err := r.Update(context.Background(), home); err != nil {
		t.Fatal(err)
	}
	if _, err := r.resolvePeeringVPNRoute(context.Background(), "other", "home", route); err == nil {
		t.Fatal("route without an explicit VPN route in peer Vpc accepted")
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: other.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(context.Background(), client.ObjectKey{Name: other.Name}, other); err != nil {
		t.Fatal(err)
	}
	if getRoute(other.Status.Routes, route.Dst) != nil || conditionReady(other.Status.Conditions, juneau.RouteTableStatusReady, other.Generation) {
		t.Fatalf("stale peer return route remained active: %+v", other.Status)
	}
	route.Dst = "0.0.0.0/0"
	if _, err := r.resolvePeeringVPNRoute(context.Background(), "other", "home", route); err == nil {
		t.Fatal("unconfigured default route accepted")
	}
}
