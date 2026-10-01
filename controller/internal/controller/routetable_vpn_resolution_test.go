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

func TestVPNRouteRequiresReadyOwnedGatewayEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dst    string
		mutate func(*juneau.VPN, *corev1.Pod, *juneau.NetworkInterface, *juneau.NetworkEndpoint)
		ready  bool
	}{
		{name: "ready", ready: true},
		{name: "explicit default route", ready: true, dst: "0.0.0.0/0"},
		{name: "overlapping connected subnet", dst: "10.1.0.0/16"},
		{name: "wrong Vpc", mutate: func(v *juneau.VPN, _ *corev1.Pod, _ *juneau.NetworkInterface, _ *juneau.NetworkEndpoint) {
			v.Spec.Vpc = "other"
		}},
		{name: "VPN not ready", mutate: func(v *juneau.VPN, _ *corev1.Pod, _ *juneau.NetworkInterface, _ *juneau.NetworkEndpoint) {
			v.Status.Conditions = nil
		}},
		{name: "Pod replaced", mutate: func(_ *juneau.VPN, p *corev1.Pod, _ *juneau.NetworkInterface, _ *juneau.NetworkEndpoint) {
			p.UID = "replacement"
		}},
		{name: "NIC wrong subnet", mutate: func(_ *juneau.VPN, _ *corev1.Pod, n *juneau.NetworkInterface, _ *juneau.NetworkEndpoint) {
			n.Spec.Subnet = "other"
		}},
		{name: "NIC not ready", mutate: func(_ *juneau.VPN, _ *corev1.Pod, n *juneau.NetworkInterface, _ *juneau.NetworkEndpoint) {
			n.Status.Phase = juneau.NetworkInterfacePhasePending
		}},
		{name: "endpoint wrong owner", mutate: func(_ *juneau.VPN, _ *corev1.Pod, _ *juneau.NetworkInterface, e *juneau.NetworkEndpoint) {
			e.Spec.PodRef.UID = "other"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := juneau.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "site", UID: "vpn-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "tenant", Subnet: "gw"}, Status: juneau.VPNStatus{ObservedGeneration: 1, Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1, Reason: "GatewayReady", LastTransitionTime: metav1.Now()}}}}
			controller := true
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(vpn), Namespace: "site", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: juneau.GroupVersion.String(), Kind: "VPN", Name: vpn.Name, UID: vpn.UID, Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
			nic := &juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: networkInterfaceNameForPod(pod.Name, "eth0"), Namespace: "site", Generation: 1}, Spec: juneau.NetworkInterfaceSpec{NodeName: "node-a", Subnet: "gw", PodRef: juneau.NetworkInterfacePodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, ObservedGeneration: 1, Address: "10.1.0.5/24"}}
			ep := &juneau.NetworkEndpoint{ObjectMeta: metav1.ObjectMeta{Name: pod.Name + ".eth0", Namespace: "site"}, Spec: juneau.NetworkEndpointSpec{Kind: juneau.EndpointKindPod, NodeName: "node-a", Subnet: "gw", Address: "10.1.0.5/24", MACAddress: "02:00:00:00:00:05", PodRef: &juneau.NetworkEndpointPodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}}
			if tc.mutate != nil {
				tc.mutate(vpn, pod, nic, ep)
			}
			dst := tc.dst
			if dst == "" {
				dst = "192.0.2.0/24"
			}
			rt := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "site", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "tenant", Routes: []juneau.Route{{Dst: dst, Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: "branch"}}}}}, Status: juneau.RouteTableStatus{TableID: 9}}
			objects := []client.Object{&juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}}, &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "tenant", CIDR: "10.1.0.0/24"}, Status: juneau.SubnetStatus{VNI: 17, GatewayMAC: "02:00:00:00:00:01", Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionTrue, ObservedGeneration: 1, Reason: "Ready", LastTransitionTime: metav1.Now()}}}}, vpn, pod, nic, ep, rt}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithStatusSubresource(rt).WithIndex(&juneau.Subnet{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.Subnet).Spec.Vpc} }).WithIndex(&juneau.L2Network{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.L2Network).Spec.Vpc} }).Build()
			r := &RouteTableReconciler{Client: cl, Scheme: scheme}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rt.Name}}); err != nil {
				t.Fatal(err)
			}
			if err := cl.Get(context.Background(), client.ObjectKey{Name: rt.Name}, rt); err != nil {
				t.Fatal(err)
			}
			route := getRoute(rt.Status.Routes, dst)
			if tc.ready {
				if route == nil || route.Subnet != "gw" {
					t.Fatalf("VPN route missing or not resolved: %+v", rt.Status.Routes)
				}
			} else {
				if route != nil {
					t.Fatalf("unsafe VPN route installed: %+v", route)
				}
				if len(rt.Status.Conditions) == 0 || !strings.Contains(rt.Status.Conditions[0].Message, "VPN") {
					t.Fatalf("not marked NotReady: %+v", rt.Status.Conditions)
				}
			}
		})
	}
}
