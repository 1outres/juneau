package reconciler

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTransitVPNFanOutIgnoresOrdinaryPods(t *testing.T) {
	r := newTgwFibFixture(t, &juneau.TransitGatewayRouteTable{ObjectMeta: metav1.ObjectMeta{Name: "table"}})
	if keys := r.FanOutVPNRouteTables(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "ordinary"}}); len(keys) != 0 {
		t.Fatalf("ordinary Pod triggered transit route updates: %v", keys)
	}
	if keys := r.FanOutVPNRouteTables(&juneau.VPN{}); len(keys) != 1 || keys[0] != "table" {
		t.Fatalf("VPN did not trigger transit route updates: %v", keys)
	}
}

func TestTransitVPNRouteUsesAttachedGatewayIdentity(t *testing.T) {
	ready := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Namespace: "site", Name: "branch", UID: "vpn-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "home", Subnet: "gw"}, Status: juneau.VPNStatus{ObservedGeneration: 1, Conditions: ready}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "site", Name: vpnGatewayPodName(vpn), UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "VPN", Name: vpn.Name, UID: vpn.UID}}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	gw := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "home"}, Status: juneau.SubnetStatus{VNI: 91, GatewayMAC: "02:00:00:00:00:01", Conditions: ready}}
	nic := &juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: pod.Name + ".eth0", Namespace: "site", Generation: 1}, Spec: juneau.NetworkInterfaceSpec{NodeName: "node-a", Subnet: "gw", PodRef: juneau.NetworkInterfacePodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, ObservedGeneration: 1, Address: "10.1.0.5/24"}}
	ep := &juneau.NetworkEndpoint{ObjectMeta: metav1.ObjectMeta{Name: pod.Name + ".eth0", Namespace: "site"}, Spec: juneau.NetworkEndpointSpec{Kind: juneau.EndpointKindPod, NodeName: "node-a", Subnet: "gw", Address: "10.1.0.5/24", MACAddress: "02:00:00:00:00:05", PodRef: &juneau.NetworkEndpointPodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}}
	attachment := &juneau.TransitGatewayAttachment{ObjectMeta: metav1.ObjectMeta{Name: "attach", Generation: 1}, Spec: juneau.TransitGatewayAttachmentSpec{Vpc: "home"}, Status: juneau.TransitGatewayAttachmentStatus{ObservedGeneration: 1, Conditions: ready}}
	r := &TgwFib{client: newFibFixture(t, vpn, pod, gw, nic, ep, attachment).client}
	route := &juneau.ResolvedTransitGatewayRoute{Dst: "192.0.2.0/24", Attachment: "attach", Subnet: "gw", Origin: juneau.TransitGatewayRouteOriginStatic, VPN: &juneau.VPNReference{Namespace: "site", Name: "branch"}}
	val, err := r.buildFibVal(context.Background(), route)
	if err != nil || val.Type != fibRouteTypeVPN || val.SubnetId != 91 || val.Dmac != [6]byte{2, 0, 0, 0, 0, 5} || val.VpnId.Bytes != vpnIdentity(vpn.UID) {
		t.Fatalf("VPN transit FIB = %+v, %v", val, err)
	}
	route.Subnet = "other"
	if _, err := r.buildFibVal(context.Background(), route); err == nil {
		t.Fatal("stale gateway subnet accepted")
	}
	route.Subnet = "gw"
	attachment.Spec.Vpc = "other"
	if err := r.client.Update(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	if _, err := r.buildFibVal(context.Background(), route); err == nil {
		t.Fatal("foreign attachment accepted")
	}
}
