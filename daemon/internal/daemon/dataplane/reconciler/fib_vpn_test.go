package reconciler

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFIBRejectsUnreadyOrStaleRouteTable(t *testing.T) {
	rt := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Generation: 3}, Status: juneau.RouteTableStatus{ObservedGeneration: 3, Conditions: []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionTrue, ObservedGeneration: 3}}}}
	if !routeTableReady(rt) {
		t.Fatal("ready table was rejected")
	}
	rt.Status.Conditions[0].Status = metav1.ConditionFalse
	if routeTableReady(rt) {
		t.Fatal("unready table was accepted")
	}
	rt.Status.Conditions[0].Status = metav1.ConditionTrue
	rt.Generation = 4
	if routeTableReady(rt) {
		t.Fatal("stale table was accepted")
	}
}

func TestPendingVPNKeepsOnlyResolvedRoutesAndDropsPendingDestination(t *testing.T) {
	vpn := func(dst, name string) juneau.Route {
		return juneau.Route{Dst: dst, Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: name}}}
	}
	a := vpn("192.0.2.0/24", "a")
	b := vpn("198.19.58.0/24", "b")
	connected := juneau.Route{Dst: "10.93.1.0/24", Via: juneau.RouteVia{Type: juneau.ViaConnected}, Subnet: "inside"}
	resolvedA := a
	resolvedA.Subnet = "inside"
	rt := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Generation: 2}, Spec: juneau.RouteTableSpec{Routes: []juneau.Route{a, b}}, Status: juneau.RouteTableStatus{TableID: 7, ObservedGeneration: 2, PendingVPN: "site/b", Routes: []juneau.Route{connected, resolvedA}, Conditions: []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionFalse, Reason: "VPNEndpointPending", ObservedGeneration: 2}}}}
	pending, ok := pendingVPNRoutes(rt)
	if !ok || len(pending) != 1 || pending[0].Dst != b.Dst {
		t.Fatalf("must keep A and blackhole B: %v, %v", pending, ok)
	}
	rt.Status.Routes = []juneau.Route{connected}
	if _, ok := pendingVPNRoutes(rt); ok {
		t.Fatal("missing non-pending VPN route accepted")
	}
	rt.Status.Routes = []juneau.Route{connected, resolvedA, b}
	if _, ok := pendingVPNRoutes(rt); ok {
		t.Fatal("pending route leaked into installed status")
	}
	rt.Status.Routes = []juneau.Route{connected, resolvedA, vpn("203.0.113.0/24", "unknown")}
	if _, ok := pendingVPNRoutes(rt); ok {
		t.Fatal("VPN route absent from spec accepted")
	}
	rt.Status.Routes = []juneau.Route{connected, resolvedA}
	rt.Status.PendingVPN = "site/unknown"
	if _, ok := pendingVPNRoutes(rt); ok {
		t.Fatal("unknown pending key accepted")
	}
	rt.Status.PendingVPN = "site/b"
	rt.Status.ObservedGeneration = 1
	if _, ok := pendingVPNRoutes(rt); ok {
		t.Fatal("stale status accepted")
	}
}

func TestVPNFIBFanOutOnlyForVPNResources(t *testing.T) {
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Namespace: "site", Name: "branch", UID: "vpn-uid"}}
	r := newFibFixture(t, &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "rt"}, Spec: juneau.RouteTableSpec{Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: vpn.Namespace, Name: vpn.Name}}}}}})
	if keys := r.FanOutVPNRouteTables(vpn); len(keys) != 1 || keys[0] != "rt" {
		t.Fatalf("VPN fan-out = %v", keys)
	}
	if keys := r.FanOutVPNRouteTables(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "site", Name: "ordinary"}}); len(keys) != 0 {
		t.Fatalf("ordinary Pod triggered VPN FIB: %v", keys)
	}
}

func TestBuildVPNFibValTargetsGatewayPodAndCarriesIdentity(t *testing.T) {
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Namespace: "site", Name: "branch", UID: "vpn-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "tenant", Subnet: "gw"}, Status: juneau.VPNStatus{ObservedGeneration: 1, Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1, Reason: "GatewayReady"}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "site", Name: vpnGatewayPodName(vpn), UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "VPN", Name: vpn.Name, UID: vpn.UID}}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "tenant"}, Status: juneau.SubnetStatus{VNI: 91, GatewayMAC: "02:00:00:00:00:01", Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionTrue, ObservedGeneration: 1, Reason: "Ready"}}}}
	nic := &juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: pod.Name + ".eth0", Namespace: "site", Generation: 1}, Spec: juneau.NetworkInterfaceSpec{NodeName: "node-a", Subnet: "gw", PodRef: juneau.NetworkInterfacePodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, ObservedGeneration: 1, Address: "10.1.0.5/24"}}
	ep := &juneau.NetworkEndpoint{ObjectMeta: metav1.ObjectMeta{Name: pod.Name + ".eth0", Namespace: "site"}, Spec: juneau.NetworkEndpointSpec{Kind: juneau.EndpointKindPod, NodeName: "node-a", Subnet: "gw", Address: "10.1.0.5/24", MACAddress: "02:00:00:00:00:05", PodRef: &juneau.NetworkEndpointPodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}}
	route := &juneau.Route{Dst: "192.0.2.0/24", Subnet: "gw", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "site", Name: "branch"}}}
	peering := &juneau.VpcPeering{ObjectMeta: metav1.ObjectMeta{Name: "direct"}, Spec: juneau.VpcPeeringSpec{Requester: juneau.VpcPeeringEndpoint{Vpc: "tenant"}, Accepter: juneau.VpcPeeringEndpoint{Vpc: "peer"}}, Status: juneau.VpcPeeringStatus{Conditions: []metav1.Condition{{Type: juneau.VpcPeeringStatusReady, Status: metav1.ConditionTrue}}}}
	r := newFibFixture(t, vpn, pod, subnet, nic, ep, peering)
	val, skip, err := r.buildFibVal(context.Background(), route)
	if err != nil || skip {
		t.Fatalf("build VPN FIB: val=%+v, skip=%v, err=%v", val, skip, err)
	}
	if val.Type != fibRouteTypeVPN || val.SubnetId != 91 || val.Dmac != [6]byte{2, 0, 0, 0, 0, 5} || val.Smac != [6]byte{2, 0, 0, 0, 0, 1} || val.VpnId.Bytes != vpnIdentity(vpn.UID) {
		t.Fatalf("wrong VPN next hop: %+v", val)
	}
	peered := route.DeepCopy()
	peered.Via.Type = juneau.ViaVpcPeering
	peered.Via.VpcPeering = "direct"
	val, skip, err = r.buildFibVal(context.Background(), peered)
	if err != nil || skip || val.Type != fibRouteTypePeeringVPN || val.Dmac != [6]byte{2, 0, 0, 0, 0, 5} || val.VpnId.Bytes != vpnIdentity(vpn.UID) {
		t.Fatalf("wrong direct peer VPN next hop: %+v, skip=%v, err=%v", val, skip, err)
	}
	peered.Subnet = "wrong"
	if _, _, err := r.buildFibVal(context.Background(), peered); err == nil {
		t.Fatal("accepted stale peer VPN gateway Subnet")
	}
	ep.Spec.PodRef.UID = "replaced"
	r = newFibFixture(t, vpn, pod, subnet, nic, ep, peering)
	if _, _, err := r.buildFibVal(context.Background(), route); err == nil {
		t.Fatal("accepted stale gateway endpoint")
	}
}
