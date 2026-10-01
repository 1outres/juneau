package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func peeringRecoveryFixture(t *testing.T) (*RouteTableReconciler, *juneau.VPN, *corev1.Pod, *juneau.NetworkInterface, *juneau.NetworkEndpoint, *juneau.RouteTable, *juneau.RouteTable) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ready := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "site", UID: "vpn-uid", Generation: 1}, Spec: juneau.VPNSpec{Vpc: "home", Subnet: "gw"}, Status: juneau.VPNStatus{ObservedGeneration: 1, Conditions: ready}}
	controller := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(vpn), Namespace: vpn.Namespace, UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: juneau.GroupVersion.String(), Kind: "VPN", Name: vpn.Name, UID: vpn.UID, Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	nic := &juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: networkInterfaceNameForPod(pod.Name, "eth0"), Namespace: pod.Namespace, Generation: 1}, Spec: juneau.NetworkInterfaceSpec{NodeName: "node-a", Subnet: "gw", PodRef: juneau.NetworkInterfacePodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, ObservedGeneration: 1, Address: "10.1.0.5/24"}}
	ep := &juneau.NetworkEndpoint{ObjectMeta: metav1.ObjectMeta{Name: pod.Name + ".eth0", Namespace: pod.Namespace}, Spec: juneau.NetworkEndpointSpec{Kind: juneau.EndpointKindPod, NodeName: "node-a", Subnet: "gw", Address: "10.1.0.5/24", MACAddress: "02:00:00:00:00:05", PodRef: &juneau.NetworkEndpointPodReference{UID: string(pod.UID), Name: pod.Name, Interface: "eth0"}}}
	gw := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "gw", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "home", CIDR: "10.1.0.0/24"}, Status: juneau.SubnetStatus{VNI: 17, GatewayMAC: "02:00:00:00:00:01", Conditions: ready}}
	peering := &juneau.VpcPeering{ObjectMeta: metav1.ObjectMeta{Name: "direct", Generation: 1}, Spec: juneau.VpcPeeringSpec{Requester: juneau.VpcPeeringEndpoint{Vpc: "home"}, Accepter: juneau.VpcPeeringEndpoint{Vpc: "other"}}, Status: juneau.VpcPeeringStatus{Conditions: ready}}
	source := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "source", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "home", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: vpn.Namespace, Name: vpn.Name}}}}}, Status: juneau.RouteTableStatus{TableID: 8, ObservedGeneration: 1, Routes: []juneau.Route{{Dst: "192.0.2.0/24", Subnet: gw.Name, Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: vpn.Namespace, Name: vpn.Name}}}}, Conditions: ready}}
	peer := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "peer", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "other", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVpcPeering, VpcPeering: peering.Name}}}}, Status: juneau.RouteTableStatus{TableID: 9}}
	unrelated := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "elsewhere"}, Status: juneau.RouteTableStatus{TableID: 10}}
	indirectPeering := &juneau.VpcPeering{ObjectMeta: metav1.ObjectMeta{Name: "indirect", Generation: 1}, Spec: juneau.VpcPeeringSpec{Requester: juneau.VpcPeeringEndpoint{Vpc: "other"}, Accepter: juneau.VpcPeeringEndpoint{Vpc: "third"}}, Status: juneau.VpcPeeringStatus{Conditions: ready}}
	indirectTable := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "third", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "third", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVpcPeering, VpcPeering: indirectPeering.Name}}}}, Status: juneau.RouteTableStatus{TableID: 11}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpn, pod, nic, ep, gw, peering, source, peer, unrelated, indirectPeering, indirectTable, &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "home"}}, &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "other"}}).WithStatusSubresource(vpn, pod, nic, gw, source, peer, &juneau.Vpc{}).WithIndex(&juneau.Subnet{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.Subnet).Spec.Vpc} }).WithIndex(&juneau.L2Network{}, "spec.vpc", func(o client.Object) []string { return []string{o.(*juneau.L2Network).Spec.Vpc} }).Build()
	return &RouteTableReconciler{Client: cl, Scheme: scheme}, vpn, pod, nic, ep, source, peer
}

func TestPeeringVPNDependencyFanout(t *testing.T) {
	r, vpn, pod, nic, ep, source, peer := peeringRecoveryFixture(t)
	ctx := context.Background()
	want := map[string]bool{source.Name: true, peer.Name: true}
	for name, requests := range map[string][]reconcile.Request{
		"VPN":              r.mapVPNToRouteTables(ctx, vpn),
		"gateway Pod":      r.mapVPNGatewayPodToRouteTables(ctx, pod),
		"gateway NIC":      r.mapVPNGatewayNICToRouteTables(ctx, nic),
		"gateway endpoint": r.mapNetworkEndpointToRouteTables(ctx, ep),
	} {
		for _, req := range requests {
			delete(want, req.Name)
		}
		if len(want) != 0 {
			t.Fatalf("%s did not enqueue source and direct peer: %+v", name, requests)
		}
		want = map[string]bool{source.Name: true, peer.Name: true}
		for _, req := range requests {
			if req.Name == "unrelated" || req.Name == "third" {
				t.Fatalf("%s enqueued unrelated or indirect table", name)
			}
		}
	}
	requests := r.mapVPNSourceRouteTableToPeeringRouteTables(ctx, source)
	if len(requests) != 1 || requests[0].Name != peer.Name {
		t.Fatalf("source table change = %+v, want only peer", requests)
	}
	if requests := r.mapVPNSourceRouteTableToPeeringRouteTables(ctx, peer); len(requests) != 0 {
		t.Fatalf("peer status update loop: %+v", requests)
	}
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	removed := source.DeepCopy()
	removed.Spec.Routes = nil
	r.vpnSourceTableWatchHandler().Update(ctx, event.UpdateEvent{ObjectOld: source, ObjectNew: removed}, q)
	if q.Len() != 1 {
		t.Fatalf("removing explicit VPN route enqueued %d requests, want one peer", q.Len())
	}
	item, _ := q.Get()
	q.Done(item)
	if item.Name != peer.Name {
		t.Fatalf("source route removal enqueued %+v", item)
	}
}

func TestPeeringVPNReturnWaitsForMatchingSourceGateway(t *testing.T) {
	r, _, _, _, _, source, peer := peeringRecoveryFixture(t)
	ctx := context.Background()
	source.Status.Routes[0].Subnet = "stale-gateway"
	if err := r.Status().Update(ctx, source); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(peer)}); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(peer), peer); err != nil {
		t.Fatal(err)
	}
	if getRoute(peer.Status.Routes, "192.0.2.0/24") != nil || conditionReady(peer.Status.Conditions, juneau.RouteTableStatusReady, peer.Generation) {
		t.Fatalf("return route installed before source gateway matched VPN: %+v", peer.Status)
	}
}

func TestPeeringPendingVPNKeepsGatewayRoutes(t *testing.T) {
	r, vpn, _, _, _, _, peer := peeringRecoveryFixture(t)
	ctx := context.Background()
	peer.Status.PendingVPN = vpn.Namespace + "/" + vpn.Name
	peer.Status.Conditions = []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionFalse, Reason: routeTableReasonVPNEndpointPending, ObservedGeneration: peer.Generation}}
	if err := r.Status().Update(ctx, peer); err != nil {
		t.Fatal(err)
	}
	v := &VPNReconciler{Client: r.Client, Scheme: r.Scheme}
	pending, err := v.peeringTablePendingOnVPN(ctx, vpn)
	if err != nil || !pending {
		t.Fatalf("pending direct peering VPN route = %v, %v", pending, err)
	}
	peer.Status.Conditions[0].Reason = routeTableReasonNotReady
	if err := r.Status().Update(ctx, peer); err != nil {
		t.Fatal(err)
	}
	pending, err = v.peeringTablePendingOnVPN(ctx, vpn)
	if err != nil || pending {
		t.Fatalf("unrelated failure must not retain gateway routes = %v, %v", pending, err)
	}
}

func TestPeeringSubnetPendingOnlyOnThisVPNCanBeAdvertised(t *testing.T) {
	r, vpn, _, _, _, _, peer := peeringRecoveryFixture(t)
	ctx := context.Background()
	peer.Status.PendingVPN = vpn.Namespace + "/" + vpn.Name
	peer.Status.Conditions = []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionFalse, Reason: routeTableReasonVPNEndpointPending, ObservedGeneration: peer.Generation}}
	if err := r.Status().Update(ctx, peer); err != nil {
		t.Fatal(err)
	}
	vpc := &juneau.Vpc{}
	if err := r.Get(ctx, client.ObjectKey{Name: "other"}, vpc); err != nil {
		t.Fatal(err)
	}
	vpc.Generation = 1
	if err := r.Update(ctx, vpc); err != nil {
		t.Fatal(err)
	}
	vpc.Status.MainRouteTable = peer.Name
	vpc.Status.VpcID = 10
	vpc.Status.Conditions = []metav1.Condition{{Type: juneau.VpcStatusReady, Status: metav1.ConditionFalse, Reason: vpcReasonRouteTableNotReady, ObservedGeneration: 1}}
	if err := r.Status().Update(ctx, vpc); err != nil {
		t.Fatal(err)
	}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "other", Generation: 1}, Spec: juneau.SubnetSpec{Vpc: "other", CIDR: "10.2.0.0/24"}, Status: juneau.SubnetStatus{VNI: 20, GatewayMAC: "02:00:00:00:00:11", Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionFalse, Reason: subnetReasonVpcNotReady, ObservedGeneration: 1}}}}
	if err := r.Create(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	v := &VPNReconciler{Client: r.Client, Scheme: r.Scheme}
	isPending := func() bool {
		t.Helper()
		pending, err := v.peeringSubnetPendingOnVPN(ctx, vpn, subnet)
		if err != nil {
			t.Fatal(err)
		}
		return pending
	}
	if !isPending() {
		t.Fatal("direct peer subnet blocked by own VPN return route must bootstrap advertisement")
	}
	actual := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Env: []corev1.EnvVar{{Name: "VPN_ADVERTISED_ROUTES", Value: `["10.1.0.0/24"]`}}}}}}
	added, err := v.peeringAdvertisementAdded(ctx, vpn, actual, []string{"10.1.0.0/24", subnet.Spec.CIDR})
	if err != nil || !added {
		t.Fatalf("new peer advertisement was suppressed by the gateway pending on its own VPN: %v", err)
	}
	added, err = v.peeringAdvertisementAdded(ctx, vpn, actual, []string{"10.1.0.0/24"})
	if err != nil || added {
		t.Fatalf("no new peer advertisement should trigger a gateway replacement: %v", err)
	}
	peer.Status.PendingVPN = "site/other-vpn"
	if err := r.Status().Update(ctx, peer); err != nil {
		t.Fatal(err)
	}
	if isPending() {
		t.Fatal("other VPN pending route admitted")
	}
	peer.Status.PendingVPN = vpn.Namespace + "/" + vpn.Name
	if err := r.Status().Update(ctx, peer); err != nil {
		t.Fatal(err)
	}
	subnet.Status.Conditions[0].Reason = subnetReasonNotReady
	if err := r.Status().Update(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if isPending() {
		t.Fatal("unrelated subnet failure admitted")
	}
	subnet.Status.Conditions[0].Reason = subnetReasonVpcNotReady
	if err := r.Status().Update(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	peer.Status.PendingVPN = ""
	peer.Status.ObservedGeneration = peer.Generation
	peer.Status.Conditions[0].Status = metav1.ConditionTrue
	peer.Status.Conditions[0].Reason = routeTableReasonReconcileSucceeded
	peer.Status.Routes = []juneau.Route{{Dst: "192.0.2.0/24", Subnet: vpn.Spec.Subnet, Via: juneau.RouteVia{Type: juneau.ViaVpcPeering, VpcPeering: "direct", VPN: &juneau.VPNReference{Namespace: vpn.Namespace, Name: vpn.Name}}}}
	if err := r.Status().Update(ctx, peer); err != nil {
		t.Fatal(err)
	}
	if !isPending() {
		t.Fatal("peer table became Ready before Vpc and Subnet status caught up")
	}
	vpc.Status.Conditions[0].Status = metav1.ConditionTrue
	vpc.Status.Conditions[0].Reason = vpcReasonReconcileSucceeded
	if err := r.Status().Update(ctx, vpc); err != nil {
		t.Fatal(err)
	}
	if !isPending() {
		t.Fatal("Vpc became Ready before peer Subnet status caught up")
	}
	peer.Status.Routes = nil
	if err := r.Status().Update(ctx, peer); err != nil {
		t.Fatal(err)
	}
	if isPending() {
		t.Fatal("Ready table without an active return route admitted")
	}
}

func TestPeeringVPNReturnRouteLossAndRecovery(t *testing.T) {
	for _, dependency := range []string{"VPN", "Pod", "NIC", "endpoint", "source table"} {
		t.Run(dependency, func(t *testing.T) {
			r, vpn, pod, nic, ep, source, peer := peeringRecoveryFixture(t)
			ctx := context.Background()
			reconcilePeer := func(ready bool) {
				t.Helper()
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(peer)}); err != nil {
					t.Fatal(err)
				}
				if err := r.Get(ctx, client.ObjectKeyFromObject(peer), peer); err != nil {
					t.Fatal(err)
				}
				route := getRoute(peer.Status.Routes, "192.0.2.0/24")
				if (route != nil) != ready || conditionReady(peer.Status.Conditions, juneau.RouteTableStatusReady, peer.Generation) != ready {
					t.Fatalf("ready=%v, peer status=%+v", ready, peer.Status)
				}
			}
			reconcilePeer(true)
			switch dependency {
			case "VPN":
				vpn.Status.Conditions[0].Status = metav1.ConditionFalse
				if err := r.Status().Update(ctx, vpn); err != nil {
					t.Fatal(err)
				}
			case "Pod":
				pod.Status.Conditions[0].Status = corev1.ConditionFalse
				if err := r.Status().Update(ctx, pod); err != nil {
					t.Fatal(err)
				}
			case "NIC":
				nic.Status.Phase = juneau.NetworkInterfacePhasePending
				if err := r.Status().Update(ctx, nic); err != nil {
					t.Fatal(err)
				}
			case "endpoint":
				if err := r.Delete(ctx, ep); err != nil {
					t.Fatal(err)
				}
			case "source table":
				source.Status.Routes = nil
				source.Status.Conditions[0].Status = metav1.ConditionFalse
				if err := r.Status().Update(ctx, source); err != nil {
					t.Fatal(err)
				}
			}
			reconcilePeer(false)
			switch dependency {
			case "VPN":
				vpn.Status.Conditions[0].Status = metav1.ConditionTrue
				if err := r.Status().Update(ctx, vpn); err != nil {
					t.Fatal(err)
				}
			case "Pod":
				pod.Status.Conditions[0].Status = corev1.ConditionTrue
				if err := r.Status().Update(ctx, pod); err != nil {
					t.Fatal(err)
				}
			case "NIC":
				nic.Status.Phase = juneau.NetworkInterfacePhaseReady
				if err := r.Status().Update(ctx, nic); err != nil {
					t.Fatal(err)
				}
			case "endpoint":
				ep.ResourceVersion = ""
				if err := r.Create(ctx, ep); err != nil {
					t.Fatal(err)
				}
			case "source table":
				source.Status.Routes = []juneau.Route{{Dst: "192.0.2.0/24", Subnet: "gw", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: vpn.Namespace, Name: vpn.Name}}}}
				source.Status.Conditions[0].Status = metav1.ConditionTrue
				if err := r.Status().Update(ctx, source); err != nil {
					t.Fatal(err)
				}
			}
			reconcilePeer(true)
		})
	}
}
