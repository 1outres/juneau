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

func TestVPNGatewaySubnetRecoversFromOwnPendingRouteAfterUpdates(t *testing.T) {
	for _, tc := range []struct {
		name, acl, routeTable string
		aclID                 uint32
	}{
		{name: "network ACL update", acl: "restricted", aclID: 42},
		{name: "unallocated network ACL", acl: "restricted"},
		{name: "gateway route table update", routeTable: "gateway"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			if err := juneau.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant", UID: "vpn-uid"}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "inside"}}
			vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{VpcID: 8, MainRouteTable: "main", Conditions: []metav1.Condition{{Type: juneau.VpcStatusReady, Status: metav1.ConditionFalse, Reason: vpcReasonRouteTableNotReady}}}}
			subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "inside", Generation: 2}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.0.0/24", NetworkACL: tc.acl, RouteTable: tc.routeTable}, Status: juneau.SubnetStatus{VNI: 9, Gateway: "10.0.0.1", GatewayMAC: "02:00:00:00:00:01", Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionTrue, ObservedGeneration: 1, Reason: subnetReasonReconcileSucceeded}}}}
			pending := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main", Generation: 1}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "tenant", Name: "branch"}}}}}, Status: juneau.RouteTableStatus{TableID: 10, PendingVPN: "tenant/branch", Conditions: []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionFalse, ObservedGeneration: 1, Reason: routeTableReasonVPNEndpointPending}}}}
			objects := []client.Object{vpn, vpc, subnet, pending}
			if tc.acl != "" {
				objects = append(objects, &juneau.NetworkACL{ObjectMeta: metav1.ObjectMeta{Name: tc.acl}, Spec: juneau.NetworkACLSpec{Vpc: "vpc"}, Status: juneau.NetworkACLStatus{ACLID: tc.aclID, RulesetVersion: 3}})
			}
			if tc.routeTable != "" {
				gateway := pending.DeepCopy()
				gateway.Name = tc.routeTable
				objects = append(objects, gateway)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(subnet, pending).WithObjects(objects...).Build()
			r := &SubnetReconciler{Client: c, Scheme: scheme}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: subnet.Name}}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKeyFromObject(subnet), subnet); err != nil {
				t.Fatal(err)
			}
			if conditionReady(subnet.Status.Conditions, juneau.SubnetStatusReady, subnet.Generation) != (tc.acl == "" || tc.aclID != 0) {
				t.Fatalf("gateway Subnet readiness ignored pending VPN or unresolved ACL: %+v", subnet.Status)
			}
			if tc.acl != "" && (subnet.Status.NetworkACL == nil || subnet.Status.NetworkACL.Name != tc.acl || subnet.Status.NetworkACL.ACLID != tc.aclID) {
				t.Fatalf("updated ACL was not published: %+v", subnet.Status.NetworkACL)
			}
			if tc.aclID == 0 && tc.acl != "" {
				return
			}
			pending.Status.PendingVPN = "tenant/other"
			if err := c.Status().Update(ctx, pending); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: subnet.Name}}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKeyFromObject(subnet), subnet); err != nil {
				t.Fatal(err)
			}
			if conditionReady(subnet.Status.Conditions, juneau.SubnetStatusReady, subnet.Generation) {
				t.Fatal("an unrelated pending VPN cannot bootstrap the gateway Subnet")
			}
		})
	}
}

func TestVPNDoesNotDeleteHealthyGatewayOnTransientSubnetDependency(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "branch", Namespace: "tenant", UID: "vpn-uid", Finalizers: []string{vpnFinalizer}}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "inside"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(vpn), Namespace: vpn.Namespace, UID: "pod-uid", Annotations: map[string]string{juneau.PodAnnotationNetworks: `[{"interface":"eth0","subnet":"inside"},{"interface":"ext0","elasticIP":"` + vpnEIPName(vpn) + `"}]`}, OwnerReferences: []metav1.OwnerReference{{APIVersion: juneau.GroupVersion.String(), Kind: "VPN", Name: vpn.Name, UID: vpn.UID, Controller: new(bool)}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	*pod.OwnerReferences[0].Controller = true
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(vpn).WithObjects(vpn, pod,
		&juneau.AllocationPool{ObjectMeta: metav1.ObjectMeta{Name: "tunnels"}, Spec: juneau.AllocationPoolSpec{Type: juneau.AllocationTypeIP, IP: &juneau.AllocationPoolIPSpec{CIDRs: []string{"169.254.1.0/29"}}}},
		&juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{VpcID: 8, MainRouteTable: "main", Conditions: []metav1.Condition{{Type: juneau.VpcStatusReady, Status: metav1.ConditionFalse, Reason: vpcReasonRouteTableNotReady}}}},
		&juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "main"}, Spec: juneau.RouteTableSpec{Vpc: "vpc", Routes: []juneau.Route{{Dst: "192.0.2.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: "tenant", Name: "branch"}}}}}, Status: juneau.RouteTableStatus{TableID: 10, PendingVPN: "tenant/branch", Conditions: []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionFalse, Reason: routeTableReasonVPNEndpointPending}}}},
		&juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "inside"}, Spec: juneau.SubnetSpec{Vpc: "vpc"}, Status: juneau.SubnetStatus{VNI: 9, Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionFalse, Reason: subnetReasonVpcNotReady}}}},
		&juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: networkInterfaceNameForPod(pod.Name, "eth0"), Namespace: vpn.Namespace}, Spec: juneau.NetworkInterfaceSpec{Subnet: "inside", PodRef: juneau.NetworkInterfacePodReference{Name: pod.Name, UID: string(pod.UID), Interface: "eth0"}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady}},
		&juneau.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: networkInterfaceNameForPod(pod.Name, "ext0"), Namespace: vpn.Namespace}, Spec: juneau.NetworkInterfaceSpec{ElasticIP: vpnEIPName(vpn), PodRef: juneau.NetworkInterfacePodReference{Name: pod.Name, UID: string(pod.UID), Interface: "ext0"}}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, Address: "203.0.113.10/32"}},
	).Build()
	r := &VPNReconciler{Client: c, Scheme: scheme, TunnelPool: "tunnels", GatewayImage: "gateway"}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpn)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatalf("gateway was deleted on temporary Subnet status change: %v", err)
	}
	var changed juneau.Subnet
	if err := c.Get(ctx, client.ObjectKey{Name: "inside"}, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Spec.NetworkACL = "restricted"
	if err := c.Update(ctx, &changed); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpn)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err == nil {
		t.Fatal("gateway continued forwarding while its new ACL was unresolved")
	}
}
