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

func TestVPNClaimsAreFencedByUIDAndNotOwnedAcrossScopes(t *testing.T) {
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: types.UID("uid-a")}}
	claim := vpnClaim(vpn, "vpn-tunnels", "local")
	if len(claim.OwnerReferences) != 0 {
		t.Fatal("namespaced VPN cannot own cluster-scoped claim")
	}
	if claim.Spec.ResourceRef.Namespace != vpn.Namespace || claim.Spec.ResourceRef.Name != vpn.Name {
		t.Fatalf("wrong resource reference: %+v", claim.Spec.ResourceRef)
	}
	other := vpn.DeepCopy()
	other.UID = "uid-b"
	if claim.Name == vpnClaim(other, "vpn-tunnels", "local").Name {
		t.Fatal("recreated VPN must not inherit previous reservation")
	}
}

func TestVPNWaitsForTwoClaimsAndRejectsForeignClaim(t *testing.T) {
	s := runtime.NewScheme()
	_ = juneau.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: "uid-a"}, Spec: juneau.VPNSpec{Vpc: "vpc", Subnet: "net", ExternalNetwork: "outside", LocalASN: 64512, RemoteASN: 64513, PeerIKEID: "@router", PSKSecretRef: juneau.VPNSecretRef{Name: "psk", Key: "key"}}}
	pool := &juneau.AllocationPool{ObjectMeta: metav1.ObjectMeta{Name: "vpn-tunnels"}, Spec: juneau.AllocationPoolSpec{Type: juneau.AllocationTypeIP, IP: &juneau.AllocationPoolIPSpec{CIDRs: []string{"169.254.50.0/29"}}}}
	vpc := &juneau.Vpc{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Status: juneau.VpcStatus{MainRouteTable: "vpc"}}
	subnet := &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: "net"}, Spec: juneau.SubnetSpec{Vpc: "vpc", CIDR: "10.0.0.0/24"}, Status: juneau.SubnetStatus{Conditions: []metav1.Condition{{Type: juneau.SubnetStatusReady, Status: metav1.ConditionTrue, Reason: "Ready"}}}}
	table := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: "vpc"}, Spec: juneau.RouteTableSpec{Vpc: "vpc"}, Status: juneau.RouteTableStatus{Conditions: []metav1.Condition{{Type: juneau.RouteTableStatusReady, Status: metav1.ConditionTrue, Reason: "Ready"}}, Routes: []juneau.Route{{Dst: "10.0.0.0/24", Via: juneau.RouteVia{Type: juneau.ViaConnected}, Subnet: "net"}}}}
	external := &juneau.ExternalNetwork{ObjectMeta: metav1.ObjectMeta{Name: "outside"}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "psk", Namespace: "tenant"}, Data: map[string][]byte{"key": []byte("secret")}}
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(vpn, &juneau.AllocationClaim{}, &juneau.ElasticIP{}, &juneau.NetworkInterface{}, &corev1.Pod{}).WithObjects(vpn, pool, vpc, subnet, table, external, secret).Build()
	r := &VPNReconciler{Client: c, Scheme: s, TunnelPool: "vpn-tunnels", GatewayImage: "gateway-image"}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpn)}
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	for _, side := range []string{"local", "remote"} {
		var claim juneau.AllocationClaim
		if err := c.Get(context.Background(), client.ObjectKey{Name: vpnClaim(vpn, "vpn-tunnels", side).Name}, &claim); err != nil {
			t.Fatal(err)
		}
		if len(claim.OwnerReferences) != 0 {
			t.Fatal("illegal owner reference")
		}
	}
	var pod corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "tenant", Name: vpnPodName(vpn)}, &pod); err == nil {
		t.Fatal("pod created before allocation")
	}
	var updated juneau.VPN
	if err := c.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.PublicIP != "" || updated.Status.LocalTunnelIP != "" {
		t.Fatalf("premature status: %+v", updated.Status)
	}
	for side, ip := range map[string]string{"local": "169.254.50.1", "remote": "169.254.50.2"} {
		var claim juneau.AllocationClaim
		key := client.ObjectKey{Name: vpnClaim(vpn, "vpn-tunnels", side).Name}
		if err := c.Get(context.Background(), key, &claim); err != nil {
			t.Fatal(err)
		}
		claim.Status.Phase = juneau.AllocationClaimPhaseAllocated
		claim.Status.Value.IP = ip
		claim.Status.Conditions = []metav1.Condition{{Type: juneau.AllocationClaimStatusReady, Status: metav1.ConditionTrue, Reason: "Allocated"}}
		if err := c.Status().Update(context.Background(), &claim); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var eip juneau.ElasticIP
	if err := c.Get(context.Background(), client.ObjectKey{Name: vpnEIPName(vpn), Namespace: vpn.Namespace}, &eip); err != nil {
		t.Fatal(err)
	}
	eip.Status.Address = "203.0.113.20"
	eip.Status.Phase = juneau.ElasticIPPhaseAvailable
	eip.Status.Conditions = []metav1.Condition{{Type: "Allocated", Status: metav1.ConditionTrue, Reason: "Allocated"}}
	if err := c.Status().Update(context.Background(), &eip); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: vpn.Namespace, Name: vpnPodName(vpn)}, &pod); err != nil {
		t.Fatal(err)
	}
	if pod.Spec.Containers[0].ReadinessProbe == nil {
		t.Fatal("gateway Pod has no health probe")
	}
	if err := c.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.LocalTunnelIP != "169.254.50.1" || updated.Status.RemoteTunnelIP != "169.254.50.2" || updated.Status.PublicIP != "203.0.113.20" {
		t.Fatalf("tunnel addresses must be published before the peer connects: %+v", updated.Status)
	}
	pod.UID = "pod-uid"
	if err := c.Update(context.Background(), &pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := c.Status().Update(context.Background(), &pod); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.PublicIP != "203.0.113.20" || conditionReady(updated.Status.Conditions, "Ready", updated.Generation) {
		t.Fatal("allocated address must remain visible while interfaces are not ready")
	}
	for _, nic := range []*juneau.NetworkInterface{
		{ObjectMeta: metav1.ObjectMeta{Name: networkInterfaceNameForPod(pod.Name, "eth0"), Namespace: vpn.Namespace}, Spec: juneau.NetworkInterfaceSpec{PodRef: juneau.NetworkInterfacePodReference{UID: string(pod.UID), Interface: "eth0"}, Subnet: vpn.Spec.Subnet}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady}},
		{ObjectMeta: metav1.ObjectMeta{Name: networkInterfaceNameForPod(pod.Name, "ext0"), Namespace: vpn.Namespace}, Spec: juneau.NetworkInterfaceSpec{PodRef: juneau.NetworkInterfacePodReference{UID: string(pod.UID), Interface: "ext0"}, ElasticIP: eip.Name}, Status: juneau.NetworkInterfaceStatus{Phase: juneau.NetworkInterfacePhaseReady, Address: eip.Status.Address + "/32"}},
	} {
		if err := c.Create(context.Background(), nic); err != nil {
			t.Fatal(err)
		}
		if err := c.Status().Update(context.Background(), nic); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.PublicIP != "203.0.113.20" || conditionReady(updated.Status.Conditions, "Ready", updated.Generation) {
		t.Fatal("allocated address must remain visible without an attached interface")
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: eip.Name, Namespace: eip.Namespace}, &eip); err != nil {
		t.Fatal(err)
	}
	eip.Status.Phase = juneau.ElasticIPPhaseAttached
	eip.Status.Attachment = &juneau.ElasticIPStatusAttachment{Kind: juneau.ElasticIPStatusAttachmentKindNetworkInterface, Name: networkInterfaceNameForPod(pod.Name, "ext0")}
	if err := c.Status().Update(context.Background(), &eip); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, &pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.Conditions[0].Status = corev1.ConditionFalse
	if err := c.Status().Update(context.Background(), &pod); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.PublicIP != "203.0.113.20" || conditionReady(updated.Status.Conditions, "Ready", updated.Generation) {
		t.Fatalf("public endpoint must be known before the peer connects, but not Ready: %+v", updated.Status)
	}
	pod.Status.Conditions[0].Status = corev1.ConditionTrue
	if err := c.Status().Update(context.Background(), &pod); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.PublicIP != "203.0.113.20" || updated.Status.LocalTunnelIP != "169.254.50.1" || updated.Status.RemoteTunnelIP != "169.254.50.2" {
		t.Fatalf("missing endpoint details after readiness: %+v", updated.Status)
	}
	var gatewayNIC juneau.NetworkInterface
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: vpn.Namespace, Name: networkInterfaceNameForPod(pod.Name, "eth0")}, &gatewayNIC); err != nil {
		t.Fatal(err)
	}
	gatewayNIC.Spec.SecurityGroups = []string{"restricted"}
	if err := c.Update(context.Background(), &gatewayNIC); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(&gatewayNIC), &gatewayNIC); err != nil {
		t.Fatal(err)
	}
	gatewayNIC.Status.Phase = juneau.NetworkInterfacePhasePending
	if err := c.Status().Update(context.Background(), &gatewayNIC); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var retained corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(&pod), &retained); err != nil || retained.UID != pod.UID {
		t.Fatalf("updating gateway NIC security groups must not replace the VPN Pod: %v", err)
	}
	var conflicting juneau.AllocationClaim
	if err := c.Get(context.Background(), client.ObjectKey{Name: vpnClaim(vpn, "vpn-tunnels", "local").Name}, &conflicting); err != nil {
		t.Fatal(err)
	}
	conflicting.Labels[vpnOwnerUIDLabel] = "other-uid"
	if err := c.Update(context.Background(), &conflicting); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.LocalTunnelIP != "" || conditionReady(updated.Status.Conditions, "Ready", updated.Generation) {
		t.Fatalf("conflicting claim must not leave a Ready VPN or stale address: %+v", updated.Status)
	}
	if err := c.Delete(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: vpn.Namespace, Name: vpnPodName(vpn)}, &pod); err == nil {
		t.Fatal("gateway continued using a deleted PSK")
	}
}
