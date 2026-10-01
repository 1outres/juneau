package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNWaitKeepsOnlyAllocatedAddresses(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = juneau.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: "uid-a"}, Spec: juneau.VPNSpec{ExternalNetwork: "outside"}, Status: juneau.VPNStatus{PublicIP: "203.0.113.5", LocalTunnelIP: "169.254.1.1", RemoteTunnelIP: "169.254.1.2"}}
	local := vpnClaim(vpn, "old-pool", "local")
	remote := vpnClaim(vpn, "old-pool", "remote")
	for _, claim := range []*juneau.AllocationClaim{local, remote} {
		claim.Status.Phase = juneau.AllocationClaimPhaseAllocated
		claim.Status.Conditions = []metav1.Condition{{Type: juneau.AllocationClaimStatusReady, Status: metav1.ConditionTrue, Reason: "Allocated"}}
	}
	local.Status.Value.IP = "169.254.1.1"
	remote.Status.Value.IP = "169.254.1.2"
	controller := true
	eip := &juneau.ElasticIP{ObjectMeta: metav1.ObjectMeta{Name: vpnEIPName(vpn), Namespace: vpn.Namespace, OwnerReferences: []metav1.OwnerReference{{APIVersion: juneau.GroupVersion.String(), Kind: "VPN", Name: vpn.Name, UID: vpn.UID, Controller: &controller}}}, Spec: juneau.ElasticIPSpec{ExternalNetwork: "outside"}, Status: juneau.ElasticIPStatus{Address: "203.0.113.5", Phase: juneau.ElasticIPPhaseAvailable, Conditions: []metav1.Condition{{Type: "Allocated", Status: metav1.ConditionTrue, Reason: "Allocated"}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(vpn, &juneau.AllocationClaim{}).WithObjects(vpn, local, remote, eip).Build()
	r := &VPNReconciler{Client: c, Scheme: scheme}
	key := client.ObjectKeyFromObject(vpn)
	check := func(public, localIP, remoteIP string) {
		t.Helper()
		var got juneau.VPN
		if err := c.Get(ctx, key, &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.PublicIP != public || got.Status.LocalTunnelIP != localIP || got.Status.RemoteTunnelIP != remoteIP || conditionReady(got.Status.Conditions, "Ready", got.Generation) {
			t.Fatalf("unexpected status after waiting: %+v", got.Status)
		}
	}
	wait := func(stopped bool) {
		t.Helper()
		if err := c.Get(ctx, key, vpn); err != nil {
			t.Fatal(err)
		}
		var err error
		if stopped {
			_, err = r.waitStopped(ctx, vpn, "SecretMissing", "secret missing")
		} else {
			_, err = r.wait(ctx, vpn, "Starting", "starting")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	wait(true)
	check("203.0.113.5", "169.254.1.1", "169.254.1.2")
	if err := c.Get(ctx, client.ObjectKey{Name: remote.Name}, remote); err != nil {
		t.Fatalf("remote %q, uid %q: %v", remote.Name, vpn.UID, err)
	}
	remote.Status.Value.IP = local.Status.Value.IP
	if err := c.Status().Update(ctx, remote); err != nil {
		t.Fatal(err)
	}
	wait(false)
	check("203.0.113.5", "", "")
	remote.Status.Value.IP = "169.254.1.2"
	if err := c.Status().Update(ctx, remote); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, local); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, eip); err != nil {
		t.Fatal(err)
	}
	wait(false)
	check("", "", "169.254.1.2")
	foreign := vpnClaim(vpn, "old-pool", "local")
	foreign.Labels[vpnOwnerUIDLabel] = "other-uid"
	foreign.Status = *local.Status.DeepCopy()
	if err := c.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	foreignEIP := eip.DeepCopy()
	foreignEIP.ResourceVersion = ""
	foreignEIP.OwnerReferences[0].UID = "other-uid"
	if err := c.Create(ctx, foreignEIP); err != nil {
		t.Fatal(err)
	}
	wait(false)
	check("", "", "169.254.1.2")
}
