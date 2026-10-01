package controller

import (
	"context"
	"testing"
	"time"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNDeletionKeepsClaimsUntilGatewayAndEIPGone(t *testing.T) {
	for _, pool := range []string{"different-pool", ""} {
		t.Run(pool, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = juneau.AddToScheme(scheme)
			now := metav1.NewTime(time.Now())
			vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: "uid-a", Finalizers: []string{vpnFinalizer}, DeletionTimestamp: &now}}
			local := vpnClaim(vpn, "tunnels", "local")
			remote := vpnClaim(vpn, "tunnels", "remote")
			controller := true
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(vpn), Namespace: vpn.Namespace, OwnerReferences: []metav1.OwnerReference{{APIVersion: juneau.GroupVersion.String(), Kind: "VPN", Name: vpn.Name, UID: vpn.UID, Controller: &controller}}}}
			eip := &juneau.ElasticIP{ObjectMeta: metav1.ObjectMeta{Name: vpnEIPName(vpn), Namespace: vpn.Namespace, OwnerReferences: pod.OwnerReferences}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(vpn).WithObjects(vpn, local, remote, pod, eip).Build()
			r := &VPNReconciler{Client: c, Scheme: scheme, TunnelPool: pool}
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpn)}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, req.NamespacedName, vpn); err != nil {
				t.Fatal("finalizer removed before children were deleted: ", err)
			}
			var claim juneau.AllocationClaim
			if err := c.Get(ctx, client.ObjectKey{Name: local.Name}, &claim); err != nil {
				t.Fatal("claim released while gateway may hold its address: ", err)
			}
			for i := 0; i < 7; i++ {
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Get(ctx, client.ObjectKey{Name: local.Name}, &claim); err == nil {
				t.Fatal("claim leaked after teardown")
			}
			if err := c.Get(ctx, req.NamespacedName, vpn); err == nil {
				t.Fatal("finalizer not removed")
			}
		})
	}
}

func TestVPNDeletionRejectsChildWithForgedOwnerReference(t *testing.T) {
	for _, ref := range []metav1.OwnerReference{
		{APIVersion: "other/v1", Kind: "VPN", Name: "other-site", UID: "uid-a"},
		{APIVersion: juneau.GroupVersion.String(), Kind: "VPN", Name: "site", UID: "uid-a"},
	} {
		t.Run(ref.APIVersion+"/"+ref.Name, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = juneau.AddToScheme(scheme)
			now := metav1.NewTime(time.Now())
			vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: "uid-a", Finalizers: []string{vpnFinalizer}, DeletionTimestamp: &now}}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(vpn), Namespace: vpn.Namespace, OwnerReferences: []metav1.OwnerReference{ref}}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(vpn).WithObjects(vpn, pod).Build()
			r := &VPNReconciler{Client: c, Scheme: scheme}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpn)}); err != nil {
				t.Fatal(err)
			}
			var remaining corev1.Pod
			if err := c.Get(ctx, client.ObjectKeyFromObject(pod), &remaining); err != nil {
				t.Fatal("foreign Pod was deleted:", err)
			}
		})
	}
}

func TestVPNDeletionRejectsClaimWithConflictingIdentity(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*juneau.AllocationClaim)
	}{
		{"wrong attribute", func(c *juneau.AllocationClaim) { c.Spec.Attribute = "status.otherTunnelIP" }},
		{"wrong owner key", func(c *juneau.AllocationClaim) { c.Labels[vpnOwnerKeyLabel] = "other" }},
		{"wrong api version", func(c *juneau.AllocationClaim) { c.Spec.ResourceRef.APIVersion = "other/v1" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = juneau.AddToScheme(scheme)
			now := metav1.NewTime(time.Now())
			vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: "uid-a", Finalizers: []string{vpnFinalizer}, DeletionTimestamp: &now}}
			claim := vpnClaim(vpn, "old-pool", "local")
			change.edit(claim)
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(vpn).WithObjects(vpn, claim).Build()
			r := &VPNReconciler{Client: c, Scheme: scheme}
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpn)}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			var got juneau.AllocationClaim
			if err := c.Get(ctx, client.ObjectKey{Name: claim.Name}, &got); err != nil {
				t.Fatal("conflicting claim was deleted:", err)
			}
			var remaining juneau.VPN
			if err := c.Get(ctx, req.NamespacedName, &remaining); err != nil {
				t.Fatal("VPN was deleted with conflicting claim:", err)
			}
		})
	}
}
