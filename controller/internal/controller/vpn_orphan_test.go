package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPNOrphanCleanupDoesNotDeleteAlteredClaim(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = juneau.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	old := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: "old-uid"}}
	claim := vpnClaim(old, "tunnels", "local")
	claim.Spec.RequestedIP = new(string)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(claim).Build()
	r := &VPNReconciler{Client: c, Scheme: s}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(old)}); err != nil {
		t.Fatal(err)
	}
	var remaining juneau.AllocationClaim
	if err := c.Get(ctx, client.ObjectKeyFromObject(claim), &remaining); err != nil {
		t.Fatal("altered claim was deleted:", err)
	}
}

func TestVPNOrphanClaimWaitsForPodAndEIP(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = juneau.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	old := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant", UID: "old-uid"}}
	claim := vpnClaim(old, "tunnels", "local")
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: vpnPodName(old), Namespace: old.Namespace}}
	eip := &juneau.ElasticIP{ObjectMeta: metav1.ObjectMeta{Name: vpnEIPName(old), Namespace: old.Namespace}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(claim, pod, eip).Build()
	r := &VPNReconciler{Client: c, Scheme: s, TunnelPool: "tunnels"}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(old)}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Name: claim.Name}, claim); err != nil {
		t.Fatal("claim released while orphan gateway may still be running")
	}
	if err := c.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Name: claim.Name}, claim); err != nil {
		t.Fatal("claim released while public address may still be held")
	}
	if err := c.Delete(ctx, eip); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Name: claim.Name}, claim); err == nil {
		t.Fatal("orphan claim leaked")
	}
}
