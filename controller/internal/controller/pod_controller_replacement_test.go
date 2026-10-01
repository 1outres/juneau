package controller

import (
	"context"
	"testing"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPodControllerDeletesNICFromPreviousPodWithSameName(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := juneau.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	isController := true
	stale := &juneau.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway.eth0", Namespace: "tenant", OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "gateway", UID: "old-pod", Controller: &isController}}},
		Spec:       juneau.NetworkInterfaceSpec{PodRef: juneau.NetworkInterfacePodReference{Name: "gateway", UID: "old-pod", Interface: "eth0"}, Subnet: "net"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stale).Build()
	r := &PodReconciler{Client: c, Scheme: scheme}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant", UID: "new-pod"}, Spec: corev1.PodSpec{NodeName: "node-a"}}
	attachment := juneau.PodNetworkAttachment{Interface: "eth0", Subnet: "net"}
	if err := r.applyNetworkInterface(ctx, pod, attachment); err != errOldNetworkInterface {
		t.Fatalf("expected the old NIC to be removed before creating a new one, got %v", err)
	}
	var nic juneau.NetworkInterface
	key := client.ObjectKeyFromObject(stale)
	if err := c.Get(ctx, key, &nic); !apierrors.IsNotFound(err) {
		t.Fatalf("old NIC remains after replacement: %v", err)
	}
	if err := r.applyNetworkInterface(ctx, pod, attachment); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, key, &nic); err != nil {
		t.Fatal(err)
	}
	if nic.Spec.PodRef.UID != string(pod.UID) {
		t.Fatalf("new NIC belongs to %q, want %q", nic.Spec.PodRef.UID, pod.UID)
	}
}
