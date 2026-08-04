/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Pod controller", func() {
	ctx := context.Background()

	newPod := func(name string, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Labels: labels},
			Spec: corev1.PodSpec{
				NodeName:   "node-a",
				Containers: []corev1.Container{{Name: "compute", Image: "busybox"}},
			},
		}
	}

	virtLauncherLabels := func(vmName string) map[string]string {
		return map[string]string{
			"kubevirt.io":         "virt-launcher",
			"vm.kubevirt.io/name": vmName,
		}
	}

	reconcilePod := func(pod *corev1.Pod) {
		r := &PodReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Eventually(func(g Gomega) {
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name + ".eth0"}, &juneauv1alpha1.NetworkInterface{})).To(Succeed())
		}).Should(Succeed())
	}

	interfaceOf := func(pod *corev1.Pod) *juneauv1alpha1.NetworkInterface {
		var nwiface juneauv1alpha1.NetworkInterface
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name + ".eth0"}, &nwiface)).To(Succeed())
		return &nwiface
	}

	It("stamps the virtual machine identity onto the NetworkInterface", func() {
		pod := newPod("vl-pod-identity", virtLauncherLabels("pod-identity-vm"))
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, pod) })

		reconcilePod(pod)
		Expect(interfaceOf(pod).Spec.AllocationIdentity).To(Equal("vmi.pod-identity-vm"))
	})

	It("leaves the allocation identity empty for a pod KubeVirt does not manage", func() {
		pod := newPod("plain-pod-identity", map[string]string{"app": "web"})
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, pod) })

		reconcilePod(pod)
		Expect(interfaceOf(pod).Spec.AllocationIdentity).To(BeEmpty())
	})

	It("keeps the address when a virt-launcher pod comes back under a new name", func() {
		first := newPod("vl-fake-vm-aaaaa", virtLauncherLabels("fake-vm"))
		Expect(k8sClient.Create(ctx, first)).To(Succeed())
		reconcilePod(first)

		firstIface := interfaceOf(first)
		allocateNetworkInterfaceForPod(ctx, firstIface)
		firstAddress := firstIface.Status.Address
		firstClaimName := firstIface.Status.AllocationClaim
		Expect(firstAddress).NotTo(BeEmpty())

		// envtest runs no garbage collector, so drop the pod-owned
		// NetworkInterface by hand and drive its finalizer. The lease is
		// left behind, exactly as a real restart leaves it.
		releasePodInterface(ctx, first, firstIface)
		Eventually(func(g Gomega) {
			err := k8sClient.Get(ctx, client.ObjectKey{Name: firstClaimName}, &juneauv1alpha1.AllocationClaim{})
			g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
		}).Should(Succeed())

		second := newPod("vl-fake-vm-bbbbb", virtLauncherLabels("fake-vm"))
		Expect(k8sClient.Create(ctx, second)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, second) })
		reconcilePod(second)

		secondIface := interfaceOf(second)
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, &juneauv1alpha1.AllocationLease{ObjectMeta: metav1.ObjectMeta{Name: leaseNameForNetworkInterface(secondIface)}})
		})
		Expect(secondIface.Spec.AllocationIdentity).To(Equal("vmi.fake-vm"))
		allocateNetworkInterfaceForPod(ctx, secondIface)
		Expect(secondIface.Status.Address).To(Equal(firstAddress))
		Expect(secondIface.Status.AllocationClaim).NotTo(Equal(firstClaimName))
	})
})

func allocateNetworkInterfaceForPod(ctx context.Context, nwiface *juneauv1alpha1.NetworkInterface) {
	r := &NetworkInterfaceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	Eventually(func(g Gomega) {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nwiface.Name, Namespace: nwiface.Namespace}})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(nwiface), nwiface)).To(Succeed())
		g.Expect(nwiface.Status.Address).NotTo(BeEmpty())
	}).Should(Succeed())
}

func interfaceOfOrNil(ctx context.Context, pod *corev1.Pod) *juneauv1alpha1.NetworkInterface {
	var nwiface juneauv1alpha1.NetworkInterface
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name + ".eth0"}, &nwiface); err != nil {
		return nil
	}
	return &nwiface
}

func cleanupPodTestArtifacts(ctx context.Context, pod *corev1.Pod) {
	if nwiface := interfaceOfOrNil(ctx, pod); nwiface != nil {
		cleanupNetworkInterface(ctx, nwiface)
	}
	_ = k8sClient.Delete(ctx, pod, client.GracePeriodSeconds(0))
}

// releasePodInterface removes a pod and its NetworkInterface the way a real
// restart does: the AllocationClaim goes away but the AllocationLease stays
// behind to hold the address.
func releasePodInterface(ctx context.Context, pod *corev1.Pod, nwiface *juneauv1alpha1.NetworkInterface) {
	r := &NetworkInterfaceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	Expect(k8sClient.Delete(ctx, nwiface)).To(Succeed())
	Eventually(func(g Gomega) {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nwiface.Name, Namespace: nwiface.Namespace}})
		g.Expect(err).NotTo(HaveOccurred())
		err = k8sClient.Get(ctx, client.ObjectKeyFromObject(nwiface), &juneauv1alpha1.NetworkInterface{})
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
	}).Should(Succeed())
	Expect(k8sClient.Delete(ctx, pod, client.GracePeriodSeconds(0))).To(Succeed())
}
