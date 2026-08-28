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
	"fmt"

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

	reconcilePod := func(pod *corev1.Pod, ifNames ...string) {
		if len(ifNames) == 0 {
			ifNames = []string{juneauv1alpha1.PodPrimaryInterfaceName}
		}
		Eventually(func(g Gomega) {
			_, err := newPodReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
			g.Expect(err).NotTo(HaveOccurred())
			for _, ifName := range ifNames {
				g.Expect(k8sClient.Get(ctx, podInterfaceKey(pod, ifName), &juneauv1alpha1.NetworkInterface{})).To(Succeed())
			}
		}).Should(Succeed())
	}

	interfaceOf := func(pod *corev1.Pod) *juneauv1alpha1.NetworkInterface {
		var nwiface juneauv1alpha1.NetworkInterface
		Expect(k8sClient.Get(ctx, podInterfaceKey(pod, juneauv1alpha1.PodPrimaryInterfaceName), &nwiface)).To(Succeed())
		return &nwiface
	}

	interfaceNamed := func(pod *corev1.Pod, ifName string) *juneauv1alpha1.NetworkInterface {
		var nwiface juneauv1alpha1.NetworkInterface
		Expect(k8sClient.Get(ctx, podInterfaceKey(pod, ifName), &nwiface)).To(Succeed())
		return &nwiface
	}

	expectNoInterface := func(pod *corev1.Pod, ifName string) {
		Eventually(func(g Gomega) {
			_, err := newPodReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
			g.Expect(err).NotTo(HaveOccurred())
			err = k8sClient.Get(ctx, podInterfaceKey(pod, ifName), &juneauv1alpha1.NetworkInterface{})
			g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
		}).Should(Succeed())
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

	It("points the NetworkInterface at the virtual machine that must keep the address", func() {
		pod := newPod("vl-pod-retain", virtLauncherLabels("pod-retain-vm"))
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, pod) })

		reconcilePod(pod)
		retain := interfaceOf(pod).Spec.RetainWhile
		Expect(retain).NotTo(BeNil())
		Expect(*retain).To(Equal(juneauv1alpha1.RetainReference{
			APIVersion: "kubevirt.io/v1",
			Kind:       "VirtualMachine",
			Namespace:  pod.Namespace,
			Name:       "pod-retain-vm",
		}))
	})

	It("leaves the retain reference unset for a pod KubeVirt does not manage", func() {
		pod := newPod("plain-pod-retain", map[string]string{"app": "web"})
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, pod) })

		reconcilePod(pod)
		Expect(interfaceOf(pod).Spec.RetainWhile).To(BeNil())
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

	It("gives the pod one NetworkInterface per NIC it asks for", func() {
		extra := createPodTestSubnet("multinic-extra", "10.31.0.0/24")
		pod := newPod("multinic-two-nics", nil)
		pod.Annotations = map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   "default",
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(`[{"interface":"eth1","subnet":%q,"address":"10.31.0.9","securityGroups":["sg-extra"]}]`, extra),
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, pod) })

		reconcilePod(pod, "eth0", "eth1")

		primary := interfaceOf(pod)
		Expect(primary.Spec.Subnet).To(Equal("default"))
		Expect(primary.Spec.PodRef.Interface).To(Equal("eth0"))
		Expect(primary.Spec.SecurityGroups).To(BeEmpty())

		secondary := interfaceNamed(pod, "eth1")
		Expect(secondary.Spec.Subnet).To(Equal(extra))
		Expect(secondary.Spec.PodRef.Interface).To(Equal("eth1"))
		Expect(secondary.Spec.PodRef.UID).To(Equal(string(pod.UID)))
		Expect(secondary.Spec.NodeName).To(Equal(pod.Spec.NodeName))
		Expect(secondary.Spec.Address).To(Equal("10.31.0.9"))
		Expect(secondary.Spec.SecurityGroups).To(Equal([]string{"sg-extra"}))
	})

	It("keeps the workload identity on every NIC of a virt-launcher pod", func() {
		extra := createPodTestSubnet("multinic-vm", "10.32.0.0/24")
		pod := newPod("vl-multinic", virtLauncherLabels("multinic-vm-name"))
		pod.Annotations = map[string]string{
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(`[{"interface":"eth1","subnet":%q}]`, extra),
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, pod) })

		reconcilePod(pod, "eth0", "eth1")

		for _, ifName := range []string{"eth0", "eth1"} {
			nwiface := interfaceNamed(pod, ifName)
			Expect(nwiface.Spec.AllocationIdentity).To(Equal("vmi.multinic-vm-name"))
			Expect(nwiface.Spec.RetainWhile).NotTo(BeNil())
			Expect(nwiface.Spec.RetainWhile.Name).To(Equal("multinic-vm-name"))
		}
	})

	It("removes the NetworkInterface of a NIC the pod no longer asks for", func() {
		extra := createPodTestSubnet("multinic-shrink", "10.33.0.0/24")
		pod := newPod("multinic-shrink", nil)
		pod.Annotations = map[string]string{
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(`[{"interface":"eth1","subnet":%q}]`, extra),
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, pod) })

		reconcilePod(pod, "eth0", "eth1")

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pod), pod)).To(Succeed())
		delete(pod.Annotations, juneauv1alpha1.PodAnnotationNetworks)
		Expect(k8sClient.Update(ctx, pod)).To(Succeed())

		expectNoInterface(pod, "eth1")
		Expect(k8sClient.Get(ctx, podInterfaceKey(pod, "eth0"), &juneauv1alpha1.NetworkInterface{})).To(Succeed())
	})

	It("removes every NetworkInterface once the pod has finished", func() {
		extra := createPodTestSubnet("multinic-finished", "10.34.0.0/24")
		pod := newPod("multinic-finished", nil)
		pod.Annotations = map[string]string{
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(`[{"interface":"eth1","subnet":%q}]`, extra),
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, pod) })

		reconcilePod(pod, "eth0", "eth1")

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pod), pod)).To(Succeed())
		pod.Status.Phase = corev1.PodSucceeded
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

		expectNoInterface(pod, "eth1")
		expectNoInterface(pod, "eth0")
	})

	It("refuses to build a pod whose networks annotation cannot be read", func() {
		pod := newPod("multinic-broken", nil)
		pod.Annotations = map[string]string{
			juneauv1alpha1.PodAnnotationNetworks: `[{"interface":"eth1"`,
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { cleanupPodTestArtifacts(ctx, pod) })

		Eventually(func(g Gomega) {
			_, err := newPodReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
			g.Expect(err).To(HaveOccurred())
		}).Should(Succeed())
		err := k8sClient.Get(ctx, podInterfaceKey(pod, "eth0"), &juneauv1alpha1.NetworkInterface{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})
})

// newPodReconciler builds the reconciler on the manager's cached client:
// reclaiming NetworkInterfaces of NICs a pod dropped needs the pod-UID
// field index, which only the cache can serve.
func newPodReconciler() *PodReconciler {
	return &PodReconciler{Client: cachedK8sClient, Scheme: cachedK8sClient.Scheme()}
}

func podInterfaceKey(pod *corev1.Pod, ifName string) client.ObjectKey {
	return client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name + "." + ifName}
}

// createPodTestSubnet adds a Subnet the Pod controller can attach an extra
// NIC to and returns its name.
func createPodTestSubnet(name, cidr string) string {
	GinkgoHelper()
	subnet := &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.SubnetSpec{Vpc: "default", CIDR: cidr},
	}
	Expect(k8sClient.Create(context.Background(), subnet)).To(Succeed())
	DeferCleanup(func() {
		_ = k8sClient.Delete(context.Background(), subnet)
	})
	return name
}

func allocateNetworkInterfaceForPod(ctx context.Context, nwiface *juneauv1alpha1.NetworkInterface) {
	r := &NetworkInterfaceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	Eventually(func(g Gomega) {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nwiface.Name, Namespace: nwiface.Namespace}})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(nwiface), nwiface)).To(Succeed())
		g.Expect(nwiface.Status.Address).NotTo(BeEmpty())
	}).Should(Succeed())
}

func interfacesOfPod(ctx context.Context, pod *corev1.Pod) []juneauv1alpha1.NetworkInterface {
	var list juneauv1alpha1.NetworkInterfaceList
	if err := k8sClient.List(ctx, &list, client.InNamespace(pod.Namespace)); err != nil {
		return nil
	}
	var out []juneauv1alpha1.NetworkInterface
	for i := range list.Items {
		if list.Items[i].Spec.PodRef.Name == pod.Name {
			out = append(out, list.Items[i])
		}
	}
	return out
}

func cleanupPodTestArtifacts(ctx context.Context, pod *corev1.Pod) {
	for _, nwiface := range interfacesOfPod(ctx, pod) {
		cleanupNetworkInterface(ctx, &nwiface)
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
