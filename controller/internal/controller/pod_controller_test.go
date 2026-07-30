package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Pod controller persistent interfaces", func() {
	It("creates and binds a Pod-owned interface for an unmanaged Pod", func() {
		ctx := context.Background()
		pod := newScheduledControllerPod(uniqueTestName("pod"), nil)
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pod) })

		reconciler := &PodReconciler{Client: k8sClient, Scheme: scheme.Scheme}
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
		Expect(err).NotTo(HaveOccurred())

		interfaceName := pod.Name + ".eth0"
		var networkInterface juneauv1alpha1.NetworkInterface
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: interfaceName}, &networkInterface)).To(Succeed())
		Expect(metav1.IsControlledBy(&networkInterface, pod)).To(BeTrue())

		var attachment juneauv1alpha1.NetworkInterfaceAttachment
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: interfaceName}, &attachment)).To(Succeed())
		Expect(metav1.IsControlledBy(&attachment, pod)).To(BeTrue())
		Expect(attachment.Spec.NetworkInterfaceRef).To(Equal(interfaceName))
		Expect(networkInterface.Spec.AttachmentRef).NotTo(BeNil())
		Expect(networkInterface.Spec.AttachmentRef.Name).To(Equal(attachment.Name))
		Expect(networkInterface.Spec.AttachmentRef.UID).To(Equal(attachment.UID))
	})

	It("creates only the Pod attachment for a workload-managed interface", func() {
		ctx := context.Background()
		interfaceName := uniqueTestName("managed-interface")
		networkInterface := &juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{Name: interfaceName, Namespace: "default"},
			Spec:       juneauv1alpha1.NetworkInterfaceSpec{Subnet: "default"},
		}
		Expect(k8sClient.Create(ctx, networkInterface)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, networkInterface) })

		pod := newScheduledControllerPod(uniqueTestName("pod"), map[string]string{
			podAnnNetworkInterface: interfaceName,
		})
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pod) })

		reconciler := &PodReconciler{Client: k8sClient, Scheme: scheme.Scheme}
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
		Expect(err).NotTo(HaveOccurred())

		var attachment juneauv1alpha1.NetworkInterfaceAttachment
		Expect(k8sClient.Get(ctx, client.ObjectKey{
			Namespace: pod.Namespace,
			Name:      pod.Name + ".eth0",
		}, &attachment)).To(Succeed())
		Expect(attachment.Spec.NetworkInterfaceRef).To(Equal(interfaceName))

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(networkInterface), networkInterface)).To(Succeed())
		Expect(networkInterface.Spec.AttachmentRef).To(BeNil())
	})
})

func newScheduledControllerPod(name string, annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "default",
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			NodeName: "node-a",
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "example.invalid/test:latest",
			}},
		},
	}
}
