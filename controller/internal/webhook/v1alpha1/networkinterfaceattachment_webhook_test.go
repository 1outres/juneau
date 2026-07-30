package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("NetworkInterfaceAttachment webhook", func() {
	It("requires an existing NetworkInterface in the same namespace", func() {
		attachment := newValidNetworkInterfaceAttachment(
			webhookUniqueTestName("attachment"),
			webhookUniqueTestName("missing-interface"),
		)

		err := webhookK8sClient.Create(context.Background(), attachment)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced NetworkInterface does not exist"))
	})

	It("accepts a Pod-scoped attachment and keeps its spec immutable", func() {
		name := webhookUniqueTestName("networkinterface")
		networkInterface := newValidNetworkInterface(name, "default", "")
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		attachment := newValidNetworkInterfaceAttachment(webhookUniqueTestName("attachment"), name)
		Expect(webhookK8sClient.Create(context.Background(), attachment)).To(Succeed())

		var current juneauv1alpha1.NetworkInterfaceAttachment
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(attachment), &current)).To(Succeed())
		current.Spec.NodeName = "node-b"
		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec is immutable"))
	})
})

func newValidNetworkInterfaceAttachment(name, interfaceName string) *juneauv1alpha1.NetworkInterfaceAttachment {
	return &juneauv1alpha1.NetworkInterfaceAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: juneauv1alpha1.NetworkInterfaceAttachmentSpec{
			NetworkInterfaceRef: interfaceName,
			NodeName:            "node-a",
			PodRef: juneauv1alpha1.NetworkInterfaceAttachmentPodReference{
				UID:       "pod-uid-a",
				Name:      "pod-a",
				Interface: "eth0",
			},
		},
	}
}
