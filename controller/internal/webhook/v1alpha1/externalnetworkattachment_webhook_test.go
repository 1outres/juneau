package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ExternalNetworkAttachment webhook", func() {
	It("rejects missing required fields via markers", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetworkAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("ena")},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(SatisfyAny(
			ContainSubstring("spec.externalNetwork"),
			ContainSubstring("spec.nodeName"),
		))
	})

	It("rejects a nonexistent ExternalNetwork", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetworkAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("ena")},
			Spec: juneauv1alpha1.ExternalNetworkAttachmentSpec{
				ExternalNetwork: webhookUniqueTestName("missing"),
				NodeName:        "node-a",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ExternalNetwork does not exist"))
	})

	It("rejects an ExternalNetwork with non-bgp type", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeARP)
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetworkAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("ena")},
			Spec: juneauv1alpha1.ExternalNetworkAttachmentSpec{
				ExternalNetwork: externalNetworkName,
				NodeName:        "node-a",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must have type=bgp"))
	})

	It("rejects updating immutable spec fields", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		attachment := &juneauv1alpha1.ExternalNetworkAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("ena")},
			Spec: juneauv1alpha1.ExternalNetworkAttachmentSpec{
				ExternalNetwork: externalNetworkName,
				NodeName:        "node-a",
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), attachment)).To(Succeed())

		var current juneauv1alpha1.ExternalNetworkAttachment
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(attachment), &current)).To(Succeed())
		current.Spec.NodeName = "node-b"
		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("nodeName is immutable"))
	})
})
