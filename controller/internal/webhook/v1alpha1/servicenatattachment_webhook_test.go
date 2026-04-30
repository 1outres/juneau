package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ServiceNATAttachment webhook", func() {
	It("rejects missing spec.nodeName", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sna")},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.nodeName"))
	})

	It("rejects spec.nodeName that differs from metadata.name", func() {
		name := webhookUniqueTestName("sna")
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       juneauv1alpha1.ServiceNATAttachmentSpec{NodeName: name + "-other"},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.nodeName must equal metadata.name"))
	})

	It("accepts a matching name/spec.nodeName pair", func() {
		name := webhookUniqueTestName("sna")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       juneauv1alpha1.ServiceNATAttachmentSpec{NodeName: name},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: name},
			})
		})
	})

	It("rejects mutating spec.nodeName", func() {
		name := webhookUniqueTestName("sna")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       juneauv1alpha1.ServiceNATAttachmentSpec{NodeName: name},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: name},
			})
		})

		var fetched juneauv1alpha1.ServiceNATAttachment
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &fetched)).To(Succeed())
		fetched.Spec.NodeName = name + "-other"
		err := webhookK8sClient.Update(context.Background(), &fetched)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.nodeName is immutable"))
	})
})
