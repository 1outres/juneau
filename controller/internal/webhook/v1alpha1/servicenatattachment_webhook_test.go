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
	It("rejects missing spec.nodeName / spec.vpc", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sna")},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(SatisfyAny(
			ContainSubstring("spec.nodeName"),
			ContainSubstring("spec.vpc"),
		))
	})

	It("rejects metadata.name that does not match `<spec.nodeName>.<spec.vpc>`", func() {
		nodeName := webhookUniqueTestName("node")
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName + ".not-the-right-vpc"},
			Spec: juneauv1alpha1.ServiceNATAttachmentSpec{
				NodeName: nodeName,
				Vpc:      "actual-vpc",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("metadata.name must equal"))
	})

	It("accepts a matching name / spec triple", func() {
		nodeName := webhookUniqueTestName("node")
		vpcName := "default" // no Subnet need exist for the attachment-side webhook check
		name := nodeName + "." + vpcName
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: juneauv1alpha1.ServiceNATAttachmentSpec{
				NodeName: nodeName,
				Vpc:      vpcName,
			},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: name},
			})
		})
	})

	It("rejects mutating spec.nodeName or spec.vpc", func() {
		nodeName := webhookUniqueTestName("node")
		vpcName := "default"
		name := nodeName + "." + vpcName
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: juneauv1alpha1.ServiceNATAttachmentSpec{
				NodeName: nodeName,
				Vpc:      vpcName,
			},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.ServiceNATAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: name},
			})
		})

		var fetched juneauv1alpha1.ServiceNATAttachment
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &fetched)).To(Succeed())
		mutNode := fetched.DeepCopy()
		mutNode.Spec.NodeName = nodeName + "-other"
		err := webhookK8sClient.Update(context.Background(), mutNode)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.nodeName is immutable"))

		mutVpc := fetched.DeepCopy()
		mutVpc.Spec.Vpc = "other-vpc"
		err = webhookK8sClient.Update(context.Background(), mutVpc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.vpc is immutable"))
	})
})
