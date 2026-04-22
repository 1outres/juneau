package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ElasticIPAttachment webhook", func() {
	It("rejects missing required fields via markers", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ElasticIPAttachment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("elasticipattachment"),
				Namespace: "default",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.elasticIPRef.name"))
		Expect(err.Error()).To(ContainSubstring("spec.targetRef.networkInterfaceName"))
	})

	It("rejects a nonexistent ElasticIP", func() {
		networkInterface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.50")
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), webhookUniqueTestName("missing-elasticip"), networkInterface.Name))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ElasticIP does not exist"))
	})

	It("rejects a nonexistent NetworkInterface", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		elasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkName)
		createWebhookElasticIPEventually(elasticIP)

		err := webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIP.Name, webhookUniqueTestName("missing-networkinterface")))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced NetworkInterface does not exist"))
	})

	It("rejects a deleting ElasticIP", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		elasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkName)
		elasticIP.Finalizers = []string{"test.juneau.loutres.me/finalizer"}
		createWebhookElasticIPEventually(elasticIP)

		networkInterface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.51")
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		Expect(webhookK8sClient.Delete(context.Background(), elasticIP)).To(Succeed())
		Eventually(func(g Gomega) {
			var current juneauv1alpha1.ElasticIP
			g.Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(elasticIP), &current)).To(Succeed())
			g.Expect(current.DeletionTimestamp).NotTo(BeNil())
		}).Should(Succeed())

		err := webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIP.Name, networkInterface.Name))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ElasticIP is being deleted"))
	})

	It("rejects a deleting NetworkInterface", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		elasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkName)
		createWebhookElasticIPEventually(elasticIP)

		networkInterface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.52")
		networkInterface.Finalizers = []string{"test.juneau.loutres.me/finalizer"}
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		Expect(webhookK8sClient.Delete(context.Background(), networkInterface)).To(Succeed())
		Eventually(func(g Gomega) {
			var current juneauv1alpha1.NetworkInterface
			g.Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkInterface), &current)).To(Succeed())
			g.Expect(current.DeletionTimestamp).NotTo(BeNil())
		}).Should(Succeed())

		err := webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIP.Name, networkInterface.Name))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced NetworkInterface is being deleted"))
	})

	It("rejects immutable spec updates", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		otherExternalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		elasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkName)
		otherElasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), otherExternalNetworkName)
		createWebhookElasticIPEventually(elasticIP)
		createWebhookElasticIPEventually(otherElasticIP)

		networkInterface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.53")
		otherNetworkInterface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.54")
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(), otherNetworkInterface)).To(Succeed())

		attachment := newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIP.Name, networkInterface.Name)
		Expect(webhookK8sClient.Create(context.Background(), attachment)).To(Succeed())

		var current juneauv1alpha1.ElasticIPAttachment
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(attachment), &current)).To(Succeed())
		current.Spec.ElasticIPRef.Name = otherElasticIP.Name
		current.Spec.TargetRef.NetworkInterfaceName = otherNetworkInterface.Name

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("elasticIPRef.name is immutable"))
		Expect(err.Error()).To(ContainSubstring("targetRef.networkInterfaceName is immutable"))
	})

	It("rejects duplicate attachment by ElasticIP", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		elasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkName)
		createWebhookElasticIPEventually(elasticIP)

		networkInterfaceA := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.55")
		networkInterfaceB := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.56")
		Expect(webhookK8sClient.Create(context.Background(), networkInterfaceA)).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(), networkInterfaceB)).To(Succeed())

		Expect(webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIP.Name, networkInterfaceA.Name))).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIP.Name, networkInterfaceB.Name))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("ElasticIP is already attached"))
	})

	It("rejects duplicate attachment by NetworkInterface", func() {
		externalNetworkNameA := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		externalNetworkNameB := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		elasticIPA := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkNameA)
		elasticIPB := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkNameB)
		createWebhookElasticIPEventually(elasticIPA)
		createWebhookElasticIPEventually(elasticIPB)

		networkInterface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.57")
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		Expect(webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIPA.Name, networkInterface.Name))).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIPB.Name, networkInterface.Name))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("NetworkInterface already has an attachment"))
	})
})

func newValidElasticIPAttachment(name, elasticIPName, networkInterfaceName string) *juneauv1alpha1.ElasticIPAttachment {
	return &juneauv1alpha1.ElasticIPAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: juneauv1alpha1.ElasticIPAttachmentSpec{
			ElasticIPRef: juneauv1alpha1.ElasticIPAttachmentElasticIPRef{Name: elasticIPName},
			TargetRef:    juneauv1alpha1.ElasticIPAttachmentTargetRef{NetworkInterfaceName: networkInterfaceName},
		},
	}
}

func createWebhookElasticIPEventually(elasticIP *juneauv1alpha1.ElasticIP) {
	Eventually(func() error {
		return webhookK8sClient.Create(context.Background(), elasticIP.DeepCopy())
	}).Should(Succeed())
}
