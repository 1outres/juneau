package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ElasticIP webhook", func() {
	It("rejects missing required fields via markers", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ElasticIP{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("elasticip"),
				Namespace: "default",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.externalNetwork"))
	})

	It("rejects a nonexistent ExternalNetwork", func() {
		err := webhookK8sClient.Create(context.Background(), newValidElasticIP(webhookUniqueTestName("elasticip"), webhookUniqueTestName("missing-externalnetwork")))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ExternalNetwork does not exist"))
	})

	It("rejects an ExternalNetwork with non-bgp type", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeARP)

		err := webhookK8sClient.Create(context.Background(), newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkName))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ExternalNetwork must have type=bgp"))
	})

	It("rejects immutable spec.externalNetwork updates", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		otherExternalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		elasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkName)
		Expect(webhookK8sClient.Create(context.Background(), elasticIP)).To(Succeed())

		var current juneauv1alpha1.ElasticIP
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(elasticIP), &current)).To(Succeed())
		current.Spec.ExternalNetwork = otherExternalNetworkName

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("externalNetwork is immutable"))
	})

	It("rejects deletion while an active attachment references the ElasticIP", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		elasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetworkName)
		Expect(webhookK8sClient.Create(context.Background(), elasticIP)).To(Succeed())
		networkInterface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.50")
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		attachment := &juneauv1alpha1.ElasticIPAttachment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("elasticipattachment"),
				Namespace: elasticIP.Namespace,
			},
			Spec: juneauv1alpha1.ElasticIPAttachmentSpec{
				ElasticIPRef: juneauv1alpha1.ElasticIPAttachmentElasticIPRef{Name: elasticIP.Name},
				TargetRef:    juneauv1alpha1.ElasticIPAttachmentTargetRef{NetworkInterfaceName: networkInterface.Name},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), attachment)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), elasticIP)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("is referenced by ElasticIPAttachment"))
	})
})

func newValidElasticIP(name, externalNetwork string) *juneauv1alpha1.ElasticIP {
	return &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: juneauv1alpha1.ElasticIPSpec{
			ExternalNetwork: externalNetwork,
		},
	}
}

func createWebhookExternalNetwork(networkType juneauv1alpha1.ExternalNetworkType) string {
	poolName := webhookUniqueTestName("addresspool")
	advertiseMode := juneauv1alpha1.AddressPoolAdvertiseModeBGP
	addresses := []string{"10.200.0.0/30"}
	if networkType == juneauv1alpha1.ExternalNetworkTypeARP {
		advertiseMode = juneauv1alpha1.AddressPoolAdvertiseModeARP
		addresses = []string{"10.200.0.10-10.200.0.20"}
	}
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: advertiseMode,
			Addresses:     addresses,
		},
	})).To(Succeed())

	name := webhookUniqueTestName("externalnetwork")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.ExternalNetworkSpec{
			Type:         networkType,
			AddressPools: []string{poolName},
		},
	})).To(Succeed())
	return name
}
