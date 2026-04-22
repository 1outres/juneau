package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ExternalNetwork webhook", func() {
	It("rejects missing required fields via markers", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookUniqueTestName("externalnetwork"),
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.type"))
		Expect(err.Error()).To(ContainSubstring("spec.addressPools"))
	})

	It("rejects an invalid spec.type via Enum marker", func() {
		pool := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkType("invalid"),
				AddressPools: []string{pool.Name},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.type"))
	})

	It("accepts type=bgp with a bgp AddressPool", func() {
		pool := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
				AddressPools: []string{pool.Name},
			},
		})).To(Succeed())
	})

	It("accepts type=arp with an arp AddressPool", func() {
		pool := newWebhookARPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeARP,
				AddressPools: []string{pool.Name},
			},
		})).To(Succeed())
	})

	It("rejects a nonexistent AddressPool", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
				AddressPools: []string{webhookUniqueTestName("missing-addresspool")},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced AddressPool does not exist"))
	})

	It("rejects type=bgp referencing an arp AddressPool", func() {
		pool := newWebhookARPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
				AddressPools: []string{pool.Name},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("type=bgp requires AddressPool advertiseMode=bgp"))
	})

	It("rejects type=arp referencing a bgp AddressPool", func() {
		pool := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeARP,
				AddressPools: []string{pool.Name},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("type=arp requires AddressPool advertiseMode=arp"))
	})

	It("rejects immutable spec.type updates", func() {
		pool := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		externalNetwork := &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
				AddressPools: []string{pool.Name},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), externalNetwork)).To(Succeed())

		var current juneauv1alpha1.ExternalNetwork
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(externalNetwork), &current)).To(Succeed())
		current.Spec.Type = juneauv1alpha1.ExternalNetworkTypeARP

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("type is immutable"))
	})

	It("rejects removing an element from spec.addressPools", func() {
		poolA := newWebhookBGPAddressPool()
		poolB := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), poolA)).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(), poolB)).To(Succeed())

		externalNetwork := &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
				AddressPools: []string{poolA.Name, poolB.Name},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), externalNetwork)).To(Succeed())

		var current juneauv1alpha1.ExternalNetwork
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(externalNetwork), &current)).To(Succeed())
		current.Spec.AddressPools = []string{poolA.Name}

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cannot be removed"))
	})

	It("accepts appending a new element to spec.addressPools", func() {
		poolA := newWebhookBGPAddressPool()
		poolB := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), poolA)).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(), poolB)).To(Succeed())

		externalNetwork := &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
				AddressPools: []string{poolA.Name},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), externalNetwork)).To(Succeed())

		var current juneauv1alpha1.ExternalNetwork
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(externalNetwork), &current)).To(Succeed())
		current.Spec.AddressPools = []string{poolA.Name, poolB.Name}

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	It("rejects deletion while an active ElasticIP references the ExternalNetwork", func() {
		pool := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		externalNetwork := &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
				AddressPools: []string{pool.Name},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), externalNetwork)).To(Succeed())

		elasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), externalNetwork.Name)
		Expect(webhookK8sClient.Create(context.Background(), elasticIP)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), externalNetwork)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("is referenced by ElasticIP"))
	})

	It("allows deletion when no ElasticIP references the ExternalNetwork", func() {
		pool := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		externalNetwork := &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
			Spec: juneauv1alpha1.ExternalNetworkSpec{
				Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
				AddressPools: []string{pool.Name},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), externalNetwork)).To(Succeed())

		Expect(webhookK8sClient.Delete(context.Background(), externalNetwork)).To(Succeed())
	})
})

func newWebhookBGPAddressPool() *juneauv1alpha1.AddressPool {
	return &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
			Addresses:     []string{"10.210.0.0/30"},
		},
	}
}

func newWebhookARPAddressPool() *juneauv1alpha1.AddressPool {
	return &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeARP,
			Addresses:     []string{"10.210.0.10-10.210.0.20"},
		},
	}
}
