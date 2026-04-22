package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("BGPAdvertisement webhook", func() {
	It("rejects missing addressPools via markers", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookUniqueTestName("bgpadvertisement"),
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.addressPools"))
	})

	It("rejects empty spec.addressPools via MinItems marker", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgpadvertisement")},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.addressPools"))
	})

	It("accepts a bgp AddressPool reference", func() {
		pool := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgpadvertisement")},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{pool.Name},
			},
		})).To(Succeed())
	})

	It("rejects a nonexistent AddressPool", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgpadvertisement")},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{webhookUniqueTestName("missing-addresspool")},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced AddressPool does not exist"))
	})

	It("rejects an arp AddressPool reference", func() {
		pool := newWebhookARPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgpadvertisement")},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{pool.Name},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("AddressPool must have advertiseMode=bgp"))
	})

	It("accepts appending a new element to spec.addressPools", func() {
		poolA := newWebhookBGPAddressPool()
		poolB := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), poolA)).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(), poolB)).To(Succeed())

		advertisement := &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgpadvertisement")},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{poolA.Name},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), advertisement)).To(Succeed())

		var current juneauv1alpha1.BGPAdvertisement
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(advertisement), &current)).To(Succeed())
		current.Spec.AddressPools = []string{poolA.Name, poolB.Name}

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	It("accepts removing an element from spec.addressPools", func() {
		poolA := newWebhookBGPAddressPool()
		poolB := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), poolA)).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(), poolB)).To(Succeed())

		advertisement := &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgpadvertisement")},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{poolA.Name, poolB.Name},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), advertisement)).To(Succeed())

		var current juneauv1alpha1.BGPAdvertisement
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(advertisement), &current)).To(Succeed())
		current.Spec.AddressPools = []string{poolA.Name}

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})
})
