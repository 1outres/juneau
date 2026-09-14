package v1alpha1

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("AddressPool webhook", func() {
	It("rejects missing required fields via markers", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookUniqueTestName("addresspool"),
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.advertiseMode"))
		Expect(err.Error()).To(ContainSubstring("spec.addresses"))
	})

	It("accepts advertiseMode=bgp with a valid CIDR", func() {
		block := newWebhookExternalBlock()

		Expect(webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(0, 30)))).To(Succeed())
	})

	It("accepts advertiseMode=arp with a valid range", func() {
		block := newWebhookExternalBlock()

		Expect(webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.addressRange(10, 20)))).To(Succeed())
	})

	It("rejects advertiseMode=bgp with an invalid CIDR", func() {
		err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, "not-a-cidr"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be a valid CIDR"))
	})

	It("rejects advertiseMode=bgp with an IPv6 CIDR", func() {
		err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, "2001:db8::/32"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("only IPv4 CIDR is supported"))
	})

	It("rejects advertiseMode=bgp with prefix outside /8-/32", func() {
		err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, "10.0.0.0/5"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("prefix must be between /8 and /32"))
	})

	It("rejects advertiseMode=arp addresses not in start-end format", func() {
		block := newWebhookExternalBlock()

		err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.address(10)))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be in start-end format"))
	})

	It("rejects advertiseMode=arp addresses where start > end", func() {
		block := newWebhookExternalBlock()

		err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.addressRange(20, 10)))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("range start must be <= end"))
	})

	It("rejects immutable spec.advertiseMode updates", func() {
		block := newWebhookExternalBlock()
		pool := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(0, 30))
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		var current juneauv1alpha1.AddressPool
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pool), &current)).To(Succeed())
		current.Spec.AdvertiseMode = juneauv1alpha1.AddressPoolAdvertiseModeARP

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("advertiseMode is immutable"))
	})

	It("rejects removing an element from spec.addresses", func() {
		block := newWebhookExternalBlock()
		pool := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(0, 30), block.cidr(4, 30))
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		var current juneauv1alpha1.AddressPool
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pool), &current)).To(Succeed())
		current.Spec.Addresses = []string{block.cidr(0, 30)}

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cannot be removed"))
	})

	It("accepts appending a new element to spec.addresses", func() {
		block := newWebhookExternalBlock()
		pool := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(0, 30))
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		var current juneauv1alpha1.AddressPool
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pool), &current)).To(Succeed())
		current.Spec.Addresses = []string{block.cidr(0, 30), block.cidr(4, 30)}

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	Describe("address overlap with other AddressPools", func() {
		It("accepts pools that sit next to each other without sharing an address", func() {
			block := newWebhookExternalBlock()
			Expect(webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(0, 30)))).To(Succeed())
			Expect(webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.addressRange(4, 7)))).To(Succeed())
			Expect(webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(8, 30)))).To(Succeed())
		})

		It("rejects a bgp CIDR that overlaps a CIDR of another bgp pool", func() {
			block := newWebhookExternalBlock()
			existing := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(0, 24))
			Expect(webhookK8sClient.Create(context.Background(), existing)).To(Succeed())

			err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(8, 30)))

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.addresses[0]"))
			Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("overlaps with AddressPool %q address %q at %s",
				existing.Name, block.cidr(0, 24), block.addressRange(8, 11))))
		})

		It("rejects an arp range that overlaps a range of another arp pool", func() {
			block := newWebhookExternalBlock()
			existing := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.addressRange(10, 20))
			Expect(webhookK8sClient.Create(context.Background(), existing)).To(Succeed())

			err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.addressRange(20, 30)))

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("overlaps with AddressPool %q address %q at %s",
				existing.Name, block.addressRange(10, 20), block.address(20))))
		})

		It("rejects a bgp CIDR that overlaps a range of an arp pool", func() {
			block := newWebhookExternalBlock()
			existing := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.addressRange(10, 20))
			Expect(webhookK8sClient.Create(context.Background(), existing)).To(Succeed())

			err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(16, 28)))

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("overlaps with AddressPool %q address %q at %s",
				existing.Name, block.addressRange(10, 20), block.addressRange(16, 20))))
		})

		It("rejects an arp range that overlaps a CIDR of a bgp pool", func() {
			block := newWebhookExternalBlock()
			existing := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(16, 28))
			Expect(webhookK8sClient.Create(context.Background(), existing)).To(Succeed())

			err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.addressRange(10, 20)))

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("overlaps with AddressPool %q address %q at %s",
				existing.Name, block.cidr(16, 28), block.addressRange(16, 20))))
		})

		It("names the entry that overlaps when the pool has several", func() {
			block := newWebhookExternalBlock()
			existing := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.addressRange(100, 110))
			Expect(webhookK8sClient.Create(context.Background(), existing)).To(Succeed())

			err := webhookK8sClient.Create(context.Background(), newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP,
				block.addressRange(10, 20), block.addressRange(105, 120)))

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.addresses[1]"))
			Expect(err.Error()).NotTo(ContainSubstring("spec.addresses[0]"))
		})

		It("rejects an update that appends an address another pool holds", func() {
			block := newWebhookExternalBlock()
			existing := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(8, 30))
			Expect(webhookK8sClient.Create(context.Background(), existing)).To(Succeed())
			pool := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, block.cidr(0, 30))
			Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

			var current juneauv1alpha1.AddressPool
			Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pool), &current)).To(Succeed())
			current.Spec.Addresses = append(current.Spec.Addresses, block.cidr(8, 29))

			err := webhookK8sClient.Update(context.Background(), &current)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.addresses[1]"))
			Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("overlaps with AddressPool %q address %q at %s",
				existing.Name, block.cidr(8, 30), block.addressRange(8, 11))))
		})

		It("does not count the addresses of the pool being updated", func() {
			block := newWebhookExternalBlock()
			pool := newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, block.addressRange(10, 20))
			Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

			var current juneauv1alpha1.AddressPool
			Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pool), &current)).To(Succeed())
			current.Labels = map[string]string{"example.com/touched": "true"}

			Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
		})
	})

	It("rejects deletion while an ExternalNetwork references the AddressPool", func() {
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

		err := webhookK8sClient.Delete(context.Background(), pool)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("is referenced by ExternalNetwork"))
	})

	It("allows deletion when nothing references the AddressPool", func() {
		pool := newWebhookBGPAddressPool()
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		Expect(webhookK8sClient.Delete(context.Background(), pool)).To(Succeed())
	})
})

// webhookExternalBlock is a /24 of external addresses that belongs to one
// spec. AddressPools are cluster scoped and the AddressPool webhook rejects
// two pools that share an address, so every pool a spec creates is carved
// out of a block that no other spec holds.
type webhookExternalBlock struct {
	base string
}

var webhookExternalBlockCount int

func newWebhookExternalBlock() webhookExternalBlock {
	webhookExternalBlockCount++
	return webhookExternalBlock{
		base: fmt.Sprintf("100.%d.%d", 64+webhookExternalBlockCount/256, webhookExternalBlockCount%256),
	}
}

func (b webhookExternalBlock) address(host int) string {
	return fmt.Sprintf("%s.%d", b.base, host)
}

func (b webhookExternalBlock) cidr(host, bits int) string {
	return fmt.Sprintf("%s/%d", b.address(host), bits)
}

func (b webhookExternalBlock) addressRange(first, last int) string {
	return fmt.Sprintf("%s-%s", b.address(first), b.address(last))
}

func newWebhookAddressPool(advertiseMode juneauv1alpha1.AddressPoolAdvertiseMode, addresses ...string) *juneauv1alpha1.AddressPool {
	return &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: advertiseMode,
			Addresses:     addresses,
		},
	}
}
