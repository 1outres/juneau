package v1alpha1

import (
	"context"

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
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.210.0.0/30"},
			},
		})).To(Succeed())
	})

	It("accepts advertiseMode=arp with a valid range", func() {
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeARP,
				Addresses:     []string{"10.210.0.10-10.210.0.20"},
			},
		})).To(Succeed())
	})

	It("rejects advertiseMode=bgp with an invalid CIDR", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"not-a-cidr"},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be a valid CIDR"))
	})

	It("rejects advertiseMode=bgp with an IPv6 CIDR", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"2001:db8::/32"},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("only IPv4 CIDR is supported"))
	})

	It("rejects advertiseMode=bgp with prefix outside /8-/32", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.0.0.0/5"},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("prefix must be between /8 and /32"))
	})

	It("rejects advertiseMode=arp addresses not in start-end format", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeARP,
				Addresses:     []string{"10.210.0.10"},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be in start-end format"))
	})

	It("rejects advertiseMode=arp addresses where start > end", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeARP,
				Addresses:     []string{"10.210.0.20-10.210.0.10"},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("range start must be <= end"))
	})

	It("rejects immutable spec.advertiseMode updates", func() {
		pool := &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.210.0.0/30"},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		var current juneauv1alpha1.AddressPool
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pool), &current)).To(Succeed())
		current.Spec.AdvertiseMode = juneauv1alpha1.AddressPoolAdvertiseModeARP

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("advertiseMode is immutable"))
	})

	It("rejects removing an element from spec.addresses", func() {
		pool := &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.210.0.0/30", "10.210.0.4/30"},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		var current juneauv1alpha1.AddressPool
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pool), &current)).To(Succeed())
		current.Spec.Addresses = []string{"10.210.0.0/30"}

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cannot be removed"))
	})

	It("accepts appending a new element to spec.addresses", func() {
		pool := &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.210.0.0/30"},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		var current juneauv1alpha1.AddressPool
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pool), &current)).To(Succeed())
		current.Spec.Addresses = []string{"10.210.0.0/30", "10.210.0.4/30"}

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	It("rejects deletion while an ExternalNetwork references the AddressPool", func() {
		pool := &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.210.0.0/30"},
			},
		}
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
		pool := &juneauv1alpha1.AddressPool{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
			Spec: juneauv1alpha1.AddressPoolSpec{
				AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
				Addresses:     []string{"10.210.0.0/30"},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

		Expect(webhookK8sClient.Delete(context.Background(), pool)).To(Succeed())
	})
})
