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

	Describe("AddressPool shared with another ExternalNetwork", func() {
		It("rejects an AddressPool that another ExternalNetwork already references", func() {
			pool := newWebhookBGPAddressPool()
			Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())
			holder := newWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP, pool.Name)
			Expect(webhookK8sClient.Create(context.Background(), holder)).To(Succeed())

			err := webhookK8sClient.Create(context.Background(), newWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP, pool.Name))

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.addressPools[0]"))
			Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("AddressPool %q is already referenced by ExternalNetwork %q", pool.Name, holder.Name)))
		})

		It("names the AddressPool that is shared when several are listed", func() {
			freePool := newWebhookARPAddressPool()
			sharedPool := newWebhookARPAddressPool()
			Expect(webhookK8sClient.Create(context.Background(), freePool)).To(Succeed())
			Expect(webhookK8sClient.Create(context.Background(), sharedPool)).To(Succeed())
			holder := newWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeARP, sharedPool.Name)
			Expect(webhookK8sClient.Create(context.Background(), holder)).To(Succeed())

			err := webhookK8sClient.Create(context.Background(), newWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeARP, freePool.Name, sharedPool.Name))

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.addressPools[1]"))
			Expect(err.Error()).NotTo(ContainSubstring("spec.addressPools[0]"))
			Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("AddressPool %q is already referenced by ExternalNetwork %q", sharedPool.Name, holder.Name)))
		})

		It("rejects an update that appends an AddressPool another ExternalNetwork references", func() {
			ownPool := newWebhookBGPAddressPool()
			sharedPool := newWebhookBGPAddressPool()
			Expect(webhookK8sClient.Create(context.Background(), ownPool)).To(Succeed())
			Expect(webhookK8sClient.Create(context.Background(), sharedPool)).To(Succeed())
			holder := newWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP, sharedPool.Name)
			Expect(webhookK8sClient.Create(context.Background(), holder)).To(Succeed())
			externalNetwork := newWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP, ownPool.Name)
			Expect(webhookK8sClient.Create(context.Background(), externalNetwork)).To(Succeed())

			var current juneauv1alpha1.ExternalNetwork
			Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(externalNetwork), &current)).To(Succeed())
			current.Spec.AddressPools = append(current.Spec.AddressPools, sharedPool.Name)

			err := webhookK8sClient.Update(context.Background(), &current)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.addressPools[1]"))
			Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("AddressPool %q is already referenced by ExternalNetwork %q", sharedPool.Name, holder.Name)))
		})

		It("does not count the ExternalNetwork being updated", func() {
			pool := newWebhookBGPAddressPool()
			Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())
			externalNetwork := newWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP, pool.Name)
			Expect(webhookK8sClient.Create(context.Background(), externalNetwork)).To(Succeed())

			var current juneauv1alpha1.ExternalNetwork
			Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(externalNetwork), &current)).To(Succeed())
			current.Labels = map[string]string{"example.com/touched": "true"}

			Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
		})

		It("accepts the AddressPool again once the ExternalNetwork that held it is gone", func() {
			pool := newWebhookBGPAddressPool()
			Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())
			holder := newWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP, pool.Name)
			Expect(webhookK8sClient.Create(context.Background(), holder)).To(Succeed())
			Expect(webhookK8sClient.Delete(context.Background(), holder)).To(Succeed())

			Expect(webhookK8sClient.Create(context.Background(), newWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP, pool.Name))).To(Succeed())
		})
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

func newWebhookExternalNetwork(networkType juneauv1alpha1.ExternalNetworkType, addressPools ...string) *juneauv1alpha1.ExternalNetwork {
	return &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
		Spec: juneauv1alpha1.ExternalNetworkSpec{
			Type:         networkType,
			AddressPools: addressPools,
		},
	}
}

func newWebhookBGPAddressPool() *juneauv1alpha1.AddressPool {
	return newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeBGP, newWebhookExternalBlock().cidr(0, 30))
}

func newWebhookARPAddressPool() *juneauv1alpha1.AddressPool {
	return newWebhookAddressPool(juneauv1alpha1.AddressPoolAdvertiseModeARP, newWebhookExternalBlock().addressRange(10, 20))
}
