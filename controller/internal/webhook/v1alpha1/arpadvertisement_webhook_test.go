package v1alpha1

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const webhookARPAdvertisementFinalizer = "test.juneau.loutres.me/hold"

var _ = Describe("ARPAdvertisement webhook", func() {
	It("rejects missing required fields via markers", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ARPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("arpadvertisement")},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.externalNetwork"))
		Expect(err.Error()).To(ContainSubstring("spec.address"))
		Expect(err.Error()).To(ContainSubstring("spec.nodeName"))
	})

	It("accepts an address inside the referenced arp ExternalNetwork", func() {
		space := newWebhookARPSpace()
		node := newWebhookARPNode()

		Expect(webhookK8sClient.Create(context.Background(), space.advertisement(space.address(10), node))).To(Succeed())
	})

	It("rejects a nonexistent ExternalNetwork", func() {
		space := newWebhookARPSpace()
		node := newWebhookARPNode()

		advertisement := space.advertisement(space.address(10), node)
		advertisement.Spec.ExternalNetwork = webhookUniqueTestName("missing-externalnetwork")

		err := webhookK8sClient.Create(context.Background(), advertisement)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ExternalNetwork does not exist"))
	})

	It("rejects a bgp ExternalNetwork", func() {
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
		node := newWebhookARPNode()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.ARPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("arpadvertisement")},
			Spec: juneauv1alpha1.ARPAdvertisementSpec{
				ExternalNetwork: externalNetwork.Name,
				Address:         "10.210.0.1",
				NodeName:        node,
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ExternalNetwork must have type=arp"))
	})

	It("rejects an address outside the referenced AddressPools", func() {
		space := newWebhookARPSpace()
		node := newWebhookARPNode()

		err := webhookK8sClient.Create(context.Background(), space.advertisement(space.address(30), node))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("address must fall inside one of the referenced ExternalNetwork's AddressPools"))
	})

	It("rejects a malformed address", func() {
		space := newWebhookARPSpace()
		node := newWebhookARPNode()

		err := webhookK8sClient.Create(context.Background(), space.advertisement("not-an-address", node))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("address must be a valid IPv4 address"))
	})

	It("rejects an IPv6 address", func() {
		space := newWebhookARPSpace()
		node := newWebhookARPNode()

		err := webhookK8sClient.Create(context.Background(), space.advertisement("2001:db8::1", node))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("address must be a valid IPv4 address"))
	})

	It("rejects a nonexistent node", func() {
		space := newWebhookARPSpace()

		err := webhookK8sClient.Create(context.Background(), space.advertisement(space.address(10), webhookUniqueTestName("missing-node")))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Node does not exist"))
	})

	It("rejects an address that is the InternalIP of a node", func() {
		space := newWebhookARPSpace()
		node := newWebhookARPNode()
		newWebhookARPNodeWithInternalIP(space.address(11))

		err := webhookK8sClient.Create(context.Background(), space.advertisement(space.address(11), node))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("address is the InternalIP of Node"))
	})

	It("rejects a second advertisement for the same address", func() {
		space := newWebhookARPSpace()
		nodeA := newWebhookARPNode()
		nodeB := newWebhookARPNode()

		first := space.advertisement(space.address(10), nodeA)
		Expect(webhookK8sClient.Create(context.Background(), first)).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), space.advertisement(space.address(10), nodeB))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("address %q is already advertised by ARPAdvertisement %q", space.address(10), first.Name)))
	})

	It("accepts an update that keeps the address of the advertisement itself", func() {
		space := newWebhookARPSpace()
		nodeA := newWebhookARPNode()
		nodeB := newWebhookARPNode()

		advertisement := space.advertisement(space.address(10), nodeA)
		Expect(webhookK8sClient.Create(context.Background(), advertisement)).To(Succeed())

		var current juneauv1alpha1.ARPAdvertisement
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(advertisement), &current)).To(Succeed())
		current.Spec.NodeName = nodeB

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	It("accepts the same address once the previous advertisement is being deleted", func() {
		space := newWebhookARPSpace()
		nodeA := newWebhookARPNode()
		nodeB := newWebhookARPNode()

		first := space.advertisement(space.address(10), nodeA)
		first.Finalizers = []string{webhookARPAdvertisementFinalizer}
		Expect(webhookK8sClient.Create(context.Background(), first)).To(Succeed())
		Expect(webhookK8sClient.Delete(context.Background(), first)).To(Succeed())
		DeferCleanup(func() {
			Expect(removeWebhookARPAdvertisementFinalizer(first.Name)).To(Succeed())
		})

		Expect(webhookK8sClient.Create(context.Background(), space.advertisement(space.address(10), nodeB))).To(Succeed())
	})

	It("rejects immutable spec.externalNetwork updates", func() {
		space := newWebhookARPSpace()
		other := newWebhookARPSpace()
		node := newWebhookARPNode()

		advertisement := space.advertisement(space.address(10), node)
		Expect(webhookK8sClient.Create(context.Background(), advertisement)).To(Succeed())

		var current juneauv1alpha1.ARPAdvertisement
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(advertisement), &current)).To(Succeed())
		current.Spec.ExternalNetwork = other.externalNetwork

		err := webhookK8sClient.Update(context.Background(), &current)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.externalNetwork is immutable"))
	})

	It("rejects immutable spec.address updates", func() {
		space := newWebhookARPSpace()
		node := newWebhookARPNode()

		advertisement := space.advertisement(space.address(10), node)
		Expect(webhookK8sClient.Create(context.Background(), advertisement)).To(Succeed())

		var current juneauv1alpha1.ARPAdvertisement
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(advertisement), &current)).To(Succeed())
		current.Spec.Address = space.address(11)

		err := webhookK8sClient.Update(context.Background(), &current)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.address is immutable"))
	})

	It("skips reference checks while the advertisement is being deleted", func() {
		space := newWebhookARPSpace()
		node := newWebhookARPNode()

		advertisement := space.advertisement(space.address(10), node)
		advertisement.Finalizers = []string{webhookARPAdvertisementFinalizer}
		Expect(webhookK8sClient.Create(context.Background(), advertisement)).To(Succeed())

		Expect(webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.ExternalNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: space.externalNetwork},
		})).To(Succeed())
		Expect(webhookK8sClient.Delete(context.Background(), advertisement)).To(Succeed())

		Expect(removeWebhookARPAdvertisementFinalizer(advertisement.Name)).To(Succeed())
	})
})

// webhookARPSpace is one arp AddressPool plus the ExternalNetwork in front of
// it. Each space owns a private /24 so that specs never contend for the
// cluster-wide uniqueness of an advertised address.
type webhookARPSpace struct {
	externalNetwork string
	addressPool     string
	base            string
}

var webhookARPSpaceCount int

func newWebhookARPSpace() *webhookARPSpace {
	webhookARPSpaceCount++
	base := fmt.Sprintf("10.211.%d", webhookARPSpaceCount)

	pool := &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("addresspool")},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeARP,
			Addresses:     []string{fmt.Sprintf("%s.10-%s.20", base, base)},
		},
	}
	Expect(webhookK8sClient.Create(context.Background(), pool)).To(Succeed())

	externalNetwork := &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("externalnetwork")},
		Spec: juneauv1alpha1.ExternalNetworkSpec{
			Type:         juneauv1alpha1.ExternalNetworkTypeARP,
			AddressPools: []string{pool.Name},
		},
	}
	Expect(webhookK8sClient.Create(context.Background(), externalNetwork)).To(Succeed())

	return &webhookARPSpace{
		externalNetwork: externalNetwork.Name,
		addressPool:     pool.Name,
		base:            base,
	}
}

func (s *webhookARPSpace) address(host int) string {
	return fmt.Sprintf("%s.%d", s.base, host)
}

func (s *webhookARPSpace) advertisement(address, nodeName string) *juneauv1alpha1.ARPAdvertisement {
	return &juneauv1alpha1.ARPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("arpadvertisement")},
		Spec: juneauv1alpha1.ARPAdvertisementSpec{
			ExternalNetwork: s.externalNetwork,
			Address:         address,
			NodeName:        nodeName,
		},
	}
}

func newWebhookARPNode() string {
	name := webhookUniqueTestName("node")
	Expect(webhookK8sClient.Create(context.Background(), &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})).To(Succeed())
	return name
}

func newWebhookARPNodeWithInternalIP(internalIP string) string {
	name := newWebhookARPNode()

	var node corev1.Node
	Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &node)).To(Succeed())
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: internalIP}}
	Expect(webhookK8sClient.Status().Update(context.Background(), &node)).To(Succeed())

	return name
}

func removeWebhookARPAdvertisementFinalizer(name string) error {
	var advertisement juneauv1alpha1.ARPAdvertisement
	if err := webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &advertisement); err != nil {
		return err
	}
	advertisement.Finalizers = nil
	return webhookK8sClient.Update(context.Background(), &advertisement)
}
