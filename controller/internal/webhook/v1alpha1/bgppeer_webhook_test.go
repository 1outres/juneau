package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("BGPPeer webhook", func() {
	It("defaults spec.peerPort to 179 when unspecified", func() {
		name := webhookUniqueTestName("bgppeer")
		peer := &juneauv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       65001,
				PeerASN:     65002,
				PeerAddress: "10.0.0.1",
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), peer)).To(Succeed())

		var current juneauv1alpha1.BGPPeer
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		Expect(current.Spec.PeerPort).To(Equal(uint16(179)))
	})

	It("does not overwrite an explicit spec.peerPort", func() {
		name := webhookUniqueTestName("bgppeer")
		peer := &juneauv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       65001,
				PeerASN:     65002,
				PeerAddress: "10.0.0.2",
				PeerPort:    12345,
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), peer)).To(Succeed())

		var current juneauv1alpha1.BGPPeer
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		Expect(current.Spec.PeerPort).To(Equal(uint16(12345)))
	})

	It("accepts an explicit spec.peerPort of 179", func() {
		name := webhookUniqueTestName("bgppeer")
		peer := &juneauv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       65001,
				PeerASN:     65002,
				PeerAddress: "10.0.0.3",
				PeerPort:    179,
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), peer)).To(Succeed())

		var current juneauv1alpha1.BGPPeer
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		Expect(current.Spec.PeerPort).To(Equal(uint16(179)))
	})

	It("rejects an IPv6 peerAddress", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgppeer")},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       65001,
				PeerASN:     65002,
				PeerAddress: "2001:db8::1",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("peerAddress must be a valid IPv4"))
	})

	It("rejects a malformed peerAddress", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgppeer")},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       65001,
				PeerASN:     65002,
				PeerAddress: "not-an-ip",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("peerAddress must be a valid IPv4"))
	})

	It("rejects spec.myASN=0 via marker", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgppeer")},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       0,
				PeerASN:     65002,
				PeerAddress: "10.0.0.4",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.myASN"))
	})

	It("rejects spec.peerASN=0 via marker", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("bgppeer")},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       65001,
				PeerASN:     0,
				PeerAddress: "10.0.0.5",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.peerASN"))
	})

	It("accepts updating spec.peerAddress", func() {
		name := webhookUniqueTestName("bgppeer")
		peer := &juneauv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: juneauv1alpha1.BGPPeerSpec{
				MyASN:       65001,
				PeerASN:     65002,
				PeerAddress: "10.0.0.6",
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), peer)).To(Succeed())

		var current juneauv1alpha1.BGPPeer
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.PeerAddress = "10.0.0.99"

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})
})
