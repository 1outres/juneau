package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("NetworkInterface webhook", func() {
	It("rejects missing required fields", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkInterface{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("networkinterface"),
				Namespace: "default",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.podRef.uid"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.name"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.interface"))
		Expect(err.Error()).To(ContainSubstring("spec.nodeName"))
		Expect(err.Error()).To(ContainSubstring("spec.subnet"))
	})

	It("rejects creating a NetworkInterface referencing a nonexistent subnet", func() {
		err := webhookK8sClient.Create(context.Background(), newValidNetworkInterface(webhookUniqueTestName("networkinterface"), webhookUniqueTestName("missing-subnet"), "10.16.0.10"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Subnet does not exist"))
	})

	It("rejects creating a NetworkInterface with an invalid requested address", func() {
		err := webhookK8sClient.Create(context.Background(), newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "not-an-ip"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be a valid IPv4 address"))
	})

	It("rejects creating a NetworkInterface with an address outside the subnet CIDR", func() {
		err := webhookK8sClient.Create(context.Background(), newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "192.168.0.10"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be within Subnet CIDR"))
	})

	It("rejects immutable spec updates", func() {
		networkInterface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "10.16.0.10")
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		var current juneauv1alpha1.NetworkInterface
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkInterface), &current)).To(Succeed())

		current.Spec.NodeName = "node-b"
		current.Spec.Subnet = "other-subnet"
		current.Spec.Address = "10.16.0.11"
		current.Spec.PodRef.UID = "pod-uid-2"
		current.Spec.PodRef.Name = "pod-b"
		current.Spec.PodRef.Interface = "net2"

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.nodeName is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.subnet is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.address is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.uid is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.name is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.interface is immutable"))
	})
})

func newValidNetworkInterface(name, subnet, address string) *juneauv1alpha1.NetworkInterface {
	return &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			NodeName: "node-a",
			Subnet:   subnet,
			Address:  address,
			PodRef: juneauv1alpha1.NetworkInterfacePodReference{
				UID:       "pod-uid-1",
				Name:      "pod-a",
				Interface: "net1",
			},
		},
	}
}
