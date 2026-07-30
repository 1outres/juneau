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

		current.Spec.Subnet = "other-subnet"
		current.Spec.Address = "10.16.0.11"

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.subnet is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.address is immutable"))
	})

	It("rejects rebinding while the previous attachment still has an endpoint", func() {
		ctx := context.Background()
		name := webhookUniqueTestName("networkinterface")
		networkInterface := newValidNetworkInterface(name, "default", "")
		Expect(webhookK8sClient.Create(ctx, networkInterface)).To(Succeed())

		oldAttachment := newValidNetworkInterfaceAttachment(webhookUniqueTestName("attachment"), name)
		Expect(webhookK8sClient.Create(ctx, oldAttachment)).To(Succeed())

		var current juneauv1alpha1.NetworkInterface
		Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(networkInterface), &current)).To(Succeed())
		current.Spec.AttachmentRef = &juneauv1alpha1.NetworkInterfaceAttachmentReference{
			Name: oldAttachment.Name,
			UID:  oldAttachment.UID,
		}
		Expect(webhookK8sClient.Update(ctx, &current)).To(Succeed())

		endpoint := newValidNetworkEndpoint(webhookUniqueTestName("networkendpoint"))
		endpoint.Spec.NetworkInterfaceRef = name
		endpoint.Spec.NetworkInterfaceAttachmentRef = current.Spec.AttachmentRef.DeepCopy()
		Expect(webhookK8sClient.Create(ctx, endpoint)).To(Succeed())

		newAttachment := newValidNetworkInterfaceAttachment(webhookUniqueTestName("attachment"), name)
		Expect(webhookK8sClient.Create(ctx, newAttachment)).To(Succeed())
		Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(networkInterface), &current)).To(Succeed())
		current.Spec.AttachmentRef = &juneauv1alpha1.NetworkInterfaceAttachmentReference{
			Name: newAttachment.Name,
			UID:  newAttachment.UID,
		}

		err := webhookK8sClient.Update(ctx, &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("still realizes the previous attachment"))
	})
})

func newValidNetworkInterface(name, subnet, address string) *juneauv1alpha1.NetworkInterface {
	return &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			Subnet:  subnet,
			Address: address,
		},
	}
}
