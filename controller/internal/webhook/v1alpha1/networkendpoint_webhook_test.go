package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("NetworkEndpoint webhook", func() {
	It("rejects empty required fields", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("networkendpoint"),
				Namespace: "default",
			},
			Spec: juneauv1alpha1.NetworkEndpointSpec{},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.kind"))
		Expect(err.Error()).To(ContainSubstring("spec.nodeName"))
		Expect(err.Error()).To(ContainSubstring("spec.subnet"))
	})

	It("requires PodRef when kind=Pod", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("networkendpoint"),
				Namespace: "default",
			},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				Kind:       juneauv1alpha1.EndpointKindPod,
				NodeName:   "node-a",
				Subnet:     "default",
				Address:    "10.16.0.10/24",
				MACAddress: "02:42:ac:10:00:01",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.podRef"))
	})

	It("forbids PodRef when kind=Node", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("networkendpoint"),
				Namespace: "default",
			},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				Kind:       juneauv1alpha1.EndpointKindNode,
				NodeName:   "node-a",
				Subnet:     "default",
				Address:    "10.16.0.10/24",
				MACAddress: "02:42:ac:10:00:01",
				PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
					UID:       "pod-uid-1",
					Name:      "pod-a",
					Interface: "net1",
				},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.podRef"))
	})

	It("rejects immutable spec updates", func() {
		networkEndpoint := newValidNetworkEndpoint(webhookUniqueTestName("networkendpoint"))
		Expect(webhookK8sClient.Create(context.Background(), networkEndpoint)).To(Succeed())

		var current juneauv1alpha1.NetworkEndpoint
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkEndpoint), &current)).To(Succeed())

		current.Spec.Kind = juneauv1alpha1.EndpointKindNode
		current.Spec.NodeName = "node-b"
		current.Spec.Subnet = "other-subnet"
		current.Spec.Address = "10.16.0.11/24"
		current.Spec.MACAddress = "02:42:ac:10:00:02"
		current.Spec.PodRef.UID = "pod-uid-2"
		current.Spec.PodRef.Name = "pod-b"
		current.Spec.PodRef.Interface = "net2"

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.kind is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.nodeName is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.subnet is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.address is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.macAddress is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.uid is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.name is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.interface is immutable"))
	})

	It("permits attachment mutation", func() {
		networkEndpoint := newValidNetworkEndpoint(webhookUniqueTestName("networkendpoint"))
		networkEndpoint.Spec.Attachment = &juneauv1alpha1.NetworkEndpointAttachment{
			Ifindex:        1,
			HostMACAddress: "02:42:ac:10:00:11",
			ContainerID:    "container-s1-1",
		}
		Expect(webhookK8sClient.Create(context.Background(), networkEndpoint)).To(Succeed())

		var current juneauv1alpha1.NetworkEndpoint
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkEndpoint), &current)).To(Succeed())
		current.Spec.Attachment.Ifindex = 99
		current.Spec.Attachment.HostMACAddress = "02:42:ac:10:00:99"
		current.Spec.Attachment.ContainerID = "container-sandbox-2"
		current.Spec.MACAddress = "02:42:ac:10:00:99"
		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	It("rejects Pod MAC mutation within the same attachment generation", func() {
		networkEndpoint := newValidNetworkEndpoint(webhookUniqueTestName("networkendpoint"))
		networkEndpoint.Spec.Attachment = &juneauv1alpha1.NetworkEndpointAttachment{
			Ifindex:        1,
			HostMACAddress: "02:42:ac:10:00:11",
			ContainerID:    "container-sandbox-1",
		}
		Expect(webhookK8sClient.Create(context.Background(), networkEndpoint)).To(Succeed())

		var current juneauv1alpha1.NetworkEndpoint
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkEndpoint), &current)).To(Succeed())
		current.Spec.MACAddress = "02:42:ac:10:00:99"
		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.macAddress is immutable"))
	})
})

func newValidNetworkEndpoint(name string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:       juneauv1alpha1.EndpointKindPod,
			NodeName:   "node-a",
			Subnet:     "default",
			Address:    "10.16.0.10/24",
			MACAddress: "02:42:ac:10:00:01",
			PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
				UID:       "pod-uid-1",
				Name:      "pod-a",
				Interface: "net1",
			},
		},
	}
}
