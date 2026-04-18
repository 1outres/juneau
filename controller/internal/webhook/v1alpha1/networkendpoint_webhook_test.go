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
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				PodRef: juneauv1alpha1.NetworkEndpointPodReference{},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.podRef.uid"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.name"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.interface"))
		Expect(err.Error()).To(ContainSubstring("spec.nodeName"))
		Expect(err.Error()).To(ContainSubstring("spec.subnet"))
	})

	It("rejects immutable spec updates", func() {
		networkEndpoint := newValidNetworkEndpoint(webhookUniqueTestName("networkendpoint"))
		Expect(webhookK8sClient.Create(context.Background(), networkEndpoint)).To(Succeed())

		var current juneauv1alpha1.NetworkEndpoint
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkEndpoint), &current)).To(Succeed())

		current.Spec.NodeName = "node-b"
		current.Spec.Subnet = "other-subnet"
		current.Spec.Address = "10.16.0.11"
		current.Spec.MACAddress = "02:42:ac:10:00:02"
		current.Spec.HostMACAddress = "02:42:ac:10:00:03"
		current.Spec.Ifindex = 2
		current.Spec.PodRef.UID = "pod-uid-2"
		current.Spec.PodRef.Name = "pod-b"
		current.Spec.PodRef.Interface = "net2"

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.nodeName is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.subnet is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.address is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.macAddress is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.hostMACAddress is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.ifindex is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.uid is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.name is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.interface is immutable"))
	})
})

func newValidNetworkEndpoint(name string) *juneauv1alpha1.NetworkEndpoint {
	return &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			NodeName:       "node-a",
			Subnet:         "default",
			Address:        "10.16.0.10",
			MACAddress:     "02:42:ac:10:00:01",
			HostMACAddress: "02:42:ac:10:00:11",
			Ifindex:        1,
			PodRef: juneauv1alpha1.NetworkEndpointPodReference{
				UID:       "pod-uid-1",
				Name:      "pod-a",
				Interface: "net1",
			},
		},
	}
}
