package v1alpha1

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("IPLease webhook", func() {
	It("rejects missing required fields", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.IPLease{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookUniqueTestName("iplease"),
			},
			Spec: juneauv1alpha1.IPLeaseSpec{
				PodRef: juneauv1alpha1.IPLeasePodReference{},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.podRef.namespace"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.name"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.interface"))
		Expect(err.Error()).To(ContainSubstring("spec.vpc"))
		Expect(err.Error()).To(ContainSubstring("spec.subnet"))
		Expect(err.Error()).To(ContainSubstring("spec.address"))
	})

	It("rejects immutable spec updates", func() {
		ipLease := newValidIPLease(webhookUniqueTestName("iplease"))
		Expect(webhookK8sClient.Create(context.Background(), ipLease)).To(Succeed())

		var current juneauv1alpha1.IPLease
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(ipLease), &current)).To(Succeed())

		updatedTTL := int32(120)
		current.Spec.PodRef.Namespace = "other"
		current.Spec.PodRef.Name = "pod-b"
		current.Spec.PodRef.Interface = "net2"
		current.Spec.Vpc = "other-vpc"
		current.Spec.Subnet = "other-subnet"
		current.Spec.Address = "10.16.0.11"
		current.Spec.TTLSeconds = &updatedTTL

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.podRef.namespace is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.name is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.podRef.interface is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.vpc is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.subnet is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.address is immutable"))
		Expect(err.Error()).To(ContainSubstring("spec.ttlSeconds is immutable"))
	})

	It("allows updating spec.ownerDeletionTimestamp", func() {
		ipLease := newValidIPLease(webhookUniqueTestName("iplease"))
		Expect(webhookK8sClient.Create(context.Background(), ipLease)).To(Succeed())

		var current juneauv1alpha1.IPLease
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(ipLease), &current)).To(Succeed())

		ts := metav1.NewTime(time.Now())
		current.Spec.OwnerDeletionTimeStamp = &ts

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})
})

func newValidIPLease(name string) *juneauv1alpha1.IPLease {
	ttl := int32(60)

	return &juneauv1alpha1.IPLease{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: juneauv1alpha1.IPLeaseSpec{
			PodRef: juneauv1alpha1.IPLeasePodReference{
				Namespace: "default",
				Name:      "pod-a",
				Interface: "net1",
			},
			Vpc:        "default",
			Subnet:     "default",
			Address:    "10.16.0.10",
			TTLSeconds: &ttl,
		},
	}
}
