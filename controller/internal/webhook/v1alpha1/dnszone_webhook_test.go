package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("DNSZone webhook", func() {
	It("accepts a valid zone and rejects a duplicate in the same Vpc", func() {
		vpcName := createWebhookVpc()
		zone := newWebhookDNSZone(webhookUniqueTestName("zone"), vpcName, "apps.example.com")
		Expect(webhookK8sClient.Create(context.Background(), zone)).To(Succeed())

		duplicate := newWebhookDNSZone(webhookUniqueTestName("zone"), vpcName, zone.Spec.Domain)
		err := webhookK8sClient.Create(context.Background(), duplicate)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("already uses this domain"))
	})

	It("allows parent and child zones in one Vpc", func() {
		vpcName := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(), newWebhookDNSZone(
			webhookUniqueTestName("zone"), vpcName, "example.com"))).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(), newWebhookDNSZone(
			webhookUniqueTestName("zone"), vpcName, "apps.example.com"))).To(Succeed())
	})

	It("allows the same domain in different Vpcs", func() {
		firstVpc := createWebhookVpc()
		secondVpc := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(), newWebhookDNSZone(
			webhookUniqueTestName("zone"), firstVpc, "shared.example.com"))).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(), newWebhookDNSZone(
			webhookUniqueTestName("zone"), secondVpc, "shared.example.com"))).To(Succeed())
	})

	DescribeTable("rejects invalid or reserved domains",
		func(domain string) {
			err := webhookK8sClient.Create(context.Background(), newWebhookDNSZone(
				webhookUniqueTestName("zone"), createWebhookVpc(), domain))
			Expect(err).To(HaveOccurred())
		},
		Entry("uppercase", "Apps.example.com"),
		Entry("trailing dot", "apps.example.com."),
		Entry("cluster domain", "cluster.local"),
		Entry("below the cluster domain", "apps.cluster.local"),
	)

	It("requires an existing Vpc", func() {
		err := webhookK8sClient.Create(context.Background(), newWebhookDNSZone(
			webhookUniqueTestName("zone"), webhookUniqueTestName("missing-vpc"), "example.com"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("keeps Vpc and domain individually immutable", func() {
		vpcName := createWebhookVpc()
		otherVpc := createWebhookVpc()
		zone := newWebhookDNSZone(webhookUniqueTestName("zone"), vpcName, "immutable.example.com")
		Expect(webhookK8sClient.Create(context.Background(), zone)).To(Succeed())
		validator := &DNSZoneCustomValidator{Reader: webhookK8sClient}

		checks := []struct {
			field  string
			mutate func(*juneauv1alpha1.DNSZone)
		}{
			{field: "vpc", mutate: func(candidate *juneauv1alpha1.DNSZone) { candidate.Spec.Vpc = otherVpc }},
			{field: "domain", mutate: func(candidate *juneauv1alpha1.DNSZone) { candidate.Spec.Domain = "changed.example.com" }},
		}
		for _, check := range checks {
			var stored juneauv1alpha1.DNSZone
			Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: zone.Name}, &stored)).To(Succeed())
			candidate := stored.DeepCopy()
			check.mutate(candidate)
			_, err := validator.ValidateUpdate(context.Background(), &stored, candidate)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec." + check.field + " is immutable"))
		}
	})

	It("blocks deleting a zone while a record references it", func() {
		vpcName := createWebhookVpc()
		zone := newWebhookDNSZone(webhookUniqueTestName("zone"), vpcName, "guard.example.com")
		Expect(webhookK8sClient.Create(context.Background(), zone)).To(Succeed())
		record := newWebhookDNSRecord(webhookUniqueTestName("record"), zone.Name, "api",
			[]juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.10")}})
		Expect(webhookK8sClient.Create(context.Background(), record)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), zone)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("DNSRecord(s)"))
	})

	It("blocks deleting a Vpc while a zone belongs to it", func() {
		vpcName := createWebhookVpc()
		zone := newWebhookDNSZone(webhookUniqueTestName("zone"), vpcName, "vpc-guard.example.com")
		Expect(webhookK8sClient.Create(context.Background(), zone)).To(Succeed())

		var vpc juneauv1alpha1.Vpc
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
		err := webhookK8sClient.Delete(context.Background(), &vpc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("DNSZone(s)"))
	})
})

func newWebhookDNSZone(name, vpcName, domain string) *juneauv1alpha1.DNSZone {
	return &juneauv1alpha1.DNSZone{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.DNSZoneSpec{
			Vpc:    vpcName,
			Domain: domain,
		},
	}
}

func stringPointer(value string) *string {
	return &value
}
