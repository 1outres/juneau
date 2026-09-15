package v1alpha1

import (
	"context"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("DNSRecord webhook", func() {
	It("defaults TTL to 30", func() {
		zone := createWebhookDNSZone("default.example.com")
		record := newWebhookDNSRecord(webhookUniqueTestName("record"), zone, "@",
			[]juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.1")}})
		Expect(webhookK8sClient.Create(context.Background(), record)).To(Succeed())

		var stored juneauv1alpha1.DNSRecord
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: record.Name}, &stored)).To(Succeed())
		Expect(stored.Spec.TTL).NotTo(BeNil())
		Expect(*stored.Spec.TTL).To(Equal(int32(30)))
	})

	It("accepts every source shape and label selector expression", func() {
		zone := createWebhookDNSZone("sources.example.com")
		ttl := int32(86400)
		record := newWebhookDNSRecord(webhookUniqueTestName("record"), zone, "mixed",
			[]juneauv1alpha1.DNSRecordSource{
				{IP: stringPointer("192.0.2.2")},
				{NetworkInterface: &juneauv1alpha1.DNSNetworkInterfaceSource{Namespace: "default", Name: "nic"}},
				{VpcEndpoint: &juneauv1alpha1.DNSVpcEndpointSource{Name: "endpoint"}},
				{PodSelector: &juneauv1alpha1.DNSPodSelectorSource{
					Namespace: "default",
					Interface: "eth0",
					Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"api"},
					}}},
				}},
			})
		record.Spec.TTL = &ttl
		Expect(webhookK8sClient.Create(context.Background(), record)).To(Succeed())
	})

	DescribeTable("rejects invalid record input",
		func(mutate func(*juneauv1alpha1.DNSRecord)) {
			zone := createWebhookDNSZone("invalid.example.com")
			record := newWebhookDNSRecord(webhookUniqueTestName("record"), zone, "api",
				[]juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.3")}})
			mutate(record)
			Expect(webhookK8sClient.Create(context.Background(), record)).NotTo(Succeed())
		},
		Entry("unsupported type", func(record *juneauv1alpha1.DNSRecord) { record.Spec.Type = "AAAA" }),
		Entry("uppercase name", func(record *juneauv1alpha1.DNSRecord) { record.Spec.Name = "API" }),
		Entry("long label", func(record *juneauv1alpha1.DNSRecord) { record.Spec.Name = strings.Repeat("a", 64) }),
		Entry("trailing dot", func(record *juneauv1alpha1.DNSRecord) { record.Spec.Name = "api." }),
		Entry("wildcard", func(record *juneauv1alpha1.DNSRecord) { record.Spec.Name = "*.api" }),
		Entry("zero ttl", func(record *juneauv1alpha1.DNSRecord) { ttl := int32(0); record.Spec.TTL = &ttl }),
		Entry("too large ttl", func(record *juneauv1alpha1.DNSRecord) { ttl := int32(86401); record.Spec.TTL = &ttl }),
		Entry("invalid IP", func(record *juneauv1alpha1.DNSRecord) { record.Spec.Sources[0].IP = stringPointer("192.0.2.0/24") }),
		Entry("empty union", func(record *juneauv1alpha1.DNSRecord) { record.Spec.Sources[0] = juneauv1alpha1.DNSRecordSource{} }),
		Entry("two union members", func(record *juneauv1alpha1.DNSRecord) {
			record.Spec.Sources[0].VpcEndpoint = &juneauv1alpha1.DNSVpcEndpointSource{Name: "endpoint"}
		}),
		Entry("empty selector", func(record *juneauv1alpha1.DNSRecord) {
			record.Spec.Sources[0] = juneauv1alpha1.DNSRecordSource{PodSelector: &juneauv1alpha1.DNSPodSelectorSource{
				Namespace: "default", Interface: "eth0", Selector: metav1.LabelSelector{},
			}}
		}),
	)

	It("rejects a combined FQDN longer than 253 characters", func() {
		domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
		zone := createWebhookDNSZone(domain)
		record := newWebhookDNSRecord(webhookUniqueTestName("record"), zone, "x",
			[]juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.4")}})
		err := webhookK8sClient.Create(context.Background(), record)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("combined FQDN"))
	})

	It("rejects more than 100 sources", func() {
		zone := createWebhookDNSZone("source-limit.example.com")
		sources := make([]juneauv1alpha1.DNSRecordSource, 101)
		for i := range sources {
			sources[i].IP = stringPointer("192.0.2.4")
		}
		record := newWebhookDNSRecord(webhookUniqueTestName("record"), zone, "api", sources)
		Expect(webhookK8sClient.Create(context.Background(), record)).NotTo(Succeed())
	})

	It("rejects a name whose FQDN is in cluster.local even when its parent zone is allowed", func() {
		zone := createWebhookDNSZone("local")
		record := newWebhookDNSRecord(webhookUniqueTestName("record"), zone, "cluster",
			[]juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.4")}})
		err := webhookK8sClient.Create(context.Background(), record)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cluster.local is reserved"))
	})

	It("rejects a missing zone and a duplicate RRset", func() {
		missing := newWebhookDNSRecord(webhookUniqueTestName("record"), webhookUniqueTestName("missing-zone"), "api",
			[]juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.5")}})
		Expect(webhookK8sClient.Create(context.Background(), missing)).NotTo(Succeed())

		zone := createWebhookDNSZone("duplicates.example.com")
		first := newWebhookDNSRecord(webhookUniqueTestName("record"), zone, "api",
			[]juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.6")}})
		Expect(webhookK8sClient.Create(context.Background(), first)).To(Succeed())
		second := newWebhookDNSRecord(webhookUniqueTestName("record"), zone, "api",
			[]juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.7")}})
		err := webhookK8sClient.Create(context.Background(), second)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("already uses this name"))
	})

	It("keeps zone, name and type individually immutable while allowing TTL and sources to change", func() {
		zone := createWebhookDNSZone("immutable-record.example.com")
		otherZone := createWebhookDNSZone("other-immutable-record.example.com")
		record := newWebhookDNSRecord(webhookUniqueTestName("record"), zone, "api",
			[]juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.8")}})
		Expect(webhookK8sClient.Create(context.Background(), record)).To(Succeed())
		validator := &DNSRecordCustomValidator{Reader: webhookK8sClient}

		checks := []struct {
			field  string
			mutate func(*juneauv1alpha1.DNSRecord)
		}{
			{field: "zone", mutate: func(candidate *juneauv1alpha1.DNSRecord) { candidate.Spec.Zone = otherZone }},
			{field: "name", mutate: func(candidate *juneauv1alpha1.DNSRecord) { candidate.Spec.Name = "changed" }},
			{field: "type", mutate: func(candidate *juneauv1alpha1.DNSRecord) { candidate.Spec.Type = "AAAA" }},
		}
		for _, check := range checks {
			var stored juneauv1alpha1.DNSRecord
			Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: record.Name}, &stored)).To(Succeed())
			candidate := stored.DeepCopy()
			check.mutate(candidate)
			_, err := validator.ValidateUpdate(context.Background(), &stored, candidate)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec." + check.field + " is immutable"))
		}

		var stored juneauv1alpha1.DNSRecord
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: record.Name}, &stored)).To(Succeed())
		ttl := int32(60)
		stored.Spec.TTL = &ttl
		stored.Spec.Sources = []juneauv1alpha1.DNSRecordSource{{IP: stringPointer("192.0.2.9")}}
		Expect(webhookK8sClient.Update(context.Background(), &stored)).To(Succeed())
	})
})

func createWebhookDNSZone(domain string) string {
	zone := newWebhookDNSZone(webhookUniqueTestName("zone"), createWebhookVpc(), domain)
	Expect(webhookK8sClient.Create(context.Background(), zone)).To(Succeed())
	return zone.Name
}

func newWebhookDNSRecord(name, zone, relativeName string, sources []juneauv1alpha1.DNSRecordSource) *juneauv1alpha1.DNSRecord {
	return &juneauv1alpha1.DNSRecord{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.DNSRecordSpec{
			Zone:    zone,
			Name:    relativeName,
			Type:    juneauv1alpha1.DNSRecordTypeA,
			Sources: sources,
		},
	}
}
