package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("DNSZone controller", func() {
	It("marks a zone Ready when its Vpc exists", func() {
		zoneName := createControllerDNSZone(createControllerVpc(), "ready.example.com")
		Eventually(func(g Gomega) {
			zone := getControllerDNSZone(zoneName)
			condition := meta.FindStatusCondition(zone.Status.Conditions, juneauv1alpha1.DNSZoneConditionReady)
			g.Expect(condition).NotTo(BeNil())
			g.Expect(condition.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(condition.ObservedGeneration).To(Equal(zone.Generation))
			g.Expect(zone.Status.ObservedGeneration).To(Equal(zone.Generation))
		}).Should(Succeed())
	})

	It("marks all race-created duplicates not Ready and recovers the survivor after deletion", func() {
		vpcName := createControllerVpc()
		first := &juneauv1alpha1.DNSZone{ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("zone")}, Spec: juneauv1alpha1.DNSZoneSpec{Vpc: vpcName, Domain: "race.example.com"}}
		second := &juneauv1alpha1.DNSZone{ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("zone")}, Spec: first.Spec}
		Expect(k8sClient.Create(context.Background(), first)).To(Succeed())
		Expect(k8sClient.Create(context.Background(), second)).To(Succeed())

		for _, name := range []string{first.Name, second.Name} {
			Eventually(func(g Gomega) {
				zone := getControllerDNSZone(name)
				condition := meta.FindStatusCondition(zone.Status.Conditions, juneauv1alpha1.DNSZoneConditionReady)
				g.Expect(condition).NotTo(BeNil())
				g.Expect(condition.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(condition.Reason).To(Equal(dnsZoneReasonDuplicate))
			}).Should(Succeed())
		}

		Expect(k8sClient.Delete(context.Background(), second)).To(Succeed())
		Eventually(func(g Gomega) {
			zone := getControllerDNSZone(first.Name)
			condition := meta.FindStatusCondition(zone.Status.Conditions, juneauv1alpha1.DNSZoneConditionReady)
			g.Expect(condition).NotTo(BeNil())
			g.Expect(condition.Status).To(Equal(metav1.ConditionTrue))
		}).Should(Succeed())
	})
})

func createControllerDNSZone(vpcName, domain string) string {
	zone := &juneauv1alpha1.DNSZone{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("zone")},
		Spec:       juneauv1alpha1.DNSZoneSpec{Vpc: vpcName, Domain: domain},
	}
	Expect(k8sClient.Create(context.Background(), zone)).To(Succeed())
	return zone.Name
}

func getControllerDNSZone(name string) *juneauv1alpha1.DNSZone {
	var zone juneauv1alpha1.DNSZone
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &zone)).To(Succeed())
	return &zone
}
