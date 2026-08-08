package controller

import (
	"context"
	"fmt"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("TransitGatewayAttachment controller", func() {
	It("publishes the attached Vpc Subnets as prefixes", func() {
		tgw := createControllerTransitGateway()
		vpc := createControllerVpc()
		subnetA := createControllerSubnet(vpc, uniqueTestName("subnet"), uniqueTransitCIDR())
		subnetB := createControllerSubnet(vpc, uniqueTestName("subnet"), uniqueTransitCIDR())

		name := createControllerTransitGatewayAttachment(tgw, vpc, tgw, nil)

		Eventually(func(g Gomega) {
			attachment := getControllerTransitGatewayAttachment(name)
			ready := meta.FindStatusCondition(attachment.Status.Conditions, juneauv1alpha1.TransitGatewayAttachmentStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(ready.Reason).To(Equal(transitGatewayAttachmentReasonReconcileSucceeded))
			g.Expect(attachment.Status.Prefixes).To(ConsistOf(
				juneauv1alpha1.TransitGatewayAttachmentPrefix{CIDR: subnetA.Spec.CIDR, Subnet: subnetA.Name},
				juneauv1alpha1.TransitGatewayAttachmentPrefix{CIDR: subnetB.Spec.CIDR, Subnet: subnetB.Name},
			))
		}).Should(Succeed())
	})

	It("marks an attachment not ready when the TransitGateway is missing", func() {
		vpc := createControllerVpc()
		missing := uniqueTestName("tgw")

		name := uniqueTestName("tgwattach")
		Expect(k8sClient.Create(context.Background(), newControllerTransitGatewayAttachment(name, missing, vpc, missing, nil))).To(Succeed())

		Eventually(func(g Gomega) {
			attachment := getControllerTransitGatewayAttachment(name)
			ready := meta.FindStatusCondition(attachment.Status.Conditions, juneauv1alpha1.TransitGatewayAttachmentStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(transitGatewayAttachmentReasonTransitGatewayMissing))
			g.Expect(ready.Message).To(ContainSubstring(missing))
		}).Should(Succeed())
	})

	It("marks an attachment not ready when the Vpc is missing", func() {
		tgw := createControllerTransitGateway()
		missing := uniqueTestName("vpc")

		name := uniqueTestName("tgwattach")
		Expect(k8sClient.Create(context.Background(), newControllerTransitGatewayAttachment(name, tgw, missing, tgw, nil))).To(Succeed())

		Eventually(func(g Gomega) {
			attachment := getControllerTransitGatewayAttachment(name)
			ready := meta.FindStatusCondition(attachment.Status.Conditions, juneauv1alpha1.TransitGatewayAttachmentStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(transitGatewayAttachmentReasonVpcNotFound))
			g.Expect(ready.Message).To(ContainSubstring(missing))
		}).Should(Succeed())
	})

	It("marks an attachment not ready when the association route table is missing", func() {
		tgw := createControllerTransitGateway()
		vpc := createControllerVpc()
		missing := uniqueTestName("tgwrt")

		name := uniqueTestName("tgwattach")
		Expect(k8sClient.Create(context.Background(), newControllerTransitGatewayAttachment(name, tgw, vpc, missing, nil))).To(Succeed())

		Eventually(func(g Gomega) {
			attachment := getControllerTransitGatewayAttachment(name)
			ready := meta.FindStatusCondition(attachment.Status.Conditions, juneauv1alpha1.TransitGatewayAttachmentStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(transitGatewayAttachmentReasonRouteTableNotFound))
			g.Expect(ready.Message).To(ContainSubstring(missing))
		}).Should(Succeed())
	})

	It("marks an attachment not ready when a propagation belongs to another TransitGateway", func() {
		tgwA := createControllerTransitGateway()
		tgwB := createControllerTransitGateway()
		vpc := createControllerVpc()

		name := uniqueTestName("tgwattach")
		Expect(k8sClient.Create(context.Background(), newControllerTransitGatewayAttachment(name, tgwA, vpc, tgwA, []string{tgwB}))).To(Succeed())

		Eventually(func(g Gomega) {
			attachment := getControllerTransitGatewayAttachment(name)
			ready := meta.FindStatusCondition(attachment.Status.Conditions, juneauv1alpha1.TransitGatewayAttachmentStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(transitGatewayAttachmentReasonRouteTableForeign))
			g.Expect(ready.Message).To(ContainSubstring(tgwB))
		}).Should(Succeed())
	})

	It("refreshes the prefixes when a Subnet is added to the attached Vpc", func() {
		tgw := createControllerTransitGateway()
		vpc := createControllerVpc()
		name := createControllerTransitGatewayAttachment(tgw, vpc, tgw, nil)

		subnet := createControllerSubnet(vpc, uniqueTestName("subnet"), uniqueTransitCIDR())

		Eventually(func(g Gomega) {
			attachment := getControllerTransitGatewayAttachment(name)
			g.Expect(attachment.Status.Prefixes).To(ContainElement(
				juneauv1alpha1.TransitGatewayAttachmentPrefix{CIDR: subnet.Spec.CIDR, Subnet: subnet.Name},
			))
		}).Should(Succeed())
	})
})

func newControllerTransitGatewayAttachment(name, transitGateway, vpc, association string, propagations []string) *juneauv1alpha1.TransitGatewayAttachment {
	return &juneauv1alpha1.TransitGatewayAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.TransitGatewayAttachmentSpec{
			TransitGateway: transitGateway,
			Vpc:            vpc,
			Association:    association,
			Propagations:   propagations,
		},
	}
}

func createControllerTransitGatewayAttachment(transitGateway, vpc, association string, propagations []string) string {
	name := uniqueTestName("tgwattach")
	Expect(k8sClient.Create(context.Background(), newControllerTransitGatewayAttachment(name, transitGateway, vpc, association, propagations))).To(Succeed())

	Eventually(func(g Gomega) {
		attachment := getControllerTransitGatewayAttachment(name)
		ready := meta.FindStatusCondition(attachment.Status.Conditions, juneauv1alpha1.TransitGatewayAttachmentStatusReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
	}).Should(Succeed())

	return name
}

// uniqueTransitCIDR hands out a /24 that no other spec in this suite
// uses. Transit gateway specs put Subnets of several Vpcs into one
// route table, so a shared CIDR would look like an ambiguous route
// rather than an unrelated test.
var transitCIDRCounter uint32

func uniqueTransitCIDR() string {
	n := atomic.AddUint32(&transitCIDRCounter, 1)
	return fmt.Sprintf("172.20.%d.0/24", n%256)
}
