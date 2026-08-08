package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("TransitGatewayRouteTable controller", func() {
	It("propagates the prefixes of every attachment that advertises into it", func() {
		tgw := createControllerTransitGateway()
		vpcA := createControllerVpc()
		vpcB := createControllerVpc()
		subnetA := createControllerSubnet(vpcA, uniqueTestName("subnet"), uniqueTransitCIDR())
		subnetB := createControllerSubnet(vpcB, uniqueTestName("subnet"), uniqueTransitCIDR())

		attachA := createControllerTransitGatewayAttachment(tgw, vpcA, tgw, []string{tgw})
		attachB := createControllerTransitGatewayAttachment(tgw, vpcB, tgw, []string{tgw})

		Eventually(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(tgw)
			ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.TransitGatewayRouteTableStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(routeTable.Status.Routes).To(ContainElements(
				juneauv1alpha1.ResolvedTransitGatewayRoute{
					Dst:        subnetA.Spec.CIDR,
					Attachment: attachA,
					Subnet:     subnetA.Name,
					Origin:     juneauv1alpha1.TransitGatewayRouteOriginPropagated,
				},
				juneauv1alpha1.ResolvedTransitGatewayRoute{
					Dst:        subnetB.Spec.CIDR,
					Attachment: attachB,
					Subnet:     subnetB.Name,
					Origin:     juneauv1alpha1.TransitGatewayRouteOriginPropagated,
				},
			))
		}).Should(Succeed())
	})

	It("does not propagate an attachment that only associates the table", func() {
		tgw := createControllerTransitGateway()
		vpc := createControllerVpc()
		subnet := createControllerSubnet(vpc, uniqueTestName("subnet"), uniqueTransitCIDR())
		createControllerTransitGatewayAttachment(tgw, vpc, tgw, nil)

		Consistently(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(tgw)
			for _, route := range routeTable.Status.Routes {
				g.Expect(route.Dst).NotTo(Equal(subnet.Spec.CIDR))
			}
		}).Should(Succeed())
	})

	It("lets a static route win over a propagated route for the same destination", func() {
		tgw := createControllerTransitGateway()
		vpcA := createControllerVpc()
		vpcB := createControllerVpc()
		cidr := uniqueTransitCIDR()
		createControllerSubnet(vpcA, uniqueTestName("subnet"), cidr)
		subnetB := createControllerSubnet(vpcB, uniqueTestName("subnet"), cidr)

		createControllerTransitGatewayAttachment(tgw, vpcA, tgw, []string{tgw})
		attachB := createControllerTransitGatewayAttachment(tgw, vpcB, tgw, nil)

		routeTableName := createControllerTransitGatewayRouteTable(tgw, []juneauv1alpha1.TransitGatewayRoute{{
			Dst:        cidr,
			Attachment: attachB,
		}})

		Eventually(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(routeTableName)
			g.Expect(routeTable.Status.Routes).To(ContainElement(
				juneauv1alpha1.ResolvedTransitGatewayRoute{
					Dst:        cidr,
					Attachment: attachB,
					Subnet:     subnetB.Name,
					Origin:     juneauv1alpha1.TransitGatewayRouteOriginStatic,
				},
			))
		}).Should(Succeed())
	})

	It("resolves a blackhole route without an attachment", func() {
		tgw := createControllerTransitGateway()
		cidr := uniqueTransitCIDR()

		routeTableName := createControllerTransitGatewayRouteTable(tgw, []juneauv1alpha1.TransitGatewayRoute{{
			Dst:       cidr,
			Blackhole: true,
		}})

		Eventually(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(routeTableName)
			g.Expect(routeTable.Status.Routes).To(ContainElement(
				juneauv1alpha1.ResolvedTransitGatewayRoute{
					Dst:       cidr,
					Blackhole: true,
					Origin:    juneauv1alpha1.TransitGatewayRouteOriginStatic,
				},
			))
		}).Should(Succeed())
	})

	It("marks the table not ready when a static route dst matches no Subnet exactly", func() {
		tgw := createControllerTransitGateway()
		vpc := createControllerVpc()
		createControllerSubnet(vpc, uniqueTestName("subnet"), "172.21.10.0/24")
		attachment := createControllerTransitGatewayAttachment(tgw, vpc, tgw, nil)

		routeTableName := uniqueTestName("tgwrt")
		Expect(k8sClient.Create(context.Background(), newControllerTransitGatewayRouteTable(routeTableName, tgw, []juneauv1alpha1.TransitGatewayRoute{{
			Dst:        "172.21.10.0/25",
			Attachment: attachment,
		}}))).To(Succeed())

		Eventually(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(routeTableName)
			ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.TransitGatewayRouteTableStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(transitGatewayRouteTableReasonNotReady))
			g.Expect(ready.Message).To(ContainSubstring("172.21.10.0/25"))
		}).Should(Succeed())
	})

	It("marks the table not ready when a static route names a missing attachment", func() {
		tgw := createControllerTransitGateway()
		missing := uniqueTestName("tgwattach")

		routeTableName := uniqueTestName("tgwrt")
		Expect(k8sClient.Create(context.Background(), newControllerTransitGatewayRouteTable(routeTableName, tgw, []juneauv1alpha1.TransitGatewayRoute{{
			Dst:        uniqueTransitCIDR(),
			Attachment: missing,
		}}))).To(Succeed())

		Eventually(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(routeTableName)
			ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.TransitGatewayRouteTableStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Message).To(ContainSubstring(missing))
		}).Should(Succeed())
	})

	It("reports an ambiguous route when two attachments propagate the same destination", func() {
		tgw := createControllerTransitGateway()
		vpcA := createControllerVpc()
		vpcB := createControllerVpc()
		cidr := uniqueTransitCIDR()
		createControllerSubnet(vpcA, uniqueTestName("subnet"), cidr)
		createControllerSubnet(vpcB, uniqueTestName("subnet"), cidr)

		attachA := createControllerTransitGatewayAttachment(tgw, vpcA, tgw, []string{tgw})
		attachB := createControllerTransitGatewayAttachment(tgw, vpcB, tgw, []string{tgw})

		Eventually(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(tgw)
			ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.TransitGatewayRouteTableStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(transitGatewayRouteTableReasonAmbiguousRoute))
			g.Expect(ready.Message).To(ContainSubstring(attachA))
			g.Expect(ready.Message).To(ContainSubstring(attachB))
			g.Expect(ready.Message).To(ContainSubstring(cidr))
		}).Should(Succeed())
	})

	It("marks the table not ready when its TransitGateway is missing", func() {
		missing := uniqueTestName("tgw")

		routeTableName := uniqueTestName("tgwrt")
		Expect(k8sClient.Create(context.Background(), newControllerTransitGatewayRouteTable(routeTableName, missing, nil))).To(Succeed())

		Eventually(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(routeTableName)
			ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.TransitGatewayRouteTableStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(transitGatewayRouteTableReasonTransitGatewayMissing))
			g.Expect(ready.Message).To(ContainSubstring(missing))
		}).Should(Succeed())
	})

	It("publishes routes sorted by destination", func() {
		tgw := createControllerTransitGateway()

		routeTableName := createControllerTransitGatewayRouteTable(tgw, []juneauv1alpha1.TransitGatewayRoute{
			{Dst: "172.22.30.0/24", Blackhole: true},
			{Dst: "172.22.10.0/24", Blackhole: true},
			{Dst: "172.22.20.0/24", Blackhole: true},
		})

		Eventually(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(routeTableName)
			dsts := make([]string, 0, len(routeTable.Status.Routes))
			for _, route := range routeTable.Status.Routes {
				dsts = append(dsts, route.Dst)
			}
			g.Expect(dsts).To(Equal([]string{"172.22.10.0/24", "172.22.20.0/24", "172.22.30.0/24"}))
		}).Should(Succeed())
	})
})

func newControllerTransitGatewayRouteTable(name, transitGateway string, routes []juneauv1alpha1.TransitGatewayRoute) *juneauv1alpha1.TransitGatewayRouteTable {
	return &juneauv1alpha1.TransitGatewayRouteTable{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.TransitGatewayRouteTableSpec{
			TransitGateway: transitGateway,
			Routes:         routes,
		},
	}
}

func createControllerTransitGatewayRouteTable(transitGateway string, routes []juneauv1alpha1.TransitGatewayRoute) string {
	name := uniqueTestName("tgwrt")
	Expect(k8sClient.Create(context.Background(), newControllerTransitGatewayRouteTable(name, transitGateway, routes))).To(Succeed())

	Eventually(func(g Gomega) {
		routeTable := getControllerTransitGatewayRouteTable(name)
		ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.TransitGatewayRouteTableStatusReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
	}).Should(Succeed())

	return name
}
