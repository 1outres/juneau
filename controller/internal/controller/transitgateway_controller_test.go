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

var _ = Describe("TransitGateway controller", func() {
	It("creates a default route table it owns and reports it ready", func() {
		name := createControllerTransitGateway()

		Eventually(func(g Gomega) {
			tgw := getControllerTransitGateway(name)
			ready := meta.FindStatusCondition(tgw.Status.Conditions, juneauv1alpha1.TransitGatewayStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(ready.Reason).To(Equal(transitGatewayReasonReconcileSucceeded))
			g.Expect(ready.ObservedGeneration).To(Equal(tgw.Generation))
			g.Expect(tgw.Status.DefaultRouteTable).To(Equal(name))

			routeTable := getControllerTransitGatewayRouteTable(name)
			g.Expect(routeTable.Spec.TransitGateway).To(Equal(name))
			g.Expect(metav1.IsControlledBy(routeTable, tgw)).To(BeTrue())
		}).Should(Succeed())
	})

	It("allocates a table ID for the default route table", func() {
		name := createControllerTransitGateway()

		Eventually(func(g Gomega) {
			routeTable := getControllerTransitGatewayRouteTable(name)
			g.Expect(routeTable.Status.TableID).NotTo(BeZero())
			ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.TransitGatewayRouteTableStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		}).Should(Succeed())
	})
})

func createControllerTransitGateway() string {
	name := uniqueTestName("tgw")
	Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.TransitGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})).To(Succeed())

	Eventually(func(g Gomega) {
		tgw := getControllerTransitGateway(name)
		ready := meta.FindStatusCondition(tgw.Status.Conditions, juneauv1alpha1.TransitGatewayStatusReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
	}).Should(Succeed())

	return name
}

func getControllerTransitGateway(name string) *juneauv1alpha1.TransitGateway {
	var tgw juneauv1alpha1.TransitGateway
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &tgw)).To(Succeed())
	return &tgw
}

func getControllerTransitGatewayRouteTable(name string) *juneauv1alpha1.TransitGatewayRouteTable {
	var routeTable juneauv1alpha1.TransitGatewayRouteTable
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &routeTable)).To(Succeed())
	return &routeTable
}

func getControllerTransitGatewayAttachment(name string) *juneauv1alpha1.TransitGatewayAttachment {
	var attachment juneauv1alpha1.TransitGatewayAttachment
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &attachment)).To(Succeed())
	return &attachment
}
