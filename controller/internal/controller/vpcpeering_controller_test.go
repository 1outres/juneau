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

var _ = Describe("VpcPeering controller", func() {
	It("marks a peering ready once both Vpcs are allocated", func() {
		vpcA := createControllerVpc()
		vpcB := createControllerVpc()

		peeringName := createControllerVpcPeering(vpcA, vpcB)

		Eventually(func(g Gomega) {
			peering := getControllerVpcPeering(peeringName)
			ready := meta.FindStatusCondition(peering.Status.Conditions, juneauv1alpha1.VpcPeeringStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(ready.Reason).To(Equal(vpcPeeringReasonReconcileSucceeded))
			g.Expect(ready.ObservedGeneration).To(Equal(peering.Generation))
		}).Should(Succeed())
	})

	It("marks a peering not ready when one side names a missing Vpc", func() {
		vpcA := createControllerVpc()
		missing := uniqueTestName("vpc")

		peeringName := uniqueTestName("peering")
		Expect(k8sClient.Create(context.Background(), newControllerVpcPeering(peeringName, vpcA, missing))).To(Succeed())

		Eventually(func(g Gomega) {
			peering := getControllerVpcPeering(peeringName)
			ready := meta.FindStatusCondition(peering.Status.Conditions, juneauv1alpha1.VpcPeeringStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(vpcPeeringReasonVpcNotFound))
			g.Expect(ready.Message).To(ContainSubstring(missing))
		}).Should(Succeed())
	})

	It("marks a peering not ready when the two Vpcs have overlapping Subnet CIDRs", func() {
		vpcA := createControllerVpc()
		vpcB := createControllerVpc()
		subnetA := createControllerSubnet(vpcA, uniqueTestName("subnet"), "172.30.10.0/24")
		subnetB := createControllerSubnet(vpcB, uniqueTestName("subnet"), "172.30.10.0/25")

		peeringName := uniqueTestName("peering")
		Expect(k8sClient.Create(context.Background(), newControllerVpcPeering(peeringName, vpcA, vpcB))).To(Succeed())

		Eventually(func(g Gomega) {
			peering := getControllerVpcPeering(peeringName)
			ready := meta.FindStatusCondition(peering.Status.Conditions, juneauv1alpha1.VpcPeeringStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(vpcPeeringReasonCIDRConflict))
			g.Expect(ready.Message).To(ContainSubstring(subnetA.Name))
			g.Expect(ready.Message).To(ContainSubstring(subnetB.Name))
		}).Should(Succeed())
	})

	It("re-evaluates a ready peering when a conflicting Subnet appears", func() {
		vpcA := createControllerVpc()
		vpcB := createControllerVpc()
		peeringName := createControllerVpcPeering(vpcA, vpcB)

		createControllerSubnet(vpcA, uniqueTestName("subnet"), "172.30.20.0/24")
		createControllerSubnet(vpcB, uniqueTestName("subnet"), "172.30.20.128/25")

		Eventually(func(g Gomega) {
			peering := getControllerVpcPeering(peeringName)
			ready := meta.FindStatusCondition(peering.Status.Conditions, juneauv1alpha1.VpcPeeringStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(vpcPeeringReasonCIDRConflict))
		}).Should(Succeed())
	})
})

func newControllerVpcPeering(name, requesterVpc, accepterVpc string) *juneauv1alpha1.VpcPeering {
	return &juneauv1alpha1.VpcPeering{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.VpcPeeringSpec{
			Requester: juneauv1alpha1.VpcPeeringEndpoint{Vpc: requesterVpc},
			Accepter:  juneauv1alpha1.VpcPeeringEndpoint{Vpc: accepterVpc},
		},
	}
}

func createControllerVpcPeering(requesterVpc, accepterVpc string) string {
	name := uniqueTestName("peering")
	Expect(k8sClient.Create(context.Background(), newControllerVpcPeering(name, requesterVpc, accepterVpc))).To(Succeed())

	Eventually(func(g Gomega) {
		peering := getControllerVpcPeering(name)
		ready := meta.FindStatusCondition(peering.Status.Conditions, juneauv1alpha1.VpcPeeringStatusReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
	}).Should(Succeed())

	return name
}

func getControllerVpcPeering(name string) *juneauv1alpha1.VpcPeering {
	var peering juneauv1alpha1.VpcPeering
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &peering)).To(Succeed())
	return &peering
}
