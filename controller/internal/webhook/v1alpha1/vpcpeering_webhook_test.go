package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("VpcPeering webhook", func() {
	It("rejects a peering that names a Vpc which does not exist", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(
			webhookUniqueTestName("peering"), vpcName, webhookUniqueTestName("missing-vpc")))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.accepter.vpc"))
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("rejects a peering between a Vpc and itself", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(
			webhookUniqueTestName("peering"), vpcName, vpcName))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must not equal spec.requester.vpc"))
	})

	It("rejects a second peering for the same Vpc pair whichever side each Vpc is on", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		firstName := webhookUniqueTestName("peering")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(firstName, vpcA, vpcB))).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(
			webhookUniqueTestName("peering"), vpcB, vpcA))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("already connected by VpcPeering"))
		Expect(err.Error()).To(ContainSubstring(firstName))
	})

	It("rejects a peering whose two sides have overlapping Subnet CIDRs", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		subnetA := webhookUniqueTestName("subnet")
		subnetB := webhookUniqueTestName("subnet")
		createWebhookSubnet(subnetA, vpcA, "172.31.10.0/24")
		createWebhookSubnet(subnetB, vpcB, "172.31.10.0/25")

		err := webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(
			webhookUniqueTestName("peering"), vpcA, vpcB))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(subnetA))
		Expect(err.Error()).To(ContainSubstring(subnetB))
		Expect(err.Error()).To(ContainSubstring("overlaps"))
	})

	It("accepts a peering whose two sides have disjoint Subnet CIDRs", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		createWebhookSubnet(webhookUniqueTestName("subnet"), vpcA, "172.31.20.0/24")
		createWebhookSubnet(webhookUniqueTestName("subnet"), vpcB, "172.31.21.0/24")

		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(
			webhookUniqueTestName("peering"), vpcA, vpcB))).To(Succeed())
	})

	It("rejects changing either side of an existing peering", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		vpcC := createWebhookVpc()
		peering := newWebhookVpcPeering(webhookUniqueTestName("peering"), vpcA, vpcB)
		Expect(webhookK8sClient.Create(context.Background(), peering)).To(Succeed())

		var current juneauv1alpha1.VpcPeering
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(peering), &current)).To(Succeed())
		current.Spec.Accepter.Vpc = vpcC

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.accepter is immutable"))
	})

	It("rejects deleting a peering that a RouteTable still routes through", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		peeringName := webhookUniqueTestName("peering")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(peeringName, vpcA, vpcB))).To(Succeed())

		routeTableName := webhookUniqueTestName("routetable")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcA,
				Routes: []juneauv1alpha1.Route{{
					Dst: "172.31.30.0/24",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: peeringName},
				}},
			},
		})).To(Succeed())

		var peering juneauv1alpha1.VpcPeering
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: peeringName}, &peering)).To(Succeed())
		err := webhookK8sClient.Delete(context.Background(), &peering)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(routeTableName))
		Expect(err.Error()).To(ContainSubstring("still references this VpcPeering"))
	})

	It("allows deleting a peering that no RouteTable routes through", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		peeringName := webhookUniqueTestName("peering")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(peeringName, vpcA, vpcB))).To(Succeed())

		var peering juneauv1alpha1.VpcPeering
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: peeringName}, &peering)).To(Succeed())
		Expect(webhookK8sClient.Delete(context.Background(), &peering)).To(Succeed())
	})
})

var _ = Describe("Subnet ↔ VpcPeering webhook", func() {
	It("rejects a Subnet whose CIDR overlaps a Subnet of a peered Vpc", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		peeringName := webhookUniqueTestName("peering")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(peeringName, vpcA, vpcB))).To(Succeed())

		peerSubnet := webhookUniqueTestName("subnet")
		createWebhookSubnet(peerSubnet, vpcB, "172.31.40.0/24")

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcA,
				CIDR: "172.31.40.0/25",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(peerSubnet))
		Expect(err.Error()).To(ContainSubstring(peeringName))
	})

	It("accepts a Subnet that does not overlap any Subnet of a peered Vpc", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(
			webhookUniqueTestName("peering"), vpcA, vpcB))).To(Succeed())

		createWebhookSubnet(webhookUniqueTestName("subnet"), vpcB, "172.31.50.0/24")
		createWebhookSubnet(webhookUniqueTestName("subnet"), vpcA, "172.31.51.0/24")
	})
})

var _ = Describe("Vpc ↔ VpcPeering webhook", func() {
	It("rejects deleting a Vpc that a VpcPeering references", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		peeringName := webhookUniqueTestName("peering")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(peeringName, vpcA, vpcB))).To(Succeed())

		var vpc juneauv1alpha1.Vpc
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: vpcB}, &vpc)).To(Succeed())
		err := webhookK8sClient.Delete(context.Background(), &vpc)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(peeringName))
		Expect(err.Error()).To(ContainSubstring("still peer this Vpc"))
	})
})

func newWebhookVpcPeering(name, requesterVpc, accepterVpc string) *juneauv1alpha1.VpcPeering {
	return &juneauv1alpha1.VpcPeering{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.VpcPeeringSpec{
			Requester: juneauv1alpha1.VpcPeeringEndpoint{Vpc: requesterVpc},
			Accepter:  juneauv1alpha1.VpcPeeringEndpoint{Vpc: accepterVpc},
		},
	}
}

func createWebhookSubnet(name, vpcName, cidr string) {
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.SubnetSpec{
			Vpc:  vpcName,
			CIDR: cidr,
		},
	})).To(Succeed())
}
