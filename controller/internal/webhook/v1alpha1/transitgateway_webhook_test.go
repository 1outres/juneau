package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("TransitGateway webhook", func() {
	It("rejects deleting a TransitGateway that still has an attachment", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpc := createWebhookVpc()
		attachment := webhookUniqueTestName("tgwattach")
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(attachment, tgw, vpc, routeTable, nil))).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.TransitGateway{
			ObjectMeta: metav1.ObjectMeta{Name: tgw},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(attachment))
		Expect(err.Error()).To(ContainSubstring("still attached to this TransitGateway"))
	})

	It("rejects deleting a TransitGateway that a RouteTable still routes through", func() {
		tgw := createWebhookTransitGateway()
		vpc := createWebhookVpc()
		routeTableName := webhookUniqueTestName("routetable")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpc,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.240.0.0/16",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaTransitGateway, TransitGateway: tgw},
				}},
			},
		})).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.TransitGateway{
			ObjectMeta: metav1.ObjectMeta{Name: tgw},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(routeTableName))
		Expect(err.Error()).To(ContainSubstring("still references this TransitGateway"))
	})

	It("allows deleting a TransitGateway with no attachment and no route", func() {
		tgw := createWebhookTransitGateway()

		Expect(webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.TransitGateway{
			ObjectMeta: metav1.ObjectMeta{Name: tgw},
		})).To(Succeed())
	})
})

var _ = Describe("TransitGatewayRouteTable webhook", func() {
	It("rejects a route table whose TransitGateway does not exist", func() {
		missing := webhookUniqueTestName("tgw")

		err := webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayRouteTable(webhookUniqueTestName("tgwrt"), missing))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.transitGateway"))
		Expect(err.Error()).To(ContainSubstring("referenced TransitGateway does not exist"))
	})

	It("rejects a static route that names neither an attachment nor a blackhole", func() {
		tgw := createWebhookTransitGateway()

		routeTable := newWebhookTransitGatewayRouteTable(webhookUniqueTestName("tgwrt"), tgw)
		routeTable.Spec.Routes = []juneauv1alpha1.TransitGatewayRoute{{Dst: "10.241.0.0/16"}}

		err := webhookK8sClient.Create(context.Background(), routeTable)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].attachment"))
	})

	It("rejects a blackhole route that also names an attachment", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpc := createWebhookVpc()
		attachment := webhookUniqueTestName("tgwattach")
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(attachment, tgw, vpc, routeTable, nil))).To(Succeed())

		other := newWebhookTransitGatewayRouteTable(webhookUniqueTestName("tgwrt"), tgw)
		other.Spec.Routes = []juneauv1alpha1.TransitGatewayRoute{{
			Dst:        "10.242.0.0/16",
			Attachment: attachment,
			Blackhole:  true,
		}}

		err := webhookK8sClient.Create(context.Background(), other)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be empty when blackhole is true"))
	})

	It("rejects duplicated static route destinations", func() {
		tgw := createWebhookTransitGateway()

		routeTable := newWebhookTransitGatewayRouteTable(webhookUniqueTestName("tgwrt"), tgw)
		routeTable.Spec.Routes = []juneauv1alpha1.TransitGatewayRoute{
			{Dst: "10.243.0.0/16", Blackhole: true},
			{Dst: "10.243.0.0/16", Blackhole: true},
		}

		err := webhookK8sClient.Create(context.Background(), routeTable)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[1].dst"))
	})

	It("rejects changing the TransitGateway of an existing route table", func() {
		tgwA := createWebhookTransitGateway()
		tgwB := createWebhookTransitGateway()
		name := createWebhookTransitGatewayRouteTable(tgwA)

		var current juneauv1alpha1.TransitGatewayRouteTable
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.TransitGateway = tgwB

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.transitGateway is immutable"))
	})

	It("rejects deleting a route table an attachment still uses", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		propagated := createWebhookTransitGatewayRouteTable(tgw)
		vpc := createWebhookVpc()
		attachment := webhookUniqueTestName("tgwattach")
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(attachment, tgw, vpc, routeTable, []string{propagated}))).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.TransitGatewayRouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: propagated},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(attachment))
		Expect(err.Error()).To(ContainSubstring("still references this TransitGatewayRouteTable"))
	})

	It("rejects deleting the default route table of a live TransitGateway", func() {
		tgw := createWebhookTransitGateway()
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayRouteTable(tgw, tgw))).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.TransitGatewayRouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: tgw},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("default TransitGatewayRouteTable"))
	})

	It("allows deleting a route table no attachment uses", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)

		Expect(webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.TransitGatewayRouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: routeTable},
		})).To(Succeed())
	})
})

var _ = Describe("TransitGatewayAttachment webhook", func() {
	It("rejects an attachment whose TransitGateway does not exist", func() {
		vpc := createWebhookVpc()
		missing := webhookUniqueTestName("tgw")

		err := webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), missing, vpc, missing, nil))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.transitGateway"))
		Expect(err.Error()).To(ContainSubstring("referenced TransitGateway does not exist"))
	})

	It("rejects an attachment whose Vpc does not exist", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		missing := webhookUniqueTestName("vpc")

		err := webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, missing, routeTable, nil))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.vpc"))
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("rejects an attachment whose association belongs to another TransitGateway", func() {
		tgwA := createWebhookTransitGateway()
		tgwB := createWebhookTransitGateway()
		foreign := createWebhookTransitGatewayRouteTable(tgwB)
		vpc := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgwA, vpc, foreign, nil))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.association"))
		Expect(err.Error()).To(ContainSubstring(tgwB))
	})

	It("rejects an attachment whose propagation belongs to another TransitGateway", func() {
		tgwA := createWebhookTransitGateway()
		tgwB := createWebhookTransitGateway()
		association := createWebhookTransitGatewayRouteTable(tgwA)
		foreign := createWebhookTransitGatewayRouteTable(tgwB)
		vpc := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgwA, vpc, association, []string{foreign}))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.propagations[0]"))
		Expect(err.Error()).To(ContainSubstring(tgwB))
	})

	It("rejects a second attachment for the same TransitGateway and Vpc", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpc := createWebhookVpc()
		first := webhookUniqueTestName("tgwattach")
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(first, tgw, vpc, routeTable, nil))).To(Succeed())

		err := webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpc, routeTable, nil))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(first))
		Expect(err.Error()).To(ContainSubstring("is already attached"))
	})

	It("rejects an attachment that would put overlapping CIDRs in one route table", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		subnetA := webhookUniqueTestName("subnet")
		subnetB := webhookUniqueTestName("subnet")
		createWebhookSubnet(subnetA, vpcA, "10.244.10.0/24")
		createWebhookSubnet(subnetB, vpcB, "10.244.10.0/25")

		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcA, routeTable, []string{routeTable}))).To(Succeed())

		err := webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcB, routeTable, []string{routeTable}))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(subnetA))
		Expect(err.Error()).To(ContainSubstring(subnetB))
		Expect(err.Error()).To(ContainSubstring("overlaps"))
	})

	It("accepts attachments whose Vpcs have disjoint CIDRs", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		createWebhookSubnet(webhookUniqueTestName("subnet"), vpcA, "10.245.10.0/24")
		createWebhookSubnet(webhookUniqueTestName("subnet"), vpcB, "10.245.11.0/24")

		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcA, routeTable, []string{routeTable}))).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcB, routeTable, []string{routeTable}))).To(Succeed())
	})

	It("rejects changing the TransitGateway or the Vpc of an attachment", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		name := webhookUniqueTestName("tgwattach")
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(name, tgw, vpcA, routeTable, nil))).To(Succeed())

		var current juneauv1alpha1.TransitGatewayAttachment
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.Vpc = vpcB

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.vpc is immutable"))
	})
})

var _ = Describe("Subnet ↔ TransitGateway webhook", func() {
	It("rejects a Subnet that overlaps a Vpc reachable through the same route table", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcA, routeTable, []string{routeTable}))).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcB, routeTable, []string{routeTable}))).To(Succeed())

		peerSubnet := webhookUniqueTestName("subnet")
		createWebhookSubnet(peerSubnet, vpcB, "10.246.10.0/24")

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcA,
				CIDR: "10.246.10.0/25",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(peerSubnet))
		Expect(err.Error()).To(ContainSubstring(routeTable))
	})

	It("accepts a Subnet that does not overlap any Vpc on the same route table", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcA, routeTable, []string{routeTable}))).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcB, routeTable, []string{routeTable}))).To(Succeed())

		createWebhookSubnet(webhookUniqueTestName("subnet"), vpcB, "10.247.10.0/24")
		createWebhookSubnet(webhookUniqueTestName("subnet"), vpcA, "10.247.11.0/24")
	})
})

var _ = Describe("Vpc ↔ TransitGateway webhook", func() {
	It("rejects deleting a Vpc that an attachment still connects", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpc := createWebhookVpc()
		attachment := webhookUniqueTestName("tgwattach")
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(attachment, tgw, vpc, routeTable, nil))).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpc},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(attachment))
		Expect(err.Error()).To(ContainSubstring("still attach this Vpc"))
	})
})

var _ = Describe("RouteTable ↔ TransitGateway webhook", func() {
	It("rejects a transitGateway route without spec.routes[].via.transitGateway", func() {
		vpc := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpc,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.248.0.0/16",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaTransitGateway},
				}},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[].via.transitGateway is required"))
	})

	It("rejects a transitGateway route that also names a VpcPeering", func() {
		vpc := createWebhookVpc()
		tgw := createWebhookTransitGateway()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpc,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.249.0.0/16",
					Via: juneauv1alpha1.RouteVia{
						Type:           juneauv1alpha1.ViaTransitGateway,
						TransitGateway: tgw,
						VpcPeering:     webhookUniqueTestName("peering"),
					},
				}},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[].via.vpcPeering must be empty when via.type is transitGateway"))
	})

	It("rejects a natGateway route that also names a TransitGateway", func() {
		vpc := createWebhookVpc()
		tgw := createWebhookTransitGateway()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpc,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.250.0.0/16",
					Via: juneauv1alpha1.RouteVia{
						Type:           juneauv1alpha1.ViaNATGateway,
						NATGateway:     webhookUniqueTestName("natgw"),
						TransitGateway: tgw,
					},
				}},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[].via.transitGateway must be empty when via.type is natGateway"))
	})

	It("accepts a well-formed transitGateway route", func() {
		vpc := createWebhookVpc()
		tgw := createWebhookTransitGateway()

		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpc,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.251.0.0/16",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaTransitGateway, TransitGateway: tgw},
				}},
			},
		})).To(Succeed())
	})
})

func createWebhookTransitGateway() string {
	name := webhookUniqueTestName("tgw")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.TransitGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})).To(Succeed())
	return name
}

func newWebhookTransitGatewayRouteTable(name, transitGateway string) *juneauv1alpha1.TransitGatewayRouteTable {
	return &juneauv1alpha1.TransitGatewayRouteTable{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.TransitGatewayRouteTableSpec{
			TransitGateway: transitGateway,
		},
	}
}

func createWebhookTransitGatewayRouteTable(transitGateway string) string {
	name := webhookUniqueTestName("tgwrt")
	Expect(webhookK8sClient.Create(context.Background(), newWebhookTransitGatewayRouteTable(name, transitGateway))).To(Succeed())
	return name
}

func newWebhookTransitGatewayAttachment(name, transitGateway, vpc, association string, propagations []string) *juneauv1alpha1.TransitGatewayAttachment {
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
