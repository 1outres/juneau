package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/controller/internal/podnetwork"
)

var _ = Describe("L2Network webhook", func() {
	It("accepts a segment that declares nothing but its Vpc", func() {
		Expect(webhookK8sClient.Create(context.Background(), newWebhookL2Network(
			webhookUniqueTestName("l2net"), createWebhookVpc()))).To(Succeed())
	})

	It("rejects a segment in the default Vpc", func() {
		err := webhookK8sClient.Create(context.Background(), newWebhookL2Network(
			webhookUniqueTestName("l2net"), "default"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cannot reference the default Vpc"))
	})

	It("rejects a segment whose Vpc does not exist", func() {
		err := webhookK8sClient.Create(context.Background(), newWebhookL2Network(
			webhookUniqueTestName("l2net"), webhookUniqueTestName("missing-vpc")))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("rejects a CIDR that is not written in its normalized form", func() {
		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.CIDR = "10.210.0.5/24"

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`normalized form "10.210.0.0/24"`))
	})

	It("rejects a prefix outside the /16../28 range", func() {
		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.CIDR = "10.211.0.0/30"

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("between /16 and /28"))
	})

	It("rejects an MTU outside the 576..9000 range", func() {
		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.MTU = ptr.To(int32(100))

		Expect(webhookK8sClient.Create(context.Background(), l2)).NotTo(Succeed())
	})

	It("keeps spec.vpc and spec.cidr immutable", func() {
		name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(name, createWebhookVpc())
		l2.Spec.CIDR = "10.212.0.0/24"
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		var current juneauv1alpha1.L2Network
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.Vpc = createWebhookVpc()
		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.vpc is immutable"))

		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.CIDR = "10.213.0.0/24"
		err = webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.cidr is immutable"))
	})

	It("allows deleting a segment even while it still exists in a Vpc", func() {
		name := webhookUniqueTestName("l2net")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookL2Network(name, createWebhookVpc()))).To(Succeed())

		Expect(webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.L2Network{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		})).To(Succeed())
	})
})

var _ = Describe("L2Network gateway webhook", func() {
	It("rejects a gateway on a segment with no CIDR", func() {
		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.gateway needs spec.cidr"))
	})

	It("accepts a gateway that leaves its address to the controller", func() {
		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.CIDR = "10.214.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}

		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())
	})

	It("rejects a gateway address outside the CIDR", func() {
		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.CIDR = "10.215.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{Address: "10.216.0.1"}

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be within spec.cidr"))
	})

	It("rejects the network and the broadcast address as a gateway", func() {
		vpcName := createWebhookVpc()

		network := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName)
		network.Spec.CIDR = "10.217.0.0/24"
		network.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{Address: "10.217.0.0"}
		err := webhookK8sClient.Create(context.Background(), network)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must not be the network address"))

		broadcast := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName)
		broadcast.Spec.CIDR = "10.218.0.0/24"
		broadcast.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{Address: "10.218.0.255"}
		err = webhookK8sClient.Create(context.Background(), broadcast)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must not be the broadcast address"))
	})

	It("rejects a gateway RouteTable that does not exist", func() {
		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.CIDR = "10.219.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{RouteTable: webhookUniqueTestName("missing-rt")}

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced RouteTable does not exist"))
	})

	It("rejects a gateway RouteTable from another Vpc", func() {
		otherVpc := createWebhookVpc()
		routeTable := webhookUniqueTestName("rt")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: routeTable},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: otherVpc},
		})).To(Succeed())

		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.CIDR = "10.220.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{RouteTable: routeTable}

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("RouteTable belongs to a different Vpc"))
	})

	It("rejects deleting a RouteTable an L2Network gateway still uses", func() {
		vpcName := createWebhookVpc()
		routeTable := webhookUniqueTestName("rt")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: routeTable},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName},
		})).To(Succeed())

		l2Name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(l2Name, vpcName)
		l2.Spec.CIDR = "10.221.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{RouteTable: routeTable}
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: routeTable},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(l2Name))
		Expect(err.Error()).To(ContainSubstring("spec.gateway.routeTable"))
	})
})

var _ = Describe("L2Network ↔ NetworkACL webhook", func() {
	It("rejects a NetworkACL on a segment with no gateway", func() {
		vpcName := createWebhookVpc()
		aclName := createWebhookNetworkACLIn(vpcName)

		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName)
		l2.Spec.CIDR = "10.222.0.0/24"
		l2.Spec.NetworkACL = aclName

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("only applies to traffic crossing spec.gateway"))
	})

	It("accepts a NetworkACL once the segment has a gateway", func() {
		vpcName := createWebhookVpc()
		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName)
		l2.Spec.CIDR = "10.223.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		l2.Spec.NetworkACL = createWebhookNetworkACLIn(vpcName)

		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())
	})

	It("rejects a NetworkACL that does not exist", func() {
		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.CIDR = "10.224.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		l2.Spec.NetworkACL = webhookUniqueTestName("missing-acl")

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced NetworkACL does not exist"))
	})

	It("rejects a NetworkACL from another Vpc", func() {
		aclName := createWebhookNetworkACLIn(createWebhookVpc())

		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), createWebhookVpc())
		l2.Spec.CIDR = "10.225.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		l2.Spec.NetworkACL = aclName

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("NetworkACL belongs to Vpc"))
	})

	It("rejects deleting a NetworkACL an L2Network still references", func() {
		vpcName := createWebhookVpc()
		aclName := createWebhookNetworkACLIn(vpcName)

		l2Name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(l2Name, vpcName)
		l2.Spec.CIDR = "10.226.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		l2.Spec.NetworkACL = aclName
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: aclName},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced by L2Network"))
		Expect(err.Error()).To(ContainSubstring(l2Name))
	})
})

var _ = Describe("L2Network CIDR overlap webhook", func() {
	It("rejects a CIDR that overlaps a Subnet of the same Vpc", func() {
		vpcName := createWebhookVpc()
		subnetName := webhookUniqueTestName("subnet")
		createWebhookSubnet(subnetName, vpcName, "10.230.0.0/24")

		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName)
		l2.Spec.CIDR = "10.230.0.0/25"

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(subnetName))
	})

	It("rejects a CIDR that overlaps another L2Network of the same Vpc", func() {
		vpcName := createWebhookVpc()
		firstName := webhookUniqueTestName("l2net")
		first := newWebhookL2Network(firstName, vpcName)
		first.Spec.CIDR = "10.231.0.0/24"
		Expect(webhookK8sClient.Create(context.Background(), first)).To(Succeed())

		second := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName)
		second.Spec.CIDR = "10.231.0.0/25"

		err := webhookK8sClient.Create(context.Background(), second)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(firstName))
		Expect(err.Error()).To(ContainSubstring("L2Network"))
	})

	It("rejects a Subnet whose CIDR overlaps an L2Network of the same Vpc", func() {
		vpcName := createWebhookVpc()
		l2Name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(l2Name, vpcName)
		l2.Spec.CIDR = "10.232.0.0/24"
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.232.0.0/25",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(l2Name))
	})

	It("rejects a CIDR that overlaps a Subnet of a peered Vpc", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		peeringName := webhookUniqueTestName("peering")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(peeringName, vpcA, vpcB))).To(Succeed())

		peerSubnet := webhookUniqueTestName("subnet")
		createWebhookSubnet(peerSubnet, vpcB, "10.233.0.0/24")

		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcA)
		l2.Spec.CIDR = "10.233.0.0/25"

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(peerSubnet))
		Expect(err.Error()).To(ContainSubstring(peeringName))
	})

	It("rejects a CIDR that overlaps a Vpc reachable through a TransitGatewayRouteTable", func() {
		tgw := createWebhookTransitGateway()
		routeTable := createWebhookTransitGatewayRouteTable(tgw)
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcA, routeTable, []string{routeTable}))).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookTransitGatewayAttachment(webhookUniqueTestName("tgwattach"), tgw, vpcB, routeTable, []string{routeTable}))).To(Succeed())

		peerSubnet := webhookUniqueTestName("subnet")
		createWebhookSubnet(peerSubnet, vpcB, "10.234.0.0/24")

		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcA)
		l2.Spec.CIDR = "10.234.0.0/25"

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(peerSubnet))
		Expect(err.Error()).To(ContainSubstring(routeTable))
	})

	It("rejects a CIDR that overlaps the endpoint pool of its own Vpc", func() {
		vpcName := createWebhookVpcWithEndpointPool("10.235.0.0/24")

		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName)
		l2.Spec.CIDR = "10.235.0.0/25"

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlaps with endpoint pool CIDR"))
	})

	It("rejects a CIDR that overlaps the Service CIDR while the Vpc routes Services", func() {
		vpcName := webhookUniqueTestName("vpc")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
			Spec:       juneauv1alpha1.VpcSpec{Service: &juneauv1alpha1.VpcServiceSpec{Consume: true}},
		})).To(Succeed())

		l2 := newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName)
		l2.Spec.CIDR = "10.96.0.0/24"

		err := webhookK8sClient.Create(context.Background(), l2)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlaps with Service CIDR"))
	})

	It("accepts two segments with no CIDR at all in the same Vpc", func() {
		vpcName := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName))).To(Succeed())
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookL2Network(webhookUniqueTestName("l2net"), vpcName))).To(Succeed())
	})
})

var _ = Describe("Vpc ↔ L2Network webhook", func() {
	It("rejects deleting a Vpc that still has an L2Network", func() {
		vpcName := createWebhookVpc()
		l2Name := webhookUniqueTestName("l2net")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookL2Network(l2Name, vpcName))).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("L2Network"))
		Expect(err.Error()).To(ContainSubstring(l2Name))

		Expect(webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.L2Network{
			ObjectMeta: metav1.ObjectMeta{Name: l2Name},
		})).To(Succeed())
		Expect(webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		})).To(Succeed())
	})
})

func newWebhookL2Network(name, vpcName string) *juneauv1alpha1.L2Network {
	return &juneauv1alpha1.L2Network{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.L2NetworkSpec{Vpc: vpcName},
	}
}

func createWebhookNetworkACLIn(vpcName string) string {
	name := webhookUniqueTestName("acl")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.NetworkACLSpec{Vpc: vpcName},
	})).To(Succeed())
	return name
}

func createWebhookSecurityGroupIn(vpcName string) string {
	name := webhookUniqueTestName("sg")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.SecurityGroupSpec{Vpc: vpcName},
	})).To(Succeed())
	return name
}

var _ = Describe("NetworkInterface ↔ L2Network webhook", func() {
	It("rejects an interface that names neither a Subnet nor an L2Network", func() {
		iface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "", "")

		err := webhookK8sClient.Create(context.Background(), iface)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("set exactly one of spec.subnet and spec.l2Network"))
	})

	It("rejects an interface that names both a Subnet and an L2Network", func() {
		iface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "")
		iface.Spec.L2Network = webhookUniqueTestName("l2net")

		err := webhookK8sClient.Create(context.Background(), iface)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("set exactly one of spec.subnet and spec.l2Network"))
	})

	It("rejects an interface whose L2Network does not exist", func() {
		iface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "", "")
		iface.Spec.L2Network = webhookUniqueTestName("missing-l2net")

		err := webhookK8sClient.Create(context.Background(), iface)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced L2Network does not exist"))
	})

	It("rejects a pinned address on a segment that hands out none", func() {
		l2Name := webhookUniqueTestName("l2net")
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookL2Network(l2Name, createWebhookVpc()))).To(Succeed())

		iface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "", "10.240.0.5")
		iface.Spec.L2Network = l2Name

		err := webhookK8sClient.Create(context.Background(), iface)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("hands out no address"))
	})

	It("keeps spec.l2Network immutable", func() {
		l2Name := webhookUniqueTestName("l2net")
		Expect(webhookK8sClient.Create(context.Background(),
			newWebhookL2Network(l2Name, createWebhookVpc()))).To(Succeed())

		name := webhookUniqueTestName("networkinterface")
		iface := newValidNetworkInterface(name, "", "")
		iface.Spec.L2Network = l2Name
		Expect(webhookK8sClient.Create(context.Background(), iface)).To(Succeed())

		var current juneauv1alpha1.NetworkInterface
		Expect(webhookK8sClient.Get(context.Background(),
			client.ObjectKey{Name: name, Namespace: "default"}, &current)).To(Succeed())
		current.Spec.L2Network = webhookUniqueTestName("other-l2net")

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.l2Network is immutable"))
	})
})

var _ = Describe("L2Network gateway address webhook", func() {
	It("rejects a gateway whose address a workload already holds", func() {
		name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(name, createWebhookVpc())
		l2.Spec.CIDR = "10.226.0.0/24"
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		leaseL2NetworkAddress(name, "10.226.0.1")

		var current juneauv1alpha1.L2Network
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("10.226.0.1"))
		Expect(err.Error()).To(ContainSubstring("already held"))
	})

	It("accepts a gateway on another address once the default one is taken", func() {
		name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(name, createWebhookVpc())
		l2.Spec.CIDR = "10.227.0.0/24"
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		leaseL2NetworkAddress(name, "10.227.0.1")

		var current juneauv1alpha1.L2Network
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{Address: "10.227.0.254"}

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	It("leaves a segment whose gateway address did not change alone", func() {
		name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(name, createWebhookVpc())
		l2.Spec.CIDR = "10.228.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		leaseL2NetworkAddress(name, "10.228.0.1")

		var current juneauv1alpha1.L2Network
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.MTU = ptr.To(int32(1400))

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	It("ignores a lease that belongs to another segment", func() {
		name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(name, createWebhookVpc())
		l2.Spec.CIDR = "10.229.0.0/24"
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		leaseL2NetworkAddress(webhookUniqueTestName("other-l2net"), "10.229.0.1")

		var current juneauv1alpha1.L2Network
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
		current.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}

		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})
})

// leaseL2NetworkAddress records address as taken out of the address pool
// of the named L2Network, the way a running workload's NIC would.
func leaseL2NetworkAddress(l2Name, address string) {
	name := webhookUniqueTestName("lease")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.AllocationLease{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.AllocationLeaseSpec{
			PoolRef: juneauv1alpha1.AllocationPoolReference{
				Name: podnetwork.L2NetworkAllocationPoolName(l2Name),
			},
			Value:    juneauv1alpha1.AllocationValue{IP: address},
			ClaimRef: juneauv1alpha1.AllocationLeaseClaimReference{Name: name, UID: name},
		},
	})).To(Succeed())
}

var _ = Describe("SecurityGroups on an L2Network NIC", func() {
	It("rejects a SecurityGroup on a NIC of a segment with no gateway", func() {
		vpcName := createWebhookVpc()
		l2Name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(l2Name, vpcName)
		l2.Spec.CIDR = "10.230.0.0/24"
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		iface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "", "")
		iface.Spec.L2Network = l2Name
		iface.Spec.SecurityGroups = []string{createWebhookSecurityGroupIn(vpcName)}

		err := webhookK8sClient.Create(context.Background(), iface)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("only applies to traffic crossing the gateway"))
	})

	It("accepts a SecurityGroup once the segment has a gateway", func() {
		vpcName := createWebhookVpc()
		l2Name := webhookUniqueTestName("l2net")
		l2 := newWebhookL2Network(l2Name, vpcName)
		l2.Spec.CIDR = "10.231.0.0/24"
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())

		iface := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "", "")
		iface.Spec.L2Network = l2Name
		iface.Spec.SecurityGroups = []string{createWebhookSecurityGroupIn(vpcName)}

		Expect(webhookK8sClient.Create(context.Background(), iface)).To(Succeed())
	})
})
