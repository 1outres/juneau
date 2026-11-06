package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("RouteTable webhook", func() {
	It("rejects missing required fields and invalid enum values", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.80.0.0/24",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.RouteViaType("invalid")},
				}},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.vpc"))
		Expect(err.Error()).To(ContainSubstring("Unsupported value"))
	})

	It("rejects immutable spec.vpc updates", func() {
		vpcName := createWebhookVpc()
		otherVpcName := createWebhookVpc()
		routeTable := newWebhookRouteTable(webhookUniqueTestName("routetable"), vpcName)
		Expect(webhookK8sClient.Create(context.Background(), routeTable)).To(Succeed())

		var current juneauv1alpha1.RouteTable
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(routeTable), &current)).To(Succeed())
		current.Spec.Vpc = otherVpcName

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.vpc is immutable"))
	})

	It("requires via.endpoint for endpoint routes", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.81.0.0/24",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint},
				}},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.endpoint"))
	})

	It("forbids via.endpoint for connected and internetGateway routes", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{
					{
						Dst: "10.82.0.0/24",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected, Endpoint: testRouteEndpoint()},
					},
					{
						Dst: "0.0.0.0/0",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaInternetGateway, Endpoint: testRouteEndpoint()},
					},
				},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.endpoint"))
		Expect(err.Error()).To(ContainSubstring("spec.routes[1].via.endpoint"))
	})

	It("rejects duplicate dst entries inside spec.routes", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{
					{
						Dst: "10.83.0.0/24",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaInternetGateway},
					},
					{
						Dst: "10.83.0.0/24",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint, Endpoint: testRouteEndpoint()},
					},
				},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Duplicate value"))
	})

	It("requires vpcPeering for vpcPeering routes", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.84.0.0/24",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering},
				}},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.vpcPeering"))
	})

	It("forbids via.endpoint and natGateway on vpcPeering routes", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.85.0.0/24",
					Via: juneauv1alpha1.RouteVia{
						Type:       juneauv1alpha1.ViaVpcPeering,
						VpcPeering: "peering-a",
						Endpoint:   testRouteEndpoint(),
						NATGateway: "natgw-a",
					},
				}},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.endpoint"))
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.natGateway"))
	})

	It("forbids vpcPeering on routes that are not vpcPeering routes", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{
					{
						Dst: "10.86.0.0/24",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaInternetGateway, VpcPeering: "peering-a"},
					},
					{
						Dst: "10.87.0.0/24",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint, Endpoint: testRouteEndpoint(), VpcPeering: "peering-a"},
					},
					{
						Dst: "10.88.0.0/24",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaNATGateway, NATGateway: "natgw-a", VpcPeering: "peering-a"},
					},
				},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.vpcPeering"))
		Expect(err.Error()).To(ContainSubstring("spec.routes[1].via.vpcPeering"))
		Expect(err.Error()).To(ContainSubstring("spec.routes[2].via.vpcPeering"))
	})

	It("rejects routes that duplicate connected routes from subnets in the same VPC", func() {
		vpcName := createWebhookVpc()
		subnetCIDR := webhookUniqueSubnetCIDR()
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: subnetCIDR,
			},
		})).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{{
					Dst: subnetCIDR,
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaInternetGateway},
				}},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("duplicates connected route"))
	})
})

func newWebhookRouteTable(name, vpcName string) *juneauv1alpha1.RouteTable {
	return &juneauv1alpha1.RouteTable{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName},
	}
}

func testRouteEndpoint() *juneauv1alpha1.RouteEndpointReference {
	return &juneauv1alpha1.RouteEndpointReference{Namespace: "default", AllocationIdentity: "router", Interface: "eth0"}
}

var _ = Describe("RouteTable webhook for endpoint and blackhole routes", func() {
	createRouteTable := func(routes ...juneauv1alpha1.Route) error {
		vpcName := createWebhookVpc()
		return webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName, Routes: routes},
		})
	}

	It("accepts an endpoint route to a workload that does not exist yet", func() {
		Expect(createRouteTable(juneauv1alpha1.Route{
			Dst: "10.90.0.0/24",
			Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint, Endpoint: testRouteEndpoint()},
		})).To(Succeed())
	})

	It("rejects an endpoint reference that cannot name a workload NIC", func() {
		err := createRouteTable(juneauv1alpha1.Route{
			Dst: "10.91.0.0/24",
			Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint, Endpoint: &juneauv1alpha1.RouteEndpointReference{
				Namespace:          "Not_A_Namespace",
				AllocationIdentity: "router",
				Interface:          "eth0",
			}},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.endpoint.namespace"))
	})

	It("accepts a blackhole route", func() {
		Expect(createRouteTable(juneauv1alpha1.Route{
			Dst: "10.92.0.0/24",
			Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaBlackhole},
		})).To(Succeed())
	})

	It("forbids every target on a blackhole route", func() {
		err := createRouteTable(juneauv1alpha1.Route{
			Dst: "10.93.0.0/24",
			Via: juneauv1alpha1.RouteVia{
				Type:           juneauv1alpha1.ViaBlackhole,
				Endpoint:       testRouteEndpoint(),
				NATGateway:     "natgw-a",
				VpcPeering:     "peering-a",
				TransitGateway: "tgw-a",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.endpoint"))
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.natGateway"))
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.vpcPeering"))
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.transitGateway"))
	})

	It("forbids via.endpoint on a natGateway route", func() {
		err := createRouteTable(juneauv1alpha1.Route{
			Dst: "0.0.0.0/0",
			Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaNATGateway, NATGateway: "natgw-a", Endpoint: testRouteEndpoint()},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.endpoint"))
	})
})
