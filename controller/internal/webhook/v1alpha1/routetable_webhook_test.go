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

	It("requires endpointName for endpoint routes", func() {
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
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.endpointName"))
	})

	It("forbids endpointName for connected and internetGateway routes", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{
					{
						Dst: "10.82.0.0/24",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected, Endpoint: "nwep-a"},
					},
					{
						Dst: "0.0.0.0/0",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaInternetGateway, Endpoint: "nwep-b"},
					},
				},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.endpointName"))
		Expect(err.Error()).To(ContainSubstring("spec.routes[1].via.endpointName"))
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
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint, Endpoint: "nwep-a"},
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

	It("forbids endpointName and natGateway on vpcPeering routes", func() {
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
						Endpoint:   "nwep-a",
						NATGateway: "natgw-a",
					},
				}},
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.routes[0].via.endpointName"))
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
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint, Endpoint: "nwep-a", VpcPeering: "peering-a"},
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
