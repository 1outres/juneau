package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("NATGateway webhook", func() {
	It("rejects missing required fields via markers", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NATGateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookUniqueTestName("natgateway"),
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(SatisfyAny(
			ContainSubstring("spec.vpc"),
			ContainSubstring("spec.externalNetwork"),
		))
	})

	It("rejects a nonexistent Vpc", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NATGateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookUniqueTestName("natgateway"),
			},
			Spec: juneauv1alpha1.NATGatewaySpec{
				Vpc:             webhookUniqueTestName("missing-vpc"),
				ExternalNetwork: externalNetworkName,
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("rejects a nonexistent ExternalNetwork", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NATGateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookUniqueTestName("natgateway"),
			},
			Spec: juneauv1alpha1.NATGatewaySpec{
				Vpc:             "default",
				ExternalNetwork: webhookUniqueTestName("missing-externalnetwork"),
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ExternalNetwork does not exist"))
	})

	It("rejects an ExternalNetwork with non-bgp type", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeARP)
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NATGateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookUniqueTestName("natgateway"),
			},
			Spec: juneauv1alpha1.NATGatewaySpec{
				Vpc:             "default",
				ExternalNetwork: externalNetworkName,
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must have type=bgp"))
	})

	It("accepts a valid NATGateway", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NATGateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: webhookUniqueTestName("natgateway"),
			},
			Spec: juneauv1alpha1.NATGatewaySpec{
				Vpc:             "default",
				ExternalNetwork: externalNetworkName,
			},
		})).To(Succeed())
	})

	It("rejects deletion while a RouteTable references the NATGateway", func() {
		externalNetworkName := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		natGateway := &juneauv1alpha1.NATGateway{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("natgateway")},
			Spec: juneauv1alpha1.NATGatewaySpec{
				Vpc:             "default",
				ExternalNetwork: externalNetworkName,
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), natGateway)).To(Succeed())

		routeTable := &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: "default",
				Routes: []juneauv1alpha1.Route{
					{
						Dst: "203.0.113.0/24",
						Via: juneauv1alpha1.RouteVia{
							Type:       juneauv1alpha1.ViaNATGateway,
							NATGateway: natGateway.Name,
						},
					},
				},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), routeTable)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), natGateway)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("RouteTable"))
	})
})
