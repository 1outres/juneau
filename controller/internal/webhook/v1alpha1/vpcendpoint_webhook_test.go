package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("VpcEndpoint webhook", func() {
	It("rejects a VpcEndpoint that names a Vpc which does not exist", func() {
		err := webhookK8sClient.Create(context.Background(), newWebhookVpcEndpoint(
			webhookUniqueTestName("vpcendpoint"), webhookUniqueTestName("missing-vpc")))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("rejects a VpcEndpoint whose Vpc has no endpoint pool", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), newWebhookVpcEndpoint(
			webhookUniqueTestName("vpcendpoint"), vpcName))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("has no spec.endpointPool"))
	})

	It("accepts a VpcEndpoint whose Vpc has an endpoint pool", func() {
		vpcName := createWebhookVpcWithEndpointPool("10.250.0.0/24")

		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcEndpoint(
			webhookUniqueTestName("vpcendpoint"), vpcName))).To(Succeed())
	})

	It("rejects changing spec.vpc", func() {
		vpcName := createWebhookVpcWithEndpointPool("10.251.0.0/24")
		otherVpc := createWebhookVpcWithEndpointPool("10.252.0.0/24")
		name := webhookUniqueTestName("vpcendpoint")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcEndpoint(name, vpcName))).To(Succeed())

		var endpoint juneauv1alpha1.VpcEndpoint
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &endpoint)).To(Succeed())
		endpoint.Spec.Vpc = otherVpc

		err := webhookK8sClient.Update(context.Background(), &endpoint)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.vpc is immutable"))
	})

	It("accepts changing spec.service", func() {
		vpcName := createWebhookVpcWithEndpointPool("10.253.0.0/24")
		name := webhookUniqueTestName("vpcendpoint")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcEndpoint(name, vpcName))).To(Succeed())

		var endpoint juneauv1alpha1.VpcEndpoint
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &endpoint)).To(Succeed())
		endpoint.Spec.Service.Name = webhookUniqueTestName("service")

		Expect(webhookK8sClient.Update(context.Background(), &endpoint)).To(Succeed())
	})
})

func newWebhookVpcEndpoint(name, vpcName string) *juneauv1alpha1.VpcEndpoint {
	return &juneauv1alpha1.VpcEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.VpcEndpointSpec{
			Vpc: vpcName,
			Service: juneauv1alpha1.VpcEndpointServiceReference{
				Namespace: "default",
				Name:      webhookUniqueTestName("service"),
			},
		},
	}
}

func createWebhookVpcEndpointWithAddress(name, vpcName, address string) {
	endpoint := newWebhookVpcEndpoint(name, vpcName)
	Expect(webhookK8sClient.Create(context.Background(), endpoint)).To(Succeed())

	// Controllers do not run in this suite, so the allocated address is
	// written directly to drive the pool-shrink validation.
	endpoint.Status.Address = address
	Expect(webhookK8sClient.Status().Update(context.Background(), endpoint)).To(Succeed())
}
