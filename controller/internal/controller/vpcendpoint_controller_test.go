package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("VpcEndpoint controller", func() {
	It("allocates a Vpc-local address and injects only its host route", func() {
		vpcName := createControllerVpc()
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		namespace := uniqueTestName("endpoint")
		serviceName := uniqueTestName("service")
		endpointName := uniqueTestName("endpoint")

		Expect(k8sClient.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})).To(Succeed())
		Expect(k8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: namespace},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}},
			},
		})).To(Succeed())
		ready := true
		Expect(k8sClient.Create(context.Background(), &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      uniqueTestName("slice"),
				Namespace: namespace,
				Labels:    map[string]string{discoveryv1.LabelServiceName: serviceName},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.16.0.10"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		})).To(Succeed())
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.VpcEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: endpointName},
			Spec: juneauv1alpha1.VpcEndpointSpec{
				Vpc:     vpcName,
				Subnet:  subnet.Name,
				Service: juneauv1alpha1.VpcEndpointServiceReference{Namespace: namespace, Name: serviceName},
			},
		})).To(Succeed())

		var address string
		Eventually(func(g Gomega) {
			var endpoint juneauv1alpha1.VpcEndpoint
			g.Expect(k8sClient.Get(context.Background(), types.NamespacedName{Name: endpointName}, &endpoint)).To(Succeed())
			g.Expect(endpoint.Status.Address).NotTo(BeEmpty())
			condition := meta.FindStatusCondition(endpoint.Status.Conditions, juneauv1alpha1.VpcEndpointConditionReady)
			g.Expect(condition).NotTo(BeNil())
			g.Expect(condition.Status).To(Equal(metav1.ConditionTrue))
			address = endpoint.Status.Address
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			routeTable := getControllerRouteTable(vpcName)
			g.Expect(routeTable.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
				Dst: address + "/32",
				Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
			}))
			for _, route := range routeTable.Status.Routes {
				g.Expect(route.Dst).NotTo(Equal(testServiceCIDR.String()))
			}
		}).Should(Succeed())
	})
})
