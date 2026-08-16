package controller

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("VpcEndpoint controller", func() {
	It("allocates an address inside the Vpc endpoint pool and outside every Subnet of the Vpc", func() {
		poolCIDR := uniqueEndpointPoolCIDR()
		vpcName := createControllerVpcWithEndpointPool(poolCIDR)
		createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		namespace, serviceName := createVpcEndpointBackend("")
		endpointName := createVpcEndpoint(vpcName, namespace, serviceName)

		var address string
		Eventually(func(g Gomega) {
			endpoint := getVpcEndpoint(endpointName)
			g.Expect(endpoint.Status.Address).NotTo(BeEmpty())
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionAddressAllocated, metav1.ConditionTrue, vpcEndpointReasonAllocated)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionServiceAccepted, metav1.ConditionTrue, vpcEndpointReasonAccepted)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionReady, metav1.ConditionTrue, vpcEndpointReasonReady)
			address = endpoint.Status.Address
		}).Should(Succeed())

		By("drawing the address from the endpoint pool")
		Expect(cidrContains(poolCIDR, address)).To(BeTrue(), "address %s must come from endpoint pool %s", address, poolCIDR)

		By("keeping the address out of every Subnet of the Vpc")
		var subnets juneauv1alpha1.SubnetList
		Expect(k8sClient.List(context.Background(), &subnets)).To(Succeed())
		checked := 0
		for i := range subnets.Items {
			subnet := &subnets.Items[i]
			if subnet.Spec.Vpc != vpcName {
				continue
			}
			checked++
			Expect(cidrContains(subnet.Spec.CIDR, address)).To(BeFalse(),
				"address %s must stay outside Subnet %s (%s)", address, subnet.Name, subnet.Spec.CIDR)
		}
		Expect(checked).To(BeNumerically(">", 0))
	})

	It("claims the endpoint address from the per-Vpc endpoint pool, not from a Subnet pool", func() {
		poolCIDR := uniqueEndpointPoolCIDR()
		vpcName := createControllerVpcWithEndpointPool(poolCIDR)
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		namespace, serviceName := createVpcEndpointBackend("")
		endpointName := createVpcEndpoint(vpcName, namespace, serviceName)

		Eventually(func(g Gomega) {
			endpoint := getVpcEndpoint(endpointName)
			g.Expect(endpoint.Status.AllocationClaim).NotTo(BeEmpty())

			var claim juneauv1alpha1.AllocationClaim
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: endpoint.Status.AllocationClaim}, &claim)).To(Succeed())
			g.Expect(claim.Spec.PoolRefs).To(HaveLen(1))
			g.Expect(claim.Spec.PoolRefs[0].Name).To(Equal(VpcEndpointIPAllocationPoolName(vpcName)))
			g.Expect(claim.Spec.PoolRefs[0].Name).NotTo(Equal(SubnetIPAllocationPoolName(subnet.Name)))
		}).Should(Succeed())
	})

	Context("main RouteTable", func() {
		It("routes every endpoint pool CIDR through vpcEndpoint before any VpcEndpoint exists", func() {
			poolA := uniqueEndpointPoolCIDR()
			poolB := uniqueEndpointPoolCIDR()
			vpcName := createControllerVpcWithEndpointPool(poolA, poolB)

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(vpcName)
				g.Expect(routeTable.Status.Routes).To(ContainElements(
					juneauv1alpha1.Route{Dst: poolA, Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcEndpoint}},
					juneauv1alpha1.Route{Dst: poolB, Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcEndpoint}},
				))
				g.Expect(countVpcEndpointRoutes(routeTable)).To(Equal(2))
			}).Should(Succeed())
		})

		It("carries no host route for the endpoint address and keeps the pool route after the VpcEndpoint is deleted", func() {
			poolCIDR := uniqueEndpointPoolCIDR()
			vpcName := createControllerVpcWithEndpointPool(poolCIDR)
			namespace, serviceName := createVpcEndpointBackend("")
			endpointName := createVpcEndpoint(vpcName, namespace, serviceName)
			poolRoute := juneauv1alpha1.Route{Dst: poolCIDR, Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcEndpoint}}

			var address string
			Eventually(func(g Gomega) {
				endpoint := getVpcEndpoint(endpointName)
				g.Expect(endpoint.Status.Address).NotTo(BeEmpty())
				address = endpoint.Status.Address
			}).Should(Succeed())

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(vpcName)
				g.Expect(routeTable.Status.Routes).To(ContainElement(poolRoute))
				g.Expect(countVpcEndpointRoutes(routeTable)).To(Equal(1))
				for _, route := range routeTable.Status.Routes {
					g.Expect(route.Dst).NotTo(Equal(address + "/32"))
					g.Expect(route.Dst).NotTo(Equal(testServiceCIDR.String()))
				}
			}).Should(Succeed())

			Expect(k8sClient.Delete(context.Background(), &juneauv1alpha1.VpcEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: endpointName},
			})).To(Succeed())
			Eventually(func(g Gomega) {
				var endpoint juneauv1alpha1.VpcEndpoint
				err := k8sClient.Get(context.Background(), client.ObjectKey{Name: endpointName}, &endpoint)
				g.Expect(errors.IsNotFound(err)).To(BeTrue())
			}).Should(Succeed())

			Consistently(func(g Gomega) {
				routeTable := getControllerRouteTable(vpcName)
				g.Expect(routeTable.Status.Routes).To(ContainElement(poolRoute))
			}, 2*time.Second, 200*time.Millisecond).Should(Succeed())
		})
	})

	It("reports EndpointPoolNotConfigured on AddressAllocated and Ready when the Vpc has no endpoint pool", func() {
		vpcName := createControllerVpc()
		namespace, serviceName := createVpcEndpointBackend("")
		endpointName := createVpcEndpoint(vpcName, namespace, serviceName)

		Eventually(func(g Gomega) {
			endpoint := getVpcEndpoint(endpointName)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionAddressAllocated, metav1.ConditionFalse, vpcEndpointReasonEndpointPoolNotConfigured)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionReady, metav1.ConditionFalse, vpcEndpointReasonEndpointPoolNotConfigured)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionServiceAccepted, metav1.ConditionTrue, vpcEndpointReasonAccepted)
			g.Expect(endpoint.Status.Address).To(BeEmpty())
		}).Should(Succeed())

		Consistently(func(g Gomega) {
			endpoint := getVpcEndpoint(endpointName)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionReady, metav1.ConditionFalse, vpcEndpointReasonEndpointPoolNotConfigured)
		}, 2*time.Second, 200*time.Millisecond).Should(Succeed())
	})

	It("reports VpcUnavailable on all three conditions when the Vpc does not exist", func() {
		namespace, serviceName := createVpcEndpointBackend("")
		endpointName := createVpcEndpoint(uniqueTestName("absent-vpc"), namespace, serviceName)

		Eventually(func(g Gomega) {
			endpoint := getVpcEndpoint(endpointName)
			for _, conditionType := range []string{
				juneauv1alpha1.VpcEndpointConditionAddressAllocated,
				juneauv1alpha1.VpcEndpointConditionServiceAccepted,
				juneauv1alpha1.VpcEndpointConditionReady,
			} {
				expectVpcEndpointCondition(g, endpoint, conditionType, metav1.ConditionFalse, vpcEndpointReasonVpcUnavailable)
			}
			g.Expect(endpoint.Status.Address).To(BeEmpty())
		}).Should(Succeed())
	})

	It("allocates an address but withholds ServiceAccepted while the backend Service is missing", func() {
		vpcName := createControllerVpcWithEndpointPool(uniqueEndpointPoolCIDR())
		endpointName := createVpcEndpoint(vpcName, "default", uniqueTestName("absent-service"))

		Eventually(func(g Gomega) {
			endpoint := getVpcEndpoint(endpointName)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionAddressAllocated, metav1.ConditionTrue, vpcEndpointReasonAllocated)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionServiceAccepted, metav1.ConditionFalse, vpcEndpointReasonServiceNotFound)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionReady, metav1.ConditionFalse, vpcEndpointReasonServiceNotAccepted)
		}).Should(Succeed())
	})

	It("withholds ServiceAccepted when the Vpc owning the backend Service has no Service routing", func() {
		vpcName := createControllerVpcWithEndpointPool(uniqueEndpointPoolCIDR())
		serviceVpcName := createControllerVpc()
		namespace, serviceName := createVpcEndpointBackend(serviceVpcName)
		endpointName := createVpcEndpoint(vpcName, namespace, serviceName)

		Eventually(func(g Gomega) {
			endpoint := getVpcEndpoint(endpointName)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionAddressAllocated, metav1.ConditionTrue, vpcEndpointReasonAllocated)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionServiceAccepted, metav1.ConditionFalse, vpcEndpointReasonServiceRoutingDisabled)
			expectVpcEndpointCondition(g, endpoint, juneauv1alpha1.VpcEndpointConditionReady, metav1.ConditionFalse, vpcEndpointReasonServiceNotAccepted)
		}).Should(Succeed())
	})
})

var endpointPoolCIDRCounter uint32

// uniqueEndpointPoolCIDR hands out a /24 outside the 10.0.0.0/8 space that
// uniqueSubnetCIDR and the test Service CIDR live in, so an endpoint pool
// never overlaps a Subnet of the same Vpc.
func uniqueEndpointPoolCIDR() string {
	n := atomic.AddUint32(&endpointPoolCIDRCounter, 1)
	return fmt.Sprintf("172.25.%d.0/24", n%256)
}

func cidrContains(cidr, address string) bool {
	_, network, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	ip := net.ParseIP(address)
	Expect(ip).NotTo(BeNil())
	return network.Contains(ip)
}

func countVpcEndpointRoutes(routeTable *juneauv1alpha1.RouteTable) int {
	count := 0
	for _, route := range routeTable.Status.Routes {
		if route.Via.Type == juneauv1alpha1.ViaVpcEndpoint {
			count++
		}
	}
	return count
}

// createVpcEndpointBackend creates a namespace holding a Service with one
// ready endpoint. When ownerVpc is set it is written to the annotation the
// controller reads to decide which Vpc owns the Service.
func createVpcEndpointBackend(ownerVpc string) (string, string) {
	namespace := uniqueTestName("backend")
	serviceName := uniqueTestName("service")

	Expect(k8sClient.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	})).To(Succeed())

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}},
		},
	}
	if ownerVpc != "" {
		service.Annotations = map[string]string{serviceVpcAnnotation: ownerVpc}
	}
	Expect(k8sClient.Create(context.Background(), service)).To(Succeed())

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

	return namespace, serviceName
}

func createVpcEndpoint(vpcName, namespace, serviceName string) string {
	name := uniqueTestName("endpoint")
	Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.VpcEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.VpcEndpointSpec{
			Vpc:     vpcName,
			Service: juneauv1alpha1.VpcEndpointServiceReference{Namespace: namespace, Name: serviceName},
		},
	})).To(Succeed())
	return name
}

func getVpcEndpoint(name string) *juneauv1alpha1.VpcEndpoint {
	var endpoint juneauv1alpha1.VpcEndpoint
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &endpoint)).To(Succeed())
	return &endpoint
}

func expectVpcEndpointCondition(g Gomega, endpoint *juneauv1alpha1.VpcEndpoint, conditionType string, status metav1.ConditionStatus, reason string) {
	condition := meta.FindStatusCondition(endpoint.Status.Conditions, conditionType)
	g.Expect(condition).NotTo(BeNil(), "condition %s is missing", conditionType)
	g.Expect(condition.Status).To(Equal(status), "condition %s has reason %s", conditionType, condition.Reason)
	g.Expect(condition.Reason).To(Equal(reason))
}
