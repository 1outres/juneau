package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// endpointBuilder is a tiny helper struct for shaping
// EndpointSlice.Endpoints entries. Tests stay readable when the
// per-endpoint defaulting (Ready/Serving/Terminating) is centralised
// here instead of repeated at every call site.
type endpointBuilder struct {
	Address     string
	Node        string
	Ready       *bool
	Serving     *bool
	Terminating *bool
}

func (b endpointBuilder) build() discoveryv1.Endpoint {
	ep := discoveryv1.Endpoint{
		Addresses:  []string{b.Address},
		Conditions: discoveryv1.EndpointConditions{Ready: b.Ready, Serving: b.Serving, Terminating: b.Terminating},
	}
	if b.Node != "" {
		ep.NodeName = ptr.To(b.Node)
	}
	return ep
}

func newEndpointSlice(svcName, sliceName string, ports []discoveryv1.EndpointPort, eps []endpointBuilder) *discoveryv1.EndpointSlice {
	endpoints := make([]discoveryv1.Endpoint, 0, len(eps))
	for _, b := range eps {
		endpoints = append(endpoints, b.build())
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sliceName,
			Namespace: "default",
			Labels: map[string]string{
				"kubernetes.io/service-name": svcName,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       ports,
		Endpoints:   endpoints,
	}
}

// ensureNamedPortService produces a Service whose targetPort is a
// string ("http"). This exercises the EndpointSlice resolution path:
// the SLB controller cannot know the integer port without consulting
// the slice's Ports field.
func newJuneauLBServiceNamedPort(name, externalNetwork string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Annotations: map[string]string{
				juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork: externalNetwork,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass:     ptr.To(juneauv1alpha1.LoadBalancerClass),
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			Ports: []corev1.ServicePort{
				{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromString("http")},
			},
			Selector: map[string]string{"app": "x"},
		},
	}
}

var _ = Describe("ServiceLoadBalancer endpoint aggregation (Phase 3)", func() {
	It("collects advertisingNodes from ready, serving, non-terminating endpoints", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.160.0.0/30"})
		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		Expect(k8sClient.Create(ctx, newEndpointSlice(svc.Name, fmt.Sprintf("%s-slice-a", svc.Name),
			[]discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(int32(8080))},
			},
			[]endpointBuilder{
				{Address: "10.99.0.1", Node: "node-a", Ready: ptr.To(true)},
				{Address: "10.99.0.2", Node: "node-c", Ready: ptr.To(true)},
				// Not ready → must not contribute to advertisingNodes.
				{Address: "10.99.0.3", Node: "node-b", Ready: ptr.To(false)},
				// Terminating → must not contribute either, even when
				// Ready is unset (defaults to true).
				{Address: "10.99.0.4", Node: "node-d", Terminating: ptr.To(true)},
			},
		))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			fresh := getServiceLoadBalancer(slb.Name)
			g.Expect(fresh.Status.AdvertisingNodes).To(Equal([]string{"node-a", "node-c"}))
			g.Expect(fresh.Status.BackendSummary.LocalReadyNodes).To(Equal(int32(2)))
			g.Expect(fresh.Status.BackendSummary.TotalReady).To(Equal(int32(2)))
			g.Expect(fresh.Status.Phase).To(Equal(juneauv1alpha1.ServiceLoadBalancerPhaseReady))
			available := meta.FindStatusCondition(fresh.Status.Conditions, juneauv1alpha1.ServiceLoadBalancerConditionAvailable)
			g.Expect(available).NotTo(BeNil())
			g.Expect(available.Status).To(Equal(metav1.ConditionTrue))
		}).Should(Succeed())
	})

	It("treats unset Ready as true and unset Serving as Ready", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.161.0.0/30"})
		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		Expect(k8sClient.Create(ctx, newEndpointSlice(svc.Name, fmt.Sprintf("%s-slice", svc.Name),
			[]discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(int32(8080))},
			},
			[]endpointBuilder{
				// No conditions at all → upstream defaults Ready=true,
				// Serving=Ready, Terminating=false → advertise.
				{Address: "10.99.1.1", Node: "node-a"},
			},
		))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			fresh := getServiceLoadBalancer(slb.Name)
			g.Expect(fresh.Status.AdvertisingNodes).To(Equal([]string{"node-a"}))
		}).Should(Succeed())
	})

	It("flips back to Degraded when all endpoints become terminating", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.162.0.0/30"})
		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		slice := newEndpointSlice(svc.Name, fmt.Sprintf("%s-slice", svc.Name),
			[]discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(int32(8080))},
			},
			[]endpointBuilder{
				{Address: "10.99.2.1", Node: "node-a", Ready: ptr.To(true)},
			},
		)
		Expect(k8sClient.Create(ctx, slice)).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			g.Expect(getServiceLoadBalancer(slb.Name).Status.Phase).To(Equal(juneauv1alpha1.ServiceLoadBalancerPhaseReady))
		}).Should(Succeed())

		// Mark the lone endpoint terminating.
		var current discoveryv1.EndpointSlice
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: slice.Name, Namespace: "default"}, &current)).To(Succeed())
		current.Endpoints[0].Conditions.Terminating = ptr.To(true)
		Expect(k8sClient.Update(ctx, &current)).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			fresh := getServiceLoadBalancer(slb.Name)
			g.Expect(fresh.Status.AdvertisingNodes).To(BeEmpty())
			g.Expect(fresh.Status.Phase).To(Equal(juneauv1alpha1.ServiceLoadBalancerPhaseDegraded))
		}).Should(Succeed())
	})

	It("resolves a string targetPort against the EndpointSlice ports", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.163.0.0/30"})
		svc := newJuneauLBServiceNamedPort(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		Expect(k8sClient.Create(ctx, newEndpointSlice(svc.Name, fmt.Sprintf("%s-slice", svc.Name),
			[]discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(int32(9090))},
			},
			[]endpointBuilder{
				{Address: "10.99.3.1", Node: "node-a", Ready: ptr.To(true)},
			},
		))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			fresh := getServiceLoadBalancer(slb.Name)
			g.Expect(fresh.Status.Ports).To(HaveLen(1))
			g.Expect(fresh.Status.Ports[0].TargetPort).To(Equal(int32(9090)))
		}).Should(Succeed())
	})

	It("ignores IPv6 EndpointSlices in the initial release", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.164.0.0/30"})
		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		// Only an IPv6 slice exists → no advertising nodes.
		Expect(k8sClient.Create(ctx, &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-v6", svc.Name),
				Namespace: "default",
				Labels:    map[string]string{"kubernetes.io/service-name": svc.Name},
			},
			AddressType: discoveryv1.AddressTypeIPv6,
			Ports: []discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(int32(8080))},
			},
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"2001:db8::1"}, NodeName: ptr.To("node-a"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
			},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			fresh := getServiceLoadBalancer(slb.Name)
			g.Expect(fresh.Status.AdvertisingNodes).To(BeEmpty())
			g.Expect(fresh.Status.Phase).To(Equal(juneauv1alpha1.ServiceLoadBalancerPhaseDegraded))
		}).Should(Succeed())
	})

	It("sorts advertisingNodes deterministically regardless of slice order", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.165.0.0/30"})
		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		// Two slices, intentionally reverse-sorted by node name.
		Expect(k8sClient.Create(ctx, newEndpointSlice(svc.Name, fmt.Sprintf("%s-slice-z", svc.Name),
			[]discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(int32(8080))},
			},
			[]endpointBuilder{
				{Address: "10.99.4.1", Node: "z-node", Ready: ptr.To(true)},
			},
		))).To(Succeed())
		Expect(k8sClient.Create(ctx, newEndpointSlice(svc.Name, fmt.Sprintf("%s-slice-a", svc.Name),
			[]discoveryv1.EndpointPort{
				{Name: ptr.To("http"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(int32(8080))},
			},
			[]endpointBuilder{
				{Address: "10.99.4.2", Node: "a-node", Ready: ptr.To(true)},
				{Address: "10.99.4.3", Node: "m-node", Ready: ptr.To(true)},
			},
		))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			fresh := getServiceLoadBalancer(slb.Name)
			g.Expect(fresh.Status.AdvertisingNodes).To(Equal([]string{"a-node", "m-node", "z-node"}))
		}).Should(Succeed())
	})
})
