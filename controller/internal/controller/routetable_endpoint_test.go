package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("RouteTable endpoint and blackhole routes", func() {
	ctx := context.Background()
	const namespace = "default"

	It("resolves an endpoint route to the NetworkEndpoint of the NIC that holds the workload's address", func() {
		vpc := createControllerVpc()
		subnet := createControllerSubnet(vpc, uniqueTestName("subnet"), uniqueSubnetCIDR())
		identity := uniqueTestName("router")
		nic := createWorkloadNIC(namespace, identity, uniqueTestName("router-a"), subnet.Name)
		endpoint := createNICEndpoint(nic, "02:42:ac:10:00:01")

		route := endpointRoute("10.250.0.0/24", namespace, identity)
		routeTable := createEndpointRouteTable(vpc, route)

		Eventually(func(g Gomega) {
			rt := getControllerRouteTable(routeTable)
			g.Expect(readyStatus(rt)).To(Equal(metav1.ConditionTrue))
			g.Expect(statusRoute(rt, route.Dst)).To(Equal(&juneauv1alpha1.ResolvedRoute{
				Dst:             route.Dst,
				Via:             route.Via,
				Subnet:          subnet.Name,
				NetworkEndpoint: &juneauv1alpha1.ResolvedNetworkEndpointReference{Namespace: namespace, Name: endpoint.Name},
				State:           juneauv1alpha1.RouteStateActive,
			}))
		}).Should(Succeed())
	})

	It("moves the route to the new Pod of the workload and blackholes it in between", func() {
		vpc := createControllerVpc()
		subnet := createControllerSubnet(vpc, uniqueTestName("subnet"), uniqueSubnetCIDR())
		identity := uniqueTestName("router")
		first := createWorkloadNIC(namespace, identity, uniqueTestName("router-a"), subnet.Name)
		firstEndpoint := createNICEndpoint(first, "02:42:ac:10:00:02")

		route := endpointRoute("10.251.0.0/24", namespace, identity)
		routeTable := createEndpointRouteTable(vpc, route)
		Eventually(func(g Gomega) {
			resolved := statusRoute(getControllerRouteTable(routeTable), route.Dst)
			g.Expect(resolved).NotTo(BeNil())
			g.Expect(resolved.NetworkEndpoint).To(Equal(&juneauv1alpha1.ResolvedNetworkEndpointReference{Namespace: namespace, Name: firstEndpoint.Name}))
		}).Should(Succeed())

		By("removing the first Pod")
		Expect(k8sClient.Delete(ctx, firstEndpoint)).To(Succeed())
		releaseWorkloadNIC(first)
		Eventually(func(g Gomega) {
			rt := getControllerRouteTable(routeTable)
			g.Expect(readyStatus(rt)).To(Equal(metav1.ConditionTrue))
			resolved := statusRoute(rt, route.Dst)
			g.Expect(resolved).NotTo(BeNil())
			g.Expect(resolved.State).To(Equal(juneauv1alpha1.RouteStateBlackhole))
			g.Expect(resolved.NetworkEndpoint).To(BeNil())
			g.Expect(resolved.Message).To(ContainSubstring(identity))
		}).Should(Succeed())

		By("starting the next Pod of the workload")
		second := createWorkloadNIC(namespace, identity, uniqueTestName("router-b"), subnet.Name)
		Expect(second.Status.Address).To(Equal(first.Status.Address))
		secondEndpoint := createNICEndpoint(second, "02:42:ac:10:00:03")
		Eventually(func(g Gomega) {
			resolved := statusRoute(getControllerRouteTable(routeTable), route.Dst)
			g.Expect(resolved).NotTo(BeNil())
			g.Expect(resolved.State).To(Equal(juneauv1alpha1.RouteStateActive))
			g.Expect(resolved.Message).To(BeEmpty())
			g.Expect(resolved.NetworkEndpoint).To(Equal(&juneauv1alpha1.ResolvedNetworkEndpointReference{Namespace: namespace, Name: secondEndpoint.Name}))
		}).Should(Succeed())
	})

	It("keeps the route on the NIC that holds the address while another NIC shares the identity", func() {
		vpc := createControllerVpc()
		subnet := createControllerSubnet(vpc, uniqueTestName("subnet"), uniqueSubnetCIDR())
		identity := uniqueTestName("router")
		holder := createWorkloadNIC(namespace, identity, uniqueTestName("router-src"), subnet.Name)
		holderEndpoint := createNICEndpoint(holder, "02:42:ac:10:00:04")

		route := endpointRoute("10.252.0.0/24", namespace, identity)
		routeTable := createEndpointRouteTable(vpc, route)

		target := createWorkloadNIC(namespace, identity, uniqueTestName("router-dst"), subnet.Name)
		Expect(target.Status.Address).NotTo(Equal(holder.Status.Address))
		createNICEndpoint(target, "02:42:ac:10:00:05")

		want := &juneauv1alpha1.ResolvedNetworkEndpointReference{Namespace: namespace, Name: holderEndpoint.Name}
		Eventually(func(g Gomega) {
			resolved := statusRoute(getControllerRouteTable(routeTable), route.Dst)
			g.Expect(resolved).NotTo(BeNil())
			g.Expect(resolved.NetworkEndpoint).To(Equal(want))
		}).Should(Succeed())
		Consistently(func(g Gomega) {
			resolved := statusRoute(getControllerRouteTable(routeTable), route.Dst)
			g.Expect(resolved).NotTo(BeNil())
			g.Expect(resolved.NetworkEndpoint).To(Equal(want))
		}, "1s").Should(Succeed())
	})

	It("blackholes only the endpoint route while no NIC holds the identity", func() {
		vpc := createControllerVpc()
		identity := uniqueTestName("absent")
		route := endpointRoute("10.253.0.0/24", namespace, identity)
		internet := juneauv1alpha1.Route{
			Dst: "0.0.0.0/0",
			Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaInternetGateway},
		}
		routeTable := createEndpointRouteTable(vpc, route, internet)

		Eventually(func(g Gomega) {
			rt := getControllerRouteTable(routeTable)
			g.Expect(readyStatus(rt)).To(Equal(metav1.ConditionTrue))
			resolved := statusRoute(rt, route.Dst)
			g.Expect(resolved).NotTo(BeNil())
			g.Expect(resolved.State).To(Equal(juneauv1alpha1.RouteStateBlackhole))
			g.Expect(resolved.Via).To(Equal(route.Via))
			g.Expect(resolved.Message).To(ContainSubstring(identity))
			g.Expect(statusRoute(rt, internet.Dst)).To(Equal(&juneauv1alpha1.ResolvedRoute{
				Dst:   internet.Dst,
				Via:   internet.Via,
				State: juneauv1alpha1.RouteStateActive,
			}))
		}).Should(Succeed())
	})

	It("blackholes an endpoint route while the holder has no NetworkEndpoint, and resolves it once the endpoint appears", func() {
		vpc := createControllerVpc()
		subnet := createControllerSubnet(vpc, uniqueTestName("subnet"), uniqueSubnetCIDR())
		identity := uniqueTestName("router")
		nic := createWorkloadNIC(namespace, identity, uniqueTestName("router-a"), subnet.Name)

		route := endpointRoute("10.254.0.0/24", namespace, identity)
		routeTable := createEndpointRouteTable(vpc, route)
		Eventually(func(g Gomega) {
			resolved := statusRoute(getControllerRouteTable(routeTable), route.Dst)
			g.Expect(resolved).NotTo(BeNil())
			g.Expect(resolved.State).To(Equal(juneauv1alpha1.RouteStateBlackhole))
			g.Expect(resolved.Message).To(ContainSubstring(nic.Name))
		}).Should(Succeed())

		endpoint := createNICEndpoint(nic, "02:42:ac:10:00:06")
		Eventually(func(g Gomega) {
			resolved := statusRoute(getControllerRouteTable(routeTable), route.Dst)
			g.Expect(resolved).NotTo(BeNil())
			g.Expect(resolved.State).To(Equal(juneauv1alpha1.RouteStateActive))
			g.Expect(resolved.NetworkEndpoint).To(Equal(&juneauv1alpha1.ResolvedNetworkEndpointReference{Namespace: namespace, Name: endpoint.Name}))
		}).Should(Succeed())
	})

	It("blackholes an endpoint route whose endpoint is outside the Vpc of the RouteTable", func() {
		vpcA := createControllerVpc()
		vpcB := createControllerVpc()
		subnetB := createControllerSubnet(vpcB, uniqueTestName("subnet"), uniqueSubnetCIDR())
		identity := uniqueTestName("router")
		nic := createWorkloadNIC(namespace, identity, uniqueTestName("router-a"), subnetB.Name)
		createNICEndpoint(nic, "02:42:ac:10:00:07")

		route := endpointRoute("10.249.0.0/24", namespace, identity)
		routeTable := createEndpointRouteTable(vpcA, route)
		Eventually(func(g Gomega) {
			rt := getControllerRouteTable(routeTable)
			g.Expect(readyStatus(rt)).To(Equal(metav1.ConditionTrue))
			resolved := statusRoute(rt, route.Dst)
			g.Expect(resolved).NotTo(BeNil())
			g.Expect(resolved.State).To(Equal(juneauv1alpha1.RouteStateBlackhole))
			g.Expect(resolved.Message).To(ContainSubstring(vpcA))
		}).Should(Succeed())
	})

	It("drops traffic for a blackhole route", func() {
		vpc := createControllerVpc()
		route := juneauv1alpha1.Route{
			Dst: "10.248.0.0/24",
			Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaBlackhole},
		}
		routeTable := createEndpointRouteTable(vpc, route)
		Eventually(func(g Gomega) {
			rt := getControllerRouteTable(routeTable)
			g.Expect(readyStatus(rt)).To(Equal(metav1.ConditionTrue))
			g.Expect(statusRoute(rt, route.Dst)).To(Equal(&juneauv1alpha1.ResolvedRoute{
				Dst:   route.Dst,
				Via:   route.Via,
				State: juneauv1alpha1.RouteStateBlackhole,
			}))
		}).Should(Succeed())
	})
})

func endpointRoute(dst, namespace, identity string) juneauv1alpha1.Route {
	return juneauv1alpha1.Route{
		Dst: dst,
		Via: juneauv1alpha1.RouteVia{
			Type: juneauv1alpha1.ViaEndpoint,
			Endpoint: &juneauv1alpha1.RouteEndpointReference{
				Namespace:          namespace,
				AllocationIdentity: identity,
				Interface:          juneauv1alpha1.PodPrimaryInterfaceName,
			},
		},
	}
}

func createEndpointRouteTable(vpc string, routes ...juneauv1alpha1.Route) string {
	GinkgoHelper()
	name := uniqueTestName("routetable")
	Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpc, Routes: routes},
	})).To(Succeed())
	return name
}

// createWorkloadNIC builds the eth0 NetworkInterface the Pod controller
// writes for one Pod of a workload, and allocates its address.
func createWorkloadNIC(namespace, identity, podName, subnet string) *juneauv1alpha1.NetworkInterface {
	GinkgoHelper()
	ctx := context.Background()
	nic := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: podName + "." + juneauv1alpha1.PodPrimaryInterfaceName, Namespace: namespace},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			PodRef: juneauv1alpha1.NetworkInterfacePodReference{
				UID:       "uid-" + podName,
				Name:      podName,
				Interface: juneauv1alpha1.PodPrimaryInterfaceName,
			},
			NodeName:           "node-a",
			Subnet:             subnet,
			AllocationIdentity: identity,
		},
	}
	Expect(k8sClient.Create(ctx, nic)).To(Succeed())
	DeferCleanup(func() { cleanupNetworkInterface(ctx, nic) })
	allocateNetworkInterfaceForPod(ctx, nic)
	return nic
}

// createNICEndpoint writes the NetworkEndpoint the CNI writes once the Pod
// of a NIC runs.
func createNICEndpoint(nic *juneauv1alpha1.NetworkInterface, mac string) *juneauv1alpha1.NetworkEndpoint {
	GinkgoHelper()
	ctx := context.Background()
	endpoint := &juneauv1alpha1.NetworkEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: nic.Name, Namespace: nic.Namespace},
		Spec: juneauv1alpha1.NetworkEndpointSpec{
			Kind:       juneauv1alpha1.EndpointKindPod,
			NodeName:   nic.Spec.NodeName,
			Subnet:     nic.Spec.Subnet,
			Address:    nic.Status.Address,
			MACAddress: mac,
			PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
				Name:      nic.Spec.PodRef.Name,
				Interface: nic.Spec.PodRef.Interface,
				UID:       nic.Spec.PodRef.UID,
			},
		},
	}
	Expect(k8sClient.Create(ctx, endpoint)).To(Succeed())
	DeferCleanup(func() { _ = k8sClient.Delete(ctx, endpoint) })
	return endpoint
}

// releaseWorkloadNIC removes a NetworkInterface the way a finished Pod
// does: the AllocationClaim goes, and the AllocationLease stays behind to
// keep the address for the next Pod of the workload.
func releaseWorkloadNIC(nic *juneauv1alpha1.NetworkInterface) {
	GinkgoHelper()
	ctx := context.Background()
	r := &NetworkInterfaceReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	Expect(k8sClient.Delete(ctx, nic)).To(Succeed())
	Eventually(func(g Gomega) {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nic.Name, Namespace: nic.Namespace}})
		g.Expect(err).NotTo(HaveOccurred())
		err = k8sClient.Get(ctx, client.ObjectKeyFromObject(nic), &juneauv1alpha1.NetworkInterface{})
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
	}).Should(Succeed())
}

func statusRoute(rt *juneauv1alpha1.RouteTable, dst string) *juneauv1alpha1.ResolvedRoute {
	for i := range rt.Status.Routes {
		if rt.Status.Routes[i].Dst == dst {
			return &rt.Status.Routes[i]
		}
	}
	return nil
}

func readyStatus(rt *juneauv1alpha1.RouteTable) metav1.ConditionStatus {
	ready := meta.FindStatusCondition(rt.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
	if ready == nil || ready.ObservedGeneration != rt.Generation {
		return metav1.ConditionUnknown
	}
	return ready.Status
}
