package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("RouteTable controller", func() {
	It("auto-generates connected routes from VPC subnets", func() {
		vpcName := createControllerVpc()
		subnetA := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		subnetB := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())

		Eventually(func(g Gomega) {
			routeTable := getControllerRouteTable(vpcName)
			g.Expect(routeTable.Status.Routes).To(ContainElements(
				juneauv1alpha1.Route{
					Dst:    subnetA.Spec.CIDR,
					Subnet: subnetA.Name,
					Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
				},
				juneauv1alpha1.Route{
					Dst:    subnetB.Spec.CIDR,
					Subnet: subnetB.Name,
					Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
				},
			))
		}).Should(Succeed())
	})

	It("resolves endpoint routes into status", func() {
		vpcName := createControllerVpc()
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		endpointName := uniqueTestName("nwep")
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: endpointName, Namespace: "default"},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				NodeName:       "node-a",
				Subnet:         subnet.Name,
				Address:        "10.200.0.10",
				MACAddress:     "02:42:ac:10:00:01",
				HostMACAddress: "02:42:ac:10:00:11",
				Ifindex:        1,
				PodRef: juneauv1alpha1.NetworkEndpointPodReference{
					UID:       fmt.Sprintf("uid-%s", endpointName),
					Name:      "pod-a",
					Interface: "net1",
				},
			},
		})).To(Succeed())

		routeTableName := uniqueTestName("routetable")
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{{
					Dst: "0.0.0.0/0",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint, Endpoint: endpointName},
				}},
			},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			routeTable := getControllerRouteTable(routeTableName)
			ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(ready.ObservedGeneration).To(Equal(routeTable.Generation))
			g.Expect(routeTable.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
				Dst:    subnet.Spec.CIDR,
				Subnet: subnet.Name,
				Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
			}))
			g.Expect(routeTable.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
				Dst:    "0.0.0.0/0",
				Subnet: subnet.Name,
				Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint, Endpoint: endpointName},
			}))
		}).Should(Succeed())
	})

	It("marks a RouteTable not ready when an endpoint is outside the VPC", func() {
		vpcA := createControllerVpc()
		vpcB := createControllerVpc()
		subnetB := createControllerSubnet(vpcB, uniqueTestName("subnet"), uniqueSubnetCIDR())
		endpointName := uniqueTestName("nwep")
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: endpointName, Namespace: "default"},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				NodeName:       "node-a",
				Subnet:         subnetB.Name,
				Address:        "10.201.0.10",
				MACAddress:     "02:42:ac:10:00:02",
				HostMACAddress: "02:42:ac:10:00:12",
				Ifindex:        1,
				PodRef: juneauv1alpha1.NetworkEndpointPodReference{
					UID:       fmt.Sprintf("uid-%s", endpointName),
					Name:      "pod-b",
					Interface: "net1",
				},
			},
		})).To(Succeed())

		routeTableName := uniqueTestName("routetable")
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcA,
				Routes: []juneauv1alpha1.Route{{
					Dst: "0.0.0.0/0",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaEndpoint, Endpoint: endpointName},
				}},
			},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			routeTable := getControllerRouteTable(routeTableName)
			ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.ObservedGeneration).To(Equal(routeTable.Generation))
			g.Expect(ready.Message).To(ContainSubstring("outside VPC"))
		}).Should(Succeed())
	})

	It("allocates a tableID", func() {
		vpcName := createControllerVpc()
		routeTableName := uniqueTestName("routetable")
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			routeTable := getControllerRouteTable(routeTableName)
			g.Expect(routeTable.Status.TableID).NotTo(BeZero())
		}).Should(Succeed())
	})
})

func createControllerVpc() string {
	name := uniqueTestName("vpc")
	Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})).To(Succeed())

	Eventually(func(g Gomega) {
		var vpc juneauv1alpha1.Vpc
		g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &vpc)).To(Succeed())
		ready := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		g.Expect(ready.ObservedGeneration).To(Equal(vpc.Generation))
	}).Should(Succeed())

	return name
}

func createControllerSubnet(vpcName, subnetName, cidr string) *juneauv1alpha1.Subnet {
	subnet := &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: subnetName},
		Spec: juneauv1alpha1.SubnetSpec{
			Vpc:  vpcName,
			CIDR: cidr,
		},
	}
	Expect(k8sClient.Create(context.Background(), subnet)).To(Succeed())

	Eventually(func(g Gomega) {
		var current juneauv1alpha1.Subnet
		g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: subnetName}, &current)).To(Succeed())
		ready := meta.FindStatusCondition(current.Status.Conditions, juneauv1alpha1.SubnetStatusReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		g.Expect(ready.ObservedGeneration).To(Equal(current.Generation))
	}).Should(Succeed())

	return subnet
}

func getControllerRouteTable(name string) *juneauv1alpha1.RouteTable {
	var routeTable juneauv1alpha1.RouteTable
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &routeTable)).To(Succeed())
	return &routeTable
}
