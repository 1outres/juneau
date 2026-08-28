package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
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

	It("auto-generates a connected route for an L2Network that has a gateway", func() {
		vpcName := createControllerVpc()
		l2Name := uniqueTestName("l2net")
		l2 := newTestL2Network(l2Name, vpcName, "10.161.0.0/24")
		l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
		Expect(k8sClient.Create(context.Background(), l2)).To(Succeed())
		waitForReadyL2Network(l2Name)

		Eventually(func(g Gomega) {
			routeTable := getControllerRouteTable(vpcName)
			g.Expect(routeTable.Status.Routes).To(ContainElement(
				juneauv1alpha1.Route{
					Dst:       "10.161.0.0/24",
					L2Network: l2Name,
					Via:       juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
				},
			))
		}).Should(Succeed())
	})

	// Without a gateway the segment is closed: nothing in the Vpc can
	// reach it, and a route would only point at a port that is not
	// there.
	It("leaves an L2Network with no gateway out of the route table", func() {
		vpcName := createControllerVpc()
		l2Name := createTestL2Network(vpcName, "10.162.0.0/24")
		waitForReadyL2Network(l2Name)

		Consistently(func(g Gomega) {
			routeTable := getControllerRouteTable(vpcName)
			for _, route := range routeTable.Status.Routes {
				g.Expect(route.Dst).NotTo(Equal("10.162.0.0/24"))
			}
		}, "1s").Should(Succeed())
	})

	It("resolves endpoint routes into status", func() {
		vpcName := createControllerVpc()
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		endpointName := uniqueTestName("nwep")
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: endpointName, Namespace: "default"},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				Kind:       juneauv1alpha1.EndpointKindPod,
				NodeName:   "node-a",
				Subnet:     subnet.Name,
				Address:    "10.200.0.10/24",
				MACAddress: "02:42:ac:10:00:01",
				Attachment: &juneauv1alpha1.NetworkEndpointAttachment{
					Ifindex:        1,
					HostMACAddress: "02:42:ac:10:00:11",
				},
				PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
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
				Kind:       juneauv1alpha1.EndpointKindPod,
				NodeName:   "node-a",
				Subnet:     subnetB.Name,
				Address:    "10.201.0.10/24",
				MACAddress: "02:42:ac:10:00:02",
				Attachment: &juneauv1alpha1.NetworkEndpointAttachment{
					Ifindex:        1,
					HostMACAddress: "02:42:ac:10:00:12",
				},
				PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
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

	It("injects a Service route into the main RouteTable when Vpc Service routing becomes enabled", func() {
		vpcName := createControllerVpc()

		Eventually(func(g Gomega) {
			rt := getControllerRouteTable(vpcName)
			for _, route := range rt.Status.Routes {
				g.Expect(route.Via.Type).NotTo(Equal(juneauv1alpha1.ViaService))
			}
		}).Should(Succeed())

		var vpc juneauv1alpha1.Vpc
		Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
		vpc.Spec.Service = &juneauv1alpha1.VpcServiceSpec{Consume: true}
		Expect(k8sClient.Update(context.Background(), &vpc)).To(Succeed())

		Eventually(func(g Gomega) {
			rt := getControllerRouteTable(vpcName)
			g.Expect(rt.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
				Dst: testServiceCIDR.String(),
				Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
			}))
		}).Should(Succeed())
	})

	It("propagates Subnet CONNECTED routes to non-main RouteTables under the same VPC", func() {
		vpcName := createControllerVpc()

		extraRouteTable := uniqueTestName("routetable")
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: extraRouteTable},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName},
		})).To(Succeed())

		// Subnet created AFTER both RouteTables exist must surface as a
		// CONNECTED route in the non-main RouteTable too. Without the
		// fan-out fix the extra RT would only learn about the Subnet on
		// the next unrelated reconcile (e.g. a Vpc update).
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())

		expected := juneauv1alpha1.Route{
			Dst:    subnet.Spec.CIDR,
			Subnet: subnet.Name,
			Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaConnected},
		}

		Eventually(func(g Gomega) {
			extra := getControllerRouteTable(extraRouteTable)
			g.Expect(extra.Status.Routes).To(ContainElement(expected))
		}).Should(Succeed())
	})

	It("propagates Service routes to all RouteTables under the same VPC", func() {
		vpcName := createControllerVpc()
		subnet := createControllerSubnet(vpcName, uniqueTestName("subnet"), uniqueSubnetCIDR())
		_ = subnet

		extraRouteTable := uniqueTestName("routetable")
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: extraRouteTable},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName},
		})).To(Succeed())

		var vpc juneauv1alpha1.Vpc
		Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
		vpc.Spec.Service = &juneauv1alpha1.VpcServiceSpec{Consume: true}
		Expect(k8sClient.Update(context.Background(), &vpc)).To(Succeed())

		serviceRoute := juneauv1alpha1.Route{
			Dst: testServiceCIDR.String(),
			Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
		}

		Eventually(func(g Gomega) {
			main := getControllerRouteTable(vpcName)
			g.Expect(main.Status.Routes).To(ContainElement(serviceRoute))
			extra := getControllerRouteTable(extraRouteTable)
			g.Expect(extra.Status.Routes).To(ContainElement(serviceRoute))
		}).Should(Succeed())
	})

	Context("vpcPeering routes", func() {
		It("resolves a vpcPeering route to the peer Vpc Subnet", func() {
			vpcA := createControllerVpc()
			vpcB := createControllerVpc()
			peerSubnet := createControllerSubnet(vpcB, uniqueTestName("subnet"), uniqueSubnetCIDR())
			peeringName := createControllerVpcPeering(vpcA, vpcB)

			routeTableName := uniqueTestName("routetable")
			Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
				Spec: juneauv1alpha1.RouteTableSpec{
					Vpc: vpcA,
					Routes: []juneauv1alpha1.Route{{
						Dst: peerSubnet.Spec.CIDR,
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: peeringName},
					}},
				},
			})).To(Succeed())

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(routeTableName)
				ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
				g.Expect(ready).NotTo(BeNil())
				g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(routeTable.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
					Dst:    peerSubnet.Spec.CIDR,
					Subnet: peerSubnet.Name,
					Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: peeringName},
				}))
			}).Should(Succeed())
		})

		It("marks a RouteTable not ready when the VpcPeering does not exist", func() {
			vpcName := createControllerVpc()
			missing := uniqueTestName("peering")

			routeTableName := uniqueTestName("routetable")
			Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
				Spec: juneauv1alpha1.RouteTableSpec{
					Vpc: vpcName,
					Routes: []juneauv1alpha1.Route{{
						Dst: uniqueSubnetCIDR(),
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: missing},
					}},
				},
			})).To(Succeed())

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(routeTableName)
				ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
				g.Expect(ready).NotTo(BeNil())
				g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(ready.Message).To(ContainSubstring(fmt.Sprintf("VpcPeering %q not found", missing)))
			}).Should(Succeed())
		})

		It("marks a RouteTable not ready when its Vpc is not part of the VpcPeering", func() {
			vpcA := createControllerVpc()
			vpcB := createControllerVpc()
			vpcC := createControllerVpc()
			peeringName := createControllerVpcPeering(vpcA, vpcB)

			routeTableName := uniqueTestName("routetable")
			Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
				Spec: juneauv1alpha1.RouteTableSpec{
					Vpc: vpcC,
					Routes: []juneauv1alpha1.Route{{
						Dst: uniqueSubnetCIDR(),
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: peeringName},
					}},
				},
			})).To(Succeed())

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(routeTableName)
				ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
				g.Expect(ready).NotTo(BeNil())
				g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(ready.Message).To(ContainSubstring("is not part of VpcPeering"))
			}).Should(Succeed())
		})

		It("marks a RouteTable not ready when no peer Subnet matches dst exactly", func() {
			vpcA := createControllerVpc()
			vpcB := createControllerVpc()
			createControllerSubnet(vpcB, uniqueTestName("subnet"), "172.29.10.0/24")
			peeringName := createControllerVpcPeering(vpcA, vpcB)

			routeTableName := uniqueTestName("routetable")
			Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
				Spec: juneauv1alpha1.RouteTableSpec{
					Vpc: vpcA,
					Routes: []juneauv1alpha1.Route{{
						Dst: "172.29.10.0/25",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: peeringName},
					}},
				},
			})).To(Succeed())

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(routeTableName)
				ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
				g.Expect(ready).NotTo(BeNil())
				g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(ready.Message).To(ContainSubstring(fmt.Sprintf("no Subnet in Vpc %q has CIDR", vpcB)))
			}).Should(Succeed())
		})

		It("resolves a vpcPeering route once the peer Subnet is created", func() {
			vpcA := createControllerVpc()
			vpcB := createControllerVpc()
			peeringName := createControllerVpcPeering(vpcA, vpcB)
			peerCIDR := uniqueSubnetCIDR()

			routeTableName := uniqueTestName("routetable")
			Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
				Spec: juneauv1alpha1.RouteTableSpec{
					Vpc: vpcA,
					Routes: []juneauv1alpha1.Route{{
						Dst: peerCIDR,
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: peeringName},
					}},
				},
			})).To(Succeed())

			peerSubnet := createControllerSubnet(vpcB, uniqueTestName("subnet"), peerCIDR)

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(routeTableName)
				g.Expect(routeTable.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
					Dst:    peerCIDR,
					Subnet: peerSubnet.Name,
					Via:    juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcPeering, VpcPeering: peeringName},
				}))
			}).Should(Succeed())
		})
	})

	Context("transitGateway routes", func() {
		It("resolves a transitGateway route to the association route table", func() {
			tgw := createControllerTransitGateway()
			vpc := createControllerVpc()
			createControllerTransitGatewayAttachment(tgw, vpc, tgw, []string{tgw})

			routeTableName := uniqueTestName("routetable")
			Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
				Spec: juneauv1alpha1.RouteTableSpec{
					Vpc: vpc,
					Routes: []juneauv1alpha1.Route{{
						Dst: "172.23.0.0/16",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaTransitGateway, TransitGateway: tgw},
					}},
				},
			})).To(Succeed())

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(routeTableName)
				ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
				g.Expect(ready).NotTo(BeNil())
				g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(routeTable.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
					Dst:                      "172.23.0.0/16",
					TransitGatewayRouteTable: tgw,
					Via:                      juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaTransitGateway, TransitGateway: tgw},
				}))
			}).Should(Succeed())
		})

		It("marks a RouteTable not ready when the TransitGateway does not exist", func() {
			vpc := createControllerVpc()
			missing := uniqueTestName("tgw")

			routeTableName := uniqueTestName("routetable")
			Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
				Spec: juneauv1alpha1.RouteTableSpec{
					Vpc: vpc,
					Routes: []juneauv1alpha1.Route{{
						Dst: "172.24.0.0/16",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaTransitGateway, TransitGateway: missing},
					}},
				},
			})).To(Succeed())

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(routeTableName)
				ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
				g.Expect(ready).NotTo(BeNil())
				g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(ready.Message).To(ContainSubstring(fmt.Sprintf("TransitGateway %q not found", missing)))
			}).Should(Succeed())
		})

		It("marks a RouteTable not ready when its Vpc has no attachment", func() {
			tgw := createControllerTransitGateway()
			vpc := createControllerVpc()

			routeTableName := uniqueTestName("routetable")
			Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
				Spec: juneauv1alpha1.RouteTableSpec{
					Vpc: vpc,
					Routes: []juneauv1alpha1.Route{{
						Dst: "172.25.0.0/16",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaTransitGateway, TransitGateway: tgw},
					}},
				},
			})).To(Succeed())

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(routeTableName)
				ready := meta.FindStatusCondition(routeTable.Status.Conditions, juneauv1alpha1.RouteTableStatusReady)
				g.Expect(ready).NotTo(BeNil())
				g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(ready.Message).To(ContainSubstring(fmt.Sprintf("Vpc %q has no attachment to TransitGateway %q", vpc, tgw)))
			}).Should(Succeed())
		})

		It("resolves a transitGateway route once the attachment is created", func() {
			tgw := createControllerTransitGateway()
			vpc := createControllerVpc()

			routeTableName := uniqueTestName("routetable")
			Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: routeTableName},
				Spec: juneauv1alpha1.RouteTableSpec{
					Vpc: vpc,
					Routes: []juneauv1alpha1.Route{{
						Dst: "172.26.0.0/16",
						Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaTransitGateway, TransitGateway: tgw},
					}},
				},
			})).To(Succeed())

			createControllerTransitGatewayAttachment(tgw, vpc, tgw, nil)

			Eventually(func(g Gomega) {
				routeTable := getControllerRouteTable(routeTableName)
				g.Expect(routeTable.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
					Dst:                      "172.26.0.0/16",
					TransitGatewayRouteTable: tgw,
					Via:                      juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaTransitGateway, TransitGateway: tgw},
				}))
			}).Should(Succeed())
		})
	})

	Context("Service.spec.externalIPs injection", func() {
		It("injects /32 SERVICE routes for each owner-Vpc Service externalIP", func() {
			vpcName := createControllerVpc()
			enableVpcServiceConsume(vpcName)

			svcName := uniqueTestName("svc")
			extA := uniqueExternalIPv4()
			extB := uniqueExternalIPv4()
			Expect(k8sClient.Create(context.Background(), buildExternalIPService(svcName, "default", vpcName, []string{extA, extB}))).To(Succeed())

			Eventually(func(g Gomega) {
				rt := getControllerRouteTable(vpcName)
				g.Expect(rt.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
					Dst: extA + "/32",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
				}))
				g.Expect(rt.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
					Dst: extB + "/32",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
				}))
			}).Should(Succeed())
		})

		It("removes /32 SERVICE routes when an externalIP entry is dropped", func() {
			vpcName := createControllerVpc()
			enableVpcServiceConsume(vpcName)

			svcName := uniqueTestName("svc")
			extA := uniqueExternalIPv4()
			extB := uniqueExternalIPv4()
			svc := buildExternalIPService(svcName, "default", vpcName, []string{extA, extB})
			Expect(k8sClient.Create(context.Background(), svc)).To(Succeed())

			Eventually(func(g Gomega) {
				rt := getControllerRouteTable(vpcName)
				g.Expect(rt.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
					Dst: extB + "/32",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
				}))
			}).Should(Succeed())

			var current corev1.Service
			Expect(k8sClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: svcName}, &current)).To(Succeed())
			current.Spec.ExternalIPs = []string{extA}
			Expect(k8sClient.Update(context.Background(), &current)).To(Succeed())

			Eventually(func(g Gomega) {
				rt := getControllerRouteTable(vpcName)
				g.Expect(rt.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
					Dst: extA + "/32",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
				}))
				g.Expect(rt.Status.Routes).NotTo(ContainElement(juneauv1alpha1.Route{
					Dst: extB + "/32",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
				}))
			}).Should(Succeed())
		})

		It("does not inject externalIPs of Services owned by another Vpc", func() {
			ownerVpc := createControllerVpc()
			otherVpc := createControllerVpc()
			enableVpcServiceConsume(ownerVpc)
			enableVpcServiceConsume(otherVpc)

			extOwner := uniqueExternalIPv4()
			extOther := uniqueExternalIPv4()
			Expect(k8sClient.Create(context.Background(), buildExternalIPService(uniqueTestName("svc"), "default", ownerVpc, []string{extOwner}))).To(Succeed())
			Expect(k8sClient.Create(context.Background(), buildExternalIPService(uniqueTestName("svc"), "default", otherVpc, []string{extOther}))).To(Succeed())

			Eventually(func(g Gomega) {
				rt := getControllerRouteTable(ownerVpc)
				g.Expect(rt.Status.Routes).To(ContainElement(juneauv1alpha1.Route{
					Dst: extOwner + "/32",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
				}))
				g.Expect(rt.Status.Routes).NotTo(ContainElement(juneauv1alpha1.Route{
					Dst: extOther + "/32",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
				}))
			}).Should(Succeed())
		})

		It("ignores ExternalName Services and IPv6 / duplicate externalIPs", func() {
			vpcName := createControllerVpc()
			enableVpcServiceConsume(vpcName)

			extDup := uniqueExternalIPv4()

			// ExternalName Service must not contribute a /32 even if it
			// somehow carries spec.externalIPs (the field is silently
			// ignored by upstream for that type).
			extName := uniqueTestName("svc-ext")
			Expect(k8sClient.Create(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "default",
					Name:        extName,
					Annotations: map[string]string{serviceVpcAnnotation: vpcName},
				},
				Spec: corev1.ServiceSpec{
					Type:         corev1.ServiceTypeExternalName,
					ExternalName: "example.com",
				},
			})).To(Succeed())

			// IPv6 entries are dropped silently by the controller (the
			// daemon-side reconciler emits a more visible warning);
			// duplicates collapse to a single /32 route.
			Expect(k8sClient.Create(context.Background(), buildExternalIPService(uniqueTestName("svc"), "default", vpcName,
				[]string{"2001:db8::1", extDup, extDup}))).To(Succeed())

			Eventually(func(g Gomega) {
				rt := getControllerRouteTable(vpcName)
				count := 0
				for _, route := range rt.Status.Routes {
					if route.Via.Type != juneauv1alpha1.ViaService {
						continue
					}
					if route.Dst == testServiceCIDR.String() {
						continue
					}
					count++
					g.Expect(route.Dst).To(Equal(extDup + "/32"))
				}
				g.Expect(count).To(Equal(1))
			}).Should(Succeed())
		})
	})
})

func enableVpcServiceConsume(vpcName string) {
	var vpc juneauv1alpha1.Vpc
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
	vpc.Spec.Service = &juneauv1alpha1.VpcServiceSpec{Consume: true}
	Expect(k8sClient.Update(context.Background(), &vpc)).To(Succeed())
}

func buildExternalIPService(name, namespace, vpcName string, externalIPs []string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: map[string]string{serviceVpcAnnotation: vpcName},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{Port: 80, Protocol: corev1.ProtocolTCP},
			},
			Selector:    map[string]string{"app": name},
			ExternalIPs: externalIPs,
		},
	}
}

func createControllerVpc() string {
	return createControllerVpcWithEndpointPool()
}

// createControllerVpcWithEndpointPool creates a ready Vpc whose VpcEndpoint
// VIPs come from the given pool CIDRs. Passing no CIDR leaves the Vpc without
// an endpoint pool.
func createControllerVpcWithEndpointPool(cidrs ...string) string {
	name := uniqueTestName("vpc")
	vpc := &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if len(cidrs) > 0 {
		vpc.Spec.EndpointPool = &juneauv1alpha1.VpcEndpointPoolSpec{CIDRs: cidrs}
	}
	Expect(k8sClient.Create(context.Background(), vpc)).To(Succeed())

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
