package v1alpha1

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Vpc/Subnet webhooks", func() {
	It("rejects deleting the default VPC", func() {
		var vpc juneauv1alpha1.Vpc
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: "default"}, &vpc)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &vpc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("default Vpc cannot be deleted"))
	})

	It("rejects deleting the default Subnet", func() {
		var subnet juneauv1alpha1.Subnet
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: "default"}, &subnet)).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &subnet)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("default Subnet cannot be deleted"))
	})

	It("rejects deleting a Vpc that still has Subnets", func() {
		vpcName := createWebhookVpc()
		subnetName := webhookUniqueTestName("subnet")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnetName},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: webhookUniqueSubnetCIDR(),
			},
		})).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Subnet"))
		Expect(err.Error()).To(ContainSubstring(subnetName))

		// Once the Subnet is gone the Vpc becomes deletable again.
		Expect(webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnetName},
		})).To(Succeed())
		Expect(webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		})).To(Succeed())
	})

	It("rejects creating a non-default Subnet in the default VPC", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  "default",
				CIDR: webhookUniqueSubnetCIDR(),
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("only the default Subnet can reference the default Vpc"))
	})

	It("rejects creating a Subnet referencing a nonexistent VPC", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  webhookUniqueTestName("missing-vpc"),
				CIDR: webhookUniqueSubnetCIDR(),
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("rejects creating a Subnet with malformed CIDR", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.0.0.0",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be a valid IPv4 CIDR"))
	})

	It("rejects creating a too-large Subnet", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.0.0.0/15",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("CIDR prefix length must be between /16 and /28"))
	})

	It("rejects creating a too-small Subnet", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.0.0.0/29",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("CIDR prefix length must be between /16 and /28"))
	})

	It("rejects overlapping subnets in the same VPC", func() {
		vpcName := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.90.0.0/24",
			},
		})).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.90.0.128/25",
			},
		})

		// This intentionally captures currently missing overlap validation.
		Expect(err).To(HaveOccurred(), "missing overlap validation currently allows overlapping subnets in the same VPC")
	})

	It("rejects creating a Subnet that references a nonexistent RouteTable", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:        vpcName,
				CIDR:       webhookUniqueSubnetCIDR(),
				RouteTable: webhookUniqueTestName("missing-rt"),
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced RouteTable does not exist"))
	})

	It("rejects creating a Subnet that references a RouteTable in a different VPC", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()

		altRT := webhookUniqueTestName("rt")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: altRT},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcB},
		})).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:        vpcA,
				CIDR:       webhookUniqueSubnetCIDR(),
				RouteTable: altRT,
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("RouteTable belongs to a different Vpc"))
	})

	It("accepts creating a Subnet that references a RouteTable in the same VPC", func() {
		vpcName := createWebhookVpc()

		altRT := webhookUniqueTestName("rt")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: altRT},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName},
		})).To(Succeed())

		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:        vpcName,
				CIDR:       webhookUniqueSubnetCIDR(),
				RouteTable: altRT,
			},
		})).To(Succeed())
	})

	It("rejects setting spec.routeTable on the default Subnet", func() {
		altRT := webhookUniqueTestName("rt")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: altRT},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: "default"},
		})).To(Succeed())

		var subnet juneauv1alpha1.Subnet
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: "default"}, &subnet)).To(Succeed())
		subnet.Spec.RouteTable = altRT

		err := webhookK8sClient.Update(context.Background(), &subnet)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("default Subnet must use the Vpc's main RouteTable"))
	})
})

var _ = Describe("Service-related Vpc/Subnet webhooks", func() {
	It("rejects enabling Service when an existing Subnet overlaps the Service CIDR", func() {
		vpcName := createWebhookVpc()
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.96.0.0/24",
			},
		})).To(Succeed())

		var vpc juneauv1alpha1.Vpc
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
		vpc.Spec.Service = &juneauv1alpha1.VpcServiceSpec{Consume: true}
		err := webhookK8sClient.Update(context.Background(), &vpc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlaps with Service CIDR"))
	})

	It("rejects creating a Subnet that overlaps the Service CIDR when the VPC has Service routing enabled", func() {
		vpcName := createWebhookServiceEnabledVpc()

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.96.0.0/24",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlaps with Service CIDR"))
	})

	// The provider NAT-source-Subnet reference is intentionally not
	// validated at admission: the Vpc and its Subnet are commonly
	// applied together (`kubectl apply -f -`), and admission-time
	// existence checks would deadlock since each side references the
	// other. Existence/ownership is enforced by the Vpc controller
	// instead, surfaced via the Vpc's Ready condition.
	It("admits a provider Vpc whose natSourceSubnet does not exist yet", func() {
		vpcName := webhookUniqueTestName("vpc")
		subnetName := webhookUniqueTestName("subnet")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
			Spec: juneauv1alpha1.VpcSpec{Service: &juneauv1alpha1.VpcServiceSpec{
				Provider: &juneauv1alpha1.VpcServiceProviderSpec{NATSourceSubnet: subnetName},
			}},
		})).To(Succeed())
	})

	It("admits a provider Vpc whose natSourceSubnet belongs to another Vpc", func() {
		otherVpc := createWebhookVpc()
		foreignSubnet := webhookUniqueTestName("subnet")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: foreignSubnet},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  otherVpc,
				CIDR: webhookUniqueSubnetCIDR(),
			},
		})).To(Succeed())

		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("vpc")},
			Spec: juneauv1alpha1.VpcSpec{Service: &juneauv1alpha1.VpcServiceSpec{
				Provider: &juneauv1alpha1.VpcServiceProviderSpec{NATSourceSubnet: foreignSubnet},
			}},
		})).To(Succeed())
	})
})

var _ = Describe("RouteTable webhook", func() {
	It("rejects routes with via.type=service from spec", func() {
		vpcName := createWebhookVpc()
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.96.0.0/12",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaService},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("managed by the controller"))
	})

	It("rejects routes with via.type=vpcEndpoint from spec", func() {
		vpcName := createWebhookVpc()
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routetable")},
			Spec: juneauv1alpha1.RouteTableSpec{
				Vpc: vpcName,
				Routes: []juneauv1alpha1.Route{{
					Dst: "10.240.0.0/24",
					Via: juneauv1alpha1.RouteVia{Type: juneauv1alpha1.ViaVpcEndpoint},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("configure spec.endpointPool on the Vpc instead"))
	})

	It("rejects deleting a RouteTable that a Subnet still references", func() {
		vpcName := createWebhookVpc()

		altRT := webhookUniqueTestName("rt")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: altRT},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName},
		})).To(Succeed())

		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:        vpcName,
				CIDR:       webhookUniqueSubnetCIDR(),
				RouteTable: altRT,
			},
		})).To(Succeed())

		var rt juneauv1alpha1.RouteTable
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: altRT}, &rt)).To(Succeed())
		err := webhookK8sClient.Delete(context.Background(), &rt)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Subnet"))
		Expect(err.Error()).To(ContainSubstring("references"))
	})

	It("rejects deleting the main RouteTable of an existing Vpc", func() {
		vpcName := createWebhookVpc()

		// In production VpcReconciler creates a RouteTable named after
		// the Vpc; controllers do not run in this webhook test suite
		// so we mint that RT directly to drive the validation path.
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName},
		})).To(Succeed())

		var rt juneauv1alpha1.RouteTable
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &rt)).To(Succeed())
		err := webhookK8sClient.Delete(context.Background(), &rt)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("main RouteTable"))
	})

	It("allows deleting the main RouteTable once the owning Vpc is being deleted", func() {
		name := webhookUniqueTestName("vpc")
		// A finalizer keeps the Vpc in etcd with a deletionTimestamp set
		// after Delete, mirroring a foreground cascade where the Vpc
		// lingers until its owned RouteTable is garbage-collected.
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{
				Name:       name,
				Finalizers: []string{"test.juneau.loutres.me/finalizer"},
			},
		})).To(Succeed())

		// VpcReconciler names the main RouteTable after the Vpc; mint it
		// directly since controllers do not run in this suite.
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: name},
		})).To(Succeed())

		Expect(webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		})).To(Succeed())
		Eventually(func(g Gomega) {
			var current juneauv1alpha1.Vpc
			g.Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
			g.Expect(current.DeletionTimestamp).NotTo(BeNil())
		}).Should(Succeed())

		var rt juneauv1alpha1.RouteTable
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &rt)).To(Succeed())
		Expect(webhookK8sClient.Delete(context.Background(), &rt)).To(Succeed())

		// Release the finalizer so the Vpc is actually removed and does
		// not leak into later specs.
		Eventually(func(g Gomega) {
			var current juneauv1alpha1.Vpc
			g.Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &current)).To(Succeed())
			current.Finalizers = nil
			g.Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
		}).Should(Succeed())
	})

	It("allows deleting a RouteTable that no Subnet references", func() {
		vpcName := createWebhookVpc()

		altRT := webhookUniqueTestName("rt")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: altRT},
			Spec:       juneauv1alpha1.RouteTableSpec{Vpc: vpcName},
		})).To(Succeed())

		var rt juneauv1alpha1.RouteTable
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: altRT}, &rt)).To(Succeed())
		Expect(webhookK8sClient.Delete(context.Background(), &rt)).To(Succeed())
	})
})

func createWebhookVpc() string {
	name := webhookUniqueTestName("vpc")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})).To(Succeed())
	return name
}

var _ = Describe("Subnet ↔ NetworkACL webhook", func() {
	It("rejects creating a Subnet whose networkACL does not exist", func() {
		vpcName := createWebhookVpc()
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:        vpcName,
				CIDR:       webhookUniqueSubnetCIDR(),
				NetworkACL: webhookUniqueTestName("missing-acl"),
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced NetworkACL does not exist"))
	})

	It("rejects creating a Subnet whose networkACL belongs to another Vpc", func() {
		aclVpc := createWebhookVpc()
		aclName := webhookUniqueTestName("acl")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: aclName},
			Spec:       juneauv1alpha1.NetworkACLSpec{Vpc: aclVpc},
		})).To(Succeed())

		subnetVpc := createWebhookVpc()
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:        subnetVpc,
				CIDR:       webhookUniqueSubnetCIDR(),
				NetworkACL: aclName,
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("NetworkACL belongs to Vpc"))
	})

	It("accepts a Subnet whose networkACL matches its Vpc, and lets the reference be cleared later", func() {
		vpcName := createWebhookVpc()
		aclName := webhookUniqueTestName("acl")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: aclName},
			Spec:       juneauv1alpha1.NetworkACLSpec{Vpc: vpcName},
		})).To(Succeed())

		subnet := &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:        vpcName,
				CIDR:       webhookUniqueSubnetCIDR(),
				NetworkACL: aclName,
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), subnet)).To(Succeed())

		var current juneauv1alpha1.Subnet
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(subnet), &current)).To(Succeed())
		current.Spec.NetworkACL = ""
		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})
})

func createWebhookServiceEnabledVpc() string {
	name := webhookUniqueTestName("vpc")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.VpcSpec{Service: &juneauv1alpha1.VpcServiceSpec{Consume: true}},
	})).To(Succeed())
	return name
}

// createWebhookServiceProviderVpc creates a Vpc that opts in to the
// cross-Vpc provider role, with a freshly-allocated Subnet acting as
// its NAT-source pool. Used by Service-webhook tests that verify
// provider-only behaviours (shared annotation acceptance, ACL).
func createWebhookServiceProviderVpc() string {
	vpcName := webhookUniqueTestName("vpc")
	subnetName := webhookUniqueTestName("subnet")

	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		// Provider must reference an existing Subnet, so create the
		// Vpc first without provider, attach the Subnet, then patch
		// provider in. Mirrors the bootstrap ordering used in
		// production.
	})).To(Succeed())
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: subnetName},
		Spec: juneauv1alpha1.SubnetSpec{
			Vpc:  vpcName,
			CIDR: webhookUniqueSubnetCIDR(),
		},
	})).To(Succeed())

	var vpc juneauv1alpha1.Vpc
	Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
	vpc.Spec.Service = &juneauv1alpha1.VpcServiceSpec{
		Consume:  true,
		Provider: &juneauv1alpha1.VpcServiceProviderSpec{NATSourceSubnet: subnetName},
	}
	Expect(webhookK8sClient.Update(context.Background(), &vpc)).To(Succeed())
	return vpcName
}

var _ = Describe("Vpc endpoint pool webhooks", func() {
	It("normalizes pool CIDRs to their masked form", func() {
		name := webhookUniqueTestName("vpc")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: juneauv1alpha1.VpcSpec{
				EndpointPool: &juneauv1alpha1.VpcEndpointPoolSpec{CIDRs: []string{"10.240.0.5/24"}},
			},
		})).To(Succeed())

		var vpc juneauv1alpha1.Vpc
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &vpc)).To(Succeed())
		Expect(vpc.Spec.EndpointPool.CIDRs).To(Equal([]string{"10.240.0.0/24"}))
	})

	It("rejects a pool CIDR that is not a valid IPv4 CIDR", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("vpc")},
			Spec: juneauv1alpha1.VpcSpec{
				EndpointPool: &juneauv1alpha1.VpcEndpointPoolSpec{CIDRs: []string{"10.240.0.0"}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be a valid IPv4 CIDR"))
	})

	It("rejects a pool CIDR wider than /16", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("vpc")},
			Spec: juneauv1alpha1.VpcSpec{
				EndpointPool: &juneauv1alpha1.VpcEndpointPoolSpec{CIDRs: []string{"10.240.0.0/15"}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("CIDR prefix length must be between /16 and /32"))
	})

	It("rejects pool CIDRs that overlap each other", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("vpc")},
			Spec: juneauv1alpha1.VpcSpec{
				EndpointPool: &juneauv1alpha1.VpcEndpointPoolSpec{
					CIDRs: []string{"10.240.0.0/24", "10.240.0.128/25"},
				},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlaps with spec.endpointPool.cidrs[0]"))
	})

	It("rejects a pool that overlaps the Service CIDR", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("vpc")},
			Spec: juneauv1alpha1.VpcSpec{
				EndpointPool: &juneauv1alpha1.VpcEndpointPoolSpec{CIDRs: []string{"10.96.0.0/24"}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlaps with Service CIDR"))
	})

	It("rejects a pool that overlaps a Subnet of the same Vpc", func() {
		vpcName := createWebhookVpc()
		subnetName := webhookUniqueTestName("subnet")
		createWebhookSubnet(subnetName, vpcName, "10.240.0.0/24")

		err := updateWebhookVpcEndpointPool(vpcName, "10.240.0.128/25")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlaps with Subnet"))
		Expect(err.Error()).To(ContainSubstring(subnetName))
	})

	It("accepts a pool that is disjoint from every Subnet of the same Vpc", func() {
		vpcName := createWebhookVpc()
		createWebhookSubnet(webhookUniqueTestName("subnet"), vpcName, "10.241.0.0/24")

		Expect(updateWebhookVpcEndpointPool(vpcName, "10.240.0.0/24")).To(Succeed())
	})

	It("rejects a pool that overlaps a Subnet of a peered Vpc", func() {
		vpcA := createWebhookVpc()
		vpcB := createWebhookVpc()
		peerSubnet := webhookUniqueTestName("subnet")
		createWebhookSubnet(peerSubnet, vpcB, "10.242.0.0/24")
		peeringName := webhookUniqueTestName("peering")
		Expect(webhookK8sClient.Create(context.Background(), newWebhookVpcPeering(peeringName, vpcA, vpcB))).To(Succeed())

		err := updateWebhookVpcEndpointPool(vpcA, "10.242.0.0/25")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(peerSubnet))
		Expect(err.Error()).To(ContainSubstring(peeringName))
	})

	It("rejects creating a Subnet that overlaps the endpoint pool of its own Vpc", func() {
		vpcName := createWebhookVpcWithEndpointPool("10.243.0.0/24")

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("subnet")},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: "10.243.0.0/25",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlaps with endpoint pool CIDR"))
		Expect(err.Error()).To(ContainSubstring(vpcName))
	})

	It("rejects shrinking the pool below the address of a live VpcEndpoint", func() {
		vpcName := createWebhookVpcWithEndpointPool("10.244.0.0/24", "10.245.0.0/24")
		endpointName := webhookUniqueTestName("vpcendpoint")
		createWebhookVpcEndpointWithAddress(endpointName, vpcName, "10.245.0.5")

		err := updateWebhookVpcEndpointPool(vpcName, "10.244.0.0/24")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(endpointName))
		Expect(err.Error()).To(ContainSubstring("10.245.0.5"))
	})

	It("accepts shrinking the pool while it still covers every live VpcEndpoint address", func() {
		vpcName := createWebhookVpcWithEndpointPool("10.246.0.0/24", "10.247.0.0/24")
		createWebhookVpcEndpointWithAddress(webhookUniqueTestName("vpcendpoint"), vpcName, "10.247.0.5")

		Expect(updateWebhookVpcEndpointPool(vpcName, "10.247.0.0/25")).To(Succeed())
	})

	It("rejects removing the endpoint pool while a VpcEndpoint still holds an address", func() {
		vpcName := createWebhookVpcWithEndpointPool("10.248.0.0/24")
		endpointName := webhookUniqueTestName("vpcendpoint")
		createWebhookVpcEndpointWithAddress(endpointName, vpcName, "10.248.0.5")

		err := removeWebhookVpcEndpointPool(vpcName)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(endpointName))
		Expect(err.Error()).To(ContainSubstring("10.248.0.5"))
	})
})

func createWebhookVpcWithEndpointPool(cidrs ...string) string {
	name := webhookUniqueTestName("vpc")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.VpcSpec{
			EndpointPool: &juneauv1alpha1.VpcEndpointPoolSpec{CIDRs: cidrs},
		},
	})).To(Succeed())
	return name
}

func updateWebhookVpcEndpointPool(vpcName string, cidrs ...string) error {
	var vpc juneauv1alpha1.Vpc
	Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
	vpc.Spec.EndpointPool = &juneauv1alpha1.VpcEndpointPoolSpec{CIDRs: cidrs}
	return webhookK8sClient.Update(context.Background(), &vpc)
}

func removeWebhookVpcEndpointPool(vpcName string) error {
	var vpc juneauv1alpha1.Vpc
	Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
	vpc.Spec.EndpointPool = nil
	return webhookK8sClient.Update(context.Background(), &vpc)
}

func webhookUniqueTestName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func webhookUniqueSubnetCIDR() string {
	// Avoid 10.96.0.0/12 (the test Service CIDR) so this helper is
	// safe to use even from specs that toggle Service routing on the
	// owning Vpc. We pick from 10.{20..95,112..219}.0.0/24.
	octet := int(time.Now().UnixNano()%(200-16) + 20)
	if octet >= 96 {
		octet += 16 // skip the 96..111 window
	}
	return fmt.Sprintf("10.%d.0.0/24", octet)
}
