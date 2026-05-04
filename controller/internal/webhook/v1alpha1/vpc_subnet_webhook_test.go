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
		vpc.Spec.EnableService = true
		err := webhookK8sClient.Update(context.Background(), &vpc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlaps with Service CIDR"))
	})

	It("rejects creating a Subnet that overlaps the Service CIDR when the VPC has enableService=true", func() {
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
		Spec:       juneauv1alpha1.VpcSpec{EnableService: true},
	})).To(Succeed())
	return name
}

func webhookUniqueTestName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func webhookUniqueSubnetCIDR() string {
	octet := time.Now().UnixNano()%200 + 20
	return fmt.Sprintf("10.%d.0.0/24", octet)
}
