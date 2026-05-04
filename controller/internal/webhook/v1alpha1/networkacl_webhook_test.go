package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("NetworkACL webhook", func() {
	It("rejects an ACL referencing a nonexistent Vpc", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: webhookUniqueTestName("missing-vpc"),
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("accepts a minimal ACL in the default Vpc", func() {
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec:       juneauv1alpha1.NetworkACLSpec{Vpc: "default"},
		})).To(Succeed())
	})

	It("accepts an ACL with explicit deny-all (empty list per direction)", func() {
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc:     "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{},
				Egress:  &[]juneauv1alpha1.NetworkACLRule{},
			},
		})).To(Succeed())
	})

	It("rejects rules that share a priority within a direction", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{
					{Priority: 100, Action: juneauv1alpha1.NetworkACLActionAllow, CIDR: "10.0.0.0/24"},
					{Priority: 100, Action: juneauv1alpha1.NetworkACLActionDeny, CIDR: "10.0.1.0/24"},
				},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("priorities must be unique within a direction"))
	})

	It("accepts identical priorities across different directions", func() {
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{
					{Priority: 100, Action: juneauv1alpha1.NetworkACLActionAllow, CIDR: "10.0.0.0/24"},
				},
				Egress: &[]juneauv1alpha1.NetworkACLRule{
					{Priority: 100, Action: juneauv1alpha1.NetworkACLActionAllow, CIDR: "0.0.0.0/0"},
				},
			},
		})).To(Succeed())
	})

	It("rejects ports when protocol=all", func() {
		port80 := int32(80)
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{{
					Priority: 100,
					Action:   juneauv1alpha1.NetworkACLActionAllow,
					Protocol: juneauv1alpha1.NetworkACLProtocolAll,
					CIDR:     "10.0.0.0/24",
					Ports:    []juneauv1alpha1.NetworkACLPort{{Port: &port80}},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("ports must be empty when protocol is icmp or all"))
	})

	It("rejects port range with from > to", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{{
					Priority: 100,
					Action:   juneauv1alpha1.NetworkACLActionAllow,
					Protocol: juneauv1alpha1.NetworkACLProtocolTCP,
					CIDR:     "10.0.0.0/24",
					Ports: []juneauv1alpha1.NetworkACLPort{{
						PortRange: &juneauv1alpha1.NetworkACLPortRange{From: 8000, To: 1000},
					}},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be >= portRange.from"))
	})

	It("rejects an invalid CIDR", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{{
					Priority: 100,
					Action:   juneauv1alpha1.NetworkACLActionAllow,
					CIDR:     "not-a-cidr",
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid CIDR"))
	})

	It("rejects vpc immutability violations", func() {
		acl := &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec:       juneauv1alpha1.NetworkACLSpec{Vpc: "default"},
		}
		Expect(webhookK8sClient.Create(context.Background(), acl)).To(Succeed())

		var current juneauv1alpha1.NetworkACL
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(acl), &current)).To(Succeed())

		newVpc := webhookUniqueTestName("vpc")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: newVpc},
		})).To(Succeed())
		current.Spec.Vpc = newVpc
		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("vpc is immutable"))
	})

	It("rejects deletion while a Subnet still references the ACL", func() {
		// Build a fresh Vpc + Subnet that references our ACL so the
		// delete attempt surfaces the dangling-reference rejection
		// rather than tripping over default-resource constraints.
		vpcName := webhookUniqueTestName("vpc")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		})).To(Succeed())

		aclName := webhookUniqueTestName("acl")
		acl := &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: aclName},
			Spec:       juneauv1alpha1.NetworkACLSpec{Vpc: vpcName},
		}
		Expect(webhookK8sClient.Create(context.Background(), acl)).To(Succeed())

		subnetName := webhookUniqueTestName("subnet")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnetName},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:        vpcName,
				CIDR:       webhookUniqueSubnetCIDR(),
				NetworkACL: aclName,
			},
		})).To(Succeed())

		err := webhookK8sClient.Delete(context.Background(), acl)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced by Subnet"))
	})
})
