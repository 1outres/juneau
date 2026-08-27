package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
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
					Protocol: ptr.To(intstr.FromString("all")),
					CIDR:     "10.0.0.0/24",
					Ports:    []juneauv1alpha1.NetworkACLPort{{Port: &port80}},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("ports are only valid when protocol is tcp or udp"))
	})

	It("accepts a rule written with an IP protocol number", func() {
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{{
					Priority: 100,
					Action:   juneauv1alpha1.NetworkACLActionAllow,
					Protocol: ptr.To(intstr.FromInt32(47)),
					CIDR:     "10.0.0.0/24",
				}},
			},
		})).To(Succeed())
	})

	It("rejects ports on a protocol that has none", func() {
		port80 := int32(80)
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{{
					Priority: 100,
					Action:   juneauv1alpha1.NetworkACLActionAllow,
					Protocol: ptr.To(intstr.FromString("gre")),
					CIDR:     "10.0.0.0/24",
					Ports:    []juneauv1alpha1.NetworkACLPort{{Port: &port80}},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("ports are only valid when protocol is tcp or udp"))
	})

	It("rejects a protocol number outside [0, 255]", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{{
					Priority: 100,
					Action:   juneauv1alpha1.NetworkACLActionAllow,
					Protocol: ptr.To(intstr.FromInt32(256)),
					CIDR:     "10.0.0.0/24",
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("IP protocol number in [0, 255]"))
	})

	It("rejects an unknown protocol keyword", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{{
					Priority: 100,
					Action:   juneauv1alpha1.NetworkACLActionAllow,
					Protocol: ptr.To(intstr.FromString("quic")),
					CIDR:     "10.0.0.0/24",
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("IP protocol number in [0, 255]"))
	})

	It("rejects port range with from > to", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc: "default",
				Ingress: &[]juneauv1alpha1.NetworkACLRule{{
					Priority: 100,
					Action:   juneauv1alpha1.NetworkACLActionAllow,
					Protocol: ptr.To(intstr.FromString("tcp")),
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

var _ = Describe("NetworkACL webhook entry capacity", func() {
	It("accepts a direction that expands to exactly the entry limit", func() {
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc:     "default",
				Ingress: webhookACLRules(juneauv1alpha1.NetworkACLMaxEntriesPerDirection),
				Egress:  webhookACLRules(juneauv1alpha1.NetworkACLMaxEntriesPerDirection),
			},
		})).To(Succeed())
	})

	It("rejects an ingress direction one entry over the limit", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc:     "default",
				Ingress: webhookACLRulesOneEntryOverTheLimit(),
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.ingress"))
		Expect(err.Error()).To(ContainSubstring("Too many: 17"))
		Expect(err.Error()).To(ContainSubstring("must have at most 16 entries"))
		Expect(err.Error()).To(ContainSubstring("costs"))
	})

	It("rejects an egress direction one entry over the limit", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc:    "default",
				Egress: webhookACLRulesOneEntryOverTheLimit(),
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.egress"))
		Expect(err.Error()).To(ContainSubstring("Too many: 17"))
		Expect(err.Error()).To(ContainSubstring("must have at most 16 entries"))
	})

	It("rejects more rules than a direction can ever hold", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec: juneauv1alpha1.NetworkACLSpec{
				Vpc:     "default",
				Ingress: webhookACLRules(juneauv1alpha1.NetworkACLMaxEntriesPerDirection + 1),
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.ingress"))
		Expect(err.Error()).To(ContainSubstring("must have at most 16 items"))
	})

	It("counts ports rather than rules against the entry limit", func() {
		rules := webhookACLRules(2)
		for i := range *rules {
			(*rules)[i].Protocol = ptr.To(intstr.FromString("tcp"))
			(*rules)[i].Ports = webhookACLPorts(9)
		}
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec:       juneauv1alpha1.NetworkACLSpec{Vpc: "default", Ingress: rules},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Too many: 18"))
	})

	It("accepts a single rule whose ports fill the whole direction budget", func() {
		rules := webhookACLRules(1)
		(*rules)[0].Protocol = ptr.To(intstr.FromString("tcp"))
		(*rules)[0].Ports = webhookACLPorts(juneauv1alpha1.NetworkACLMaxEntriesPerDirection)
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec:       juneauv1alpha1.NetworkACLSpec{Vpc: "default", Ingress: rules},
		})).To(Succeed())
	})

	It("rejects a single rule carrying more ports than the whole direction budget", func() {
		rules := webhookACLRules(1)
		(*rules)[0].Protocol = ptr.To(intstr.FromString("tcp"))
		(*rules)[0].Ports = webhookACLPorts(juneauv1alpha1.NetworkACLMaxEntriesPerDirection + 1)
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("acl")},
			Spec:       juneauv1alpha1.NetworkACLSpec{Vpc: "default", Ingress: rules},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("at most 16 items"))
	})
})

// webhookACLRules returns count port-less rules, so the direction costs
// exactly count entries.
func webhookACLRules(count int) *[]juneauv1alpha1.NetworkACLRule {
	rules := make([]juneauv1alpha1.NetworkACLRule, 0, count)
	for i := 0; i < count; i++ {
		rules = append(rules, juneauv1alpha1.NetworkACLRule{
			Priority: int32(i + 1),
			Action:   juneauv1alpha1.NetworkACLActionAllow,
			CIDR:     "10.0.0.0/24",
		})
	}
	return &rules
}

// webhookACLRulesOneEntryOverTheLimit fills a direction with the most
// rules the schema allows and then adds one port to the first rule, so
// the direction costs one entry more than it may hold. Going one rule
// over instead would trip the schema item cap and never reach the
// entry check.
func webhookACLRulesOneEntryOverTheLimit() *[]juneauv1alpha1.NetworkACLRule {
	rules := webhookACLRules(juneauv1alpha1.NetworkACLMaxEntriesPerDirection)
	(*rules)[0].Protocol = ptr.To(intstr.FromString("tcp"))
	(*rules)[0].Ports = webhookACLPorts(2)
	return rules
}

func webhookACLPorts(count int) []juneauv1alpha1.NetworkACLPort {
	ports := make([]juneauv1alpha1.NetworkACLPort, 0, count)
	for i := 0; i < count; i++ {
		port := int32(1000 + i)
		ports = append(ports, juneauv1alpha1.NetworkACLPort{Port: &port})
	}
	return ports
}
