package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("NetworkACL controller", func() {
	It("reports the rule count and the entry count as different numbers", func() {
		vpcName := createControllerVpc()
		aclName := createControllerNetworkACL(vpcName, &[]juneauv1alpha1.NetworkACLRule{{
			Priority: 100,
			Action:   juneauv1alpha1.NetworkACLActionAllow,
			Protocol: ptr.To(intstr.FromString("tcp")),
			CIDR:     "10.0.0.0/24",
			Ports:    controllerACLPorts(3),
		}}, nil)

		Eventually(func(g Gomega) {
			acl := getControllerNetworkACL(aclName)
			g.Expect(acl.Status.IngressRuleCount).To(Equal(int32(1)))
			g.Expect(acl.Status.IngressEntryCount).To(Equal(int32(3)))
			g.Expect(acl.Status.EgressRuleCount).To(Equal(int32(0)))
			g.Expect(acl.Status.EgressEntryCount).To(Equal(int32(0)))
			expectNetworkACLCondition(g, acl, juneauv1alpha1.NetworkACLConditionReady,
				metav1.ConditionTrue, juneauv1alpha1.NetworkACLReasonReconcileSucceeded)
			expectNetworkACLCondition(g, acl, juneauv1alpha1.NetworkACLConditionRulesValid,
				metav1.ConditionTrue, juneauv1alpha1.NetworkACLReasonReconcileSucceeded)
		}).Should(Succeed())
	})

	It("refuses Ready and RulesValid when a direction is over capacity", func() {
		vpcName := createControllerVpc()
		overCapacity := []juneauv1alpha1.NetworkACLRule{
			{
				Priority: 100,
				Action:   juneauv1alpha1.NetworkACLActionAllow,
				Protocol: ptr.To(intstr.FromString("tcp")),
				CIDR:     "10.0.0.0/24",
				Ports:    controllerACLPorts(juneauv1alpha1.NetworkACLMaxEntriesPerDirection),
			},
			{
				Priority: 200,
				Action:   juneauv1alpha1.NetworkACLActionAllow,
				Protocol: ptr.To(intstr.FromString("tcp")),
				CIDR:     "10.0.1.0/24",
				Ports:    controllerACLPorts(juneauv1alpha1.NetworkACLMaxEntriesPerDirection),
			},
		}
		aclName := createControllerNetworkACL(vpcName, &overCapacity, nil)

		Eventually(func(g Gomega) {
			acl := getControllerNetworkACL(aclName)
			g.Expect(acl.Status.IngressRuleCount).To(Equal(int32(2)))
			g.Expect(acl.Status.IngressEntryCount).To(Equal(int32(32)))
			expectNetworkACLCondition(g, acl, juneauv1alpha1.NetworkACLConditionRulesValid,
				metav1.ConditionFalse, juneauv1alpha1.NetworkACLReasonRuleLimitExceeded)
			expectNetworkACLCondition(g, acl, juneauv1alpha1.NetworkACLConditionReady,
				metav1.ConditionFalse, juneauv1alpha1.NetworkACLReasonRuleLimitExceeded)

			message := meta.FindStatusCondition(acl.Status.Conditions, juneauv1alpha1.NetworkACLConditionRulesValid).Message
			g.Expect(message).To(ContainSubstring("ingress"))
			g.Expect(message).To(ContainSubstring("32"))
			g.Expect(message).To(ContainSubstring("16"))
			g.Expect(message).To(ContainSubstring("port"))
		}).Should(Succeed())
	})

	It("names only the direction that is over capacity", func() {
		vpcName := createControllerVpc()
		egress := []juneauv1alpha1.NetworkACLRule{{
			Priority: 100,
			Action:   juneauv1alpha1.NetworkACLActionAllow,
			Protocol: ptr.To(intstr.FromString("tcp")),
			CIDR:     "0.0.0.0/0",
			Ports:    controllerACLPorts(juneauv1alpha1.NetworkACLMaxEntriesPerDirection),
		}}
		ingress := []juneauv1alpha1.NetworkACLRule{
			{Priority: 100, Action: juneauv1alpha1.NetworkACLActionAllow, CIDR: "10.0.0.0/24"},
		}
		aclName := createControllerNetworkACL(vpcName, &ingress, &egress)

		Eventually(func(g Gomega) {
			acl := getControllerNetworkACL(aclName)
			g.Expect(acl.Status.EgressEntryCount).To(Equal(int32(16)))
			expectNetworkACLCondition(g, acl, juneauv1alpha1.NetworkACLConditionReady,
				metav1.ConditionTrue, juneauv1alpha1.NetworkACLReasonReconcileSucceeded)
		}).Should(Succeed())
	})

	Describe("nextRulesetVersion", func() {
		var reconciler *NetworkACLReconciler

		BeforeEach(func() {
			reconciler = &NetworkACLReconciler{}
		})

		It("keeps the published version when nothing in the summary changed", func() {
			acl := networkACLAtVersion(7, networkACLRuleSummary{
				ingressRuleCount:  1,
				ingressEntryCount: 3,
				hasIngressRules:   true,
			})
			Expect(reconciler.nextRulesetVersion(acl, networkACLRuleSummary{
				ingressRuleCount:  1,
				ingressEntryCount: 3,
				hasIngressRules:   true,
			})).To(Equal(uint64(7)))
		})

		It("bumps the published version when only the entry counts changed", func() {
			acl := networkACLAtVersion(7, networkACLRuleSummary{
				ingressRuleCount:  1,
				ingressEntryCount: 3,
				hasIngressRules:   true,
			})
			Expect(reconciler.nextRulesetVersion(acl, networkACLRuleSummary{
				ingressRuleCount:  1,
				ingressEntryCount: 5,
				hasIngressRules:   true,
			})).To(Equal(uint64(8)))
		})
	})
})

func createControllerNetworkACL(vpcName string, ingress, egress *[]juneauv1alpha1.NetworkACLRule) string {
	name := uniqueTestName("acl")
	Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.NetworkACL{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.NetworkACLSpec{
			Vpc:     vpcName,
			Ingress: ingress,
			Egress:  egress,
		},
	})).To(Succeed())
	return name
}

func getControllerNetworkACL(name string) *juneauv1alpha1.NetworkACL {
	var acl juneauv1alpha1.NetworkACL
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &acl)).To(Succeed())
	return &acl
}

func expectNetworkACLCondition(g Gomega, acl *juneauv1alpha1.NetworkACL, conditionType string, status metav1.ConditionStatus, reason string) {
	condition := meta.FindStatusCondition(acl.Status.Conditions, conditionType)
	g.Expect(condition).NotTo(BeNil())
	g.Expect(condition.Status).To(Equal(status))
	g.Expect(condition.Reason).To(Equal(reason))
	g.Expect(condition.ObservedGeneration).To(Equal(acl.Generation))
}

func controllerACLPorts(count int) []juneauv1alpha1.NetworkACLPort {
	ports := make([]juneauv1alpha1.NetworkACLPort, 0, count)
	for i := 0; i < count; i++ {
		port := int32(1000 + i)
		ports = append(ports, juneauv1alpha1.NetworkACLPort{Port: &port})
	}
	return ports
}

// networkACLAtVersion builds an ACL whose status already published the
// given summary, so nextRulesetVersion sees an up-to-date generation and
// only the summary can make it move.
func networkACLAtVersion(version uint64, published networkACLRuleSummary) *juneauv1alpha1.NetworkACL {
	return &juneauv1alpha1.NetworkACL{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("acl"), Generation: 3},
		Status: juneauv1alpha1.NetworkACLStatus{
			ObservedGeneration: 3,
			RulesetVersion:     version,
			IngressRuleCount:   published.ingressRuleCount,
			EgressRuleCount:    published.egressRuleCount,
			IngressEntryCount:  published.ingressEntryCount,
			EgressEntryCount:   published.egressEntryCount,
			HasIngressRules:    published.hasIngressRules,
			HasEgressRules:     published.hasEgressRules,
		},
	}
}
