package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("SecurityGroup controller", func() {
	It("reports the rule count and the entry count as different numbers", func() {
		vpcName := createControllerVpc()
		sgName := createControllerSecurityGroup(vpcName, []juneauv1alpha1.SecurityGroupIngressRule{{
			From:     controllerSGPeers(2),
			Protocol: ptr.To(intstr.FromString("tcp")),
			Ports:    controllerSGPorts(3),
		}}, nil)

		Eventually(func(g Gomega) {
			sg := getControllerSecurityGroup(sgName)
			g.Expect(sg.Status.IngressRuleCount).To(Equal(int32(1)))
			g.Expect(sg.Status.IngressEntryCount).To(Equal(int32(6)))
			g.Expect(sg.Status.EgressRuleCount).To(Equal(int32(0)))
			g.Expect(sg.Status.EgressEntryCount).To(Equal(int32(0)))
			expectSecurityGroupCondition(g, sg, juneauv1alpha1.SecurityGroupConditionReady,
				metav1.ConditionTrue, juneauv1alpha1.SecurityGroupReasonReconcileSucceeded)
			expectSecurityGroupCondition(g, sg, juneauv1alpha1.SecurityGroupConditionRulesValid,
				metav1.ConditionTrue, juneauv1alpha1.SecurityGroupReasonReconcileSucceeded)
		}).Should(Succeed())
	})

	It("refuses Ready and RulesValid when one rule expands past the direction budget", func() {
		vpcName := createControllerVpc()
		sgName := createControllerSecurityGroup(vpcName, []juneauv1alpha1.SecurityGroupIngressRule{{
			From:     controllerSGPeers(4),
			Protocol: ptr.To(intstr.FromString("tcp")),
			Ports:    controllerSGPorts(4),
		}}, nil)

		Eventually(func(g Gomega) {
			sg := getControllerSecurityGroup(sgName)
			g.Expect(sg.Status.IngressRuleCount).To(Equal(int32(1)))
			g.Expect(sg.Status.IngressEntryCount).To(Equal(int32(16)))
			expectSecurityGroupCondition(g, sg, juneauv1alpha1.SecurityGroupConditionRulesValid,
				metav1.ConditionFalse, juneauv1alpha1.SecurityGroupReasonRuleLimitExceeded)
			expectSecurityGroupCondition(g, sg, juneauv1alpha1.SecurityGroupConditionReady,
				metav1.ConditionFalse, juneauv1alpha1.SecurityGroupReasonRuleLimitExceeded)

			message := meta.FindStatusCondition(sg.Status.Conditions, juneauv1alpha1.SecurityGroupConditionRulesValid).Message
			g.Expect(message).To(ContainSubstring("ingress"))
			g.Expect(message).To(ContainSubstring("16"))
			g.Expect(message).To(ContainSubstring("8"))
			g.Expect(message).To(ContainSubstring("peer"))
		}).Should(Succeed())
	})

	It("reports an explicit empty egress list as declared but free of entries", func() {
		vpcName := createControllerVpc()
		sgName := createControllerSecurityGroup(vpcName, nil, &[]juneauv1alpha1.SecurityGroupEgressRule{})

		Eventually(func(g Gomega) {
			sg := getControllerSecurityGroup(sgName)
			g.Expect(sg.Status.HasEgressRules).To(BeTrue())
			g.Expect(sg.Status.EgressRuleCount).To(Equal(int32(0)))
			g.Expect(sg.Status.EgressEntryCount).To(Equal(int32(0)))
		}).Should(Succeed())
	})

	Describe("nextRulesetVersion", func() {
		var reconciler *SecurityGroupReconciler

		BeforeEach(func() {
			reconciler = &SecurityGroupReconciler{}
		})

		It("keeps the published version when nothing in the summary changed", func() {
			sg := securityGroupAtVersion(4, securityGroupRuleSummary{
				ingressRuleCount:  1,
				ingressEntryCount: 6,
			})
			Expect(reconciler.nextRulesetVersion(sg, securityGroupRuleSummary{
				ingressRuleCount:  1,
				ingressEntryCount: 6,
			})).To(Equal(uint64(4)))
		})

		It("bumps the published version when only the entry counts changed", func() {
			sg := securityGroupAtVersion(4, securityGroupRuleSummary{
				ingressRuleCount:  1,
				ingressEntryCount: 6,
			})
			Expect(reconciler.nextRulesetVersion(sg, securityGroupRuleSummary{
				ingressRuleCount:  1,
				ingressEntryCount: 2,
			})).To(Equal(uint64(5)))
		})
	})
})

func createControllerSecurityGroup(vpcName string, ingress []juneauv1alpha1.SecurityGroupIngressRule, egress *[]juneauv1alpha1.SecurityGroupEgressRule) string {
	name := uniqueTestName("sg")
	Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: juneauv1alpha1.SecurityGroupSpec{
			Vpc:     vpcName,
			Ingress: ingress,
			Egress:  egress,
		},
	})).To(Succeed())
	return name
}

func getControllerSecurityGroup(name string) *juneauv1alpha1.SecurityGroup {
	var sg juneauv1alpha1.SecurityGroup
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &sg)).To(Succeed())
	return &sg
}

func expectSecurityGroupCondition(g Gomega, sg *juneauv1alpha1.SecurityGroup, conditionType string, status metav1.ConditionStatus, reason string) {
	condition := meta.FindStatusCondition(sg.Status.Conditions, conditionType)
	g.Expect(condition).NotTo(BeNil())
	g.Expect(condition.Status).To(Equal(status))
	g.Expect(condition.Reason).To(Equal(reason))
	g.Expect(condition.ObservedGeneration).To(Equal(sg.Generation))
}

func controllerSGPeers(count int) []juneauv1alpha1.SecurityGroupPeer {
	peers := make([]juneauv1alpha1.SecurityGroupPeer, 0, count)
	for i := 0; i < count; i++ {
		peers = append(peers, juneauv1alpha1.SecurityGroupPeer{CIDR: fmt.Sprintf("10.%d.0.0/16", i+1)})
	}
	return peers
}

func controllerSGPorts(count int) []juneauv1alpha1.SecurityGroupPort {
	ports := make([]juneauv1alpha1.SecurityGroupPort, 0, count)
	for i := 0; i < count; i++ {
		port := int32(1000 + i)
		ports = append(ports, juneauv1alpha1.SecurityGroupPort{Port: &port})
	}
	return ports
}

// securityGroupAtVersion builds an SG whose status already published the
// given summary, so nextRulesetVersion sees an up-to-date generation and
// only the summary can make it move.
func securityGroupAtVersion(version uint64, published securityGroupRuleSummary) *juneauv1alpha1.SecurityGroup {
	return &juneauv1alpha1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("sg"), Generation: 2},
		Status: juneauv1alpha1.SecurityGroupStatus{
			ObservedGeneration: 2,
			RulesetVersion:     version,
			IngressRuleCount:   published.ingressRuleCount,
			EgressRuleCount:    published.egressRuleCount,
			IngressEntryCount:  published.ingressEntryCount,
			EgressEntryCount:   published.egressEntryCount,
			HasEgressRules:     published.hasEgressRules,
		},
	}
}
