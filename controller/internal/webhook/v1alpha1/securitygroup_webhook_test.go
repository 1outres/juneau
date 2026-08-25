package v1alpha1

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("SecurityGroup webhook", func() {
	It("rejects a SG referencing a nonexistent Vpc", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: webhookUniqueTestName("missing-vpc"),
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("accepts a minimal SG in default Vpc", func() {
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
			},
		})).To(Succeed())
	})

	It("rejects an ingress rule with both cidr and securityGroupRef on the same peer", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
				Ingress: []juneauv1alpha1.SecurityGroupIngressRule{{
					From: []juneauv1alpha1.SecurityGroupPeer{{
						CIDR:             "10.0.0.0/8",
						SecurityGroupRef: &juneauv1alpha1.SecurityGroupPeerRef{Name: "x"},
					}},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("exactly one of cidr or securityGroupRef"))
	})

	It("rejects ports when protocol=all", func() {
		port80 := int32(80)
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
				Ingress: []juneauv1alpha1.SecurityGroupIngressRule{{
					From:     []juneauv1alpha1.SecurityGroupPeer{{CIDR: "10.0.0.0/8"}},
					Protocol: juneauv1alpha1.SecurityGroupProtocolAll,
					Ports:    []juneauv1alpha1.SecurityGroupPort{{Port: &port80}},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("ports must be empty when protocol is icmp or all"))
	})

	It("rejects port range with from > to", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
				Ingress: []juneauv1alpha1.SecurityGroupIngressRule{{
					From:     []juneauv1alpha1.SecurityGroupPeer{{CIDR: "10.0.0.0/8"}},
					Protocol: juneauv1alpha1.SecurityGroupProtocolTCP,
					Ports: []juneauv1alpha1.SecurityGroupPort{{
						PortRange: &juneauv1alpha1.SecurityGroupPortRange{From: 200, To: 100},
					}},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be >= portRange.from"))
	})

	It("rejects securityGroupRef pointing at a different Vpc", func() {
		// Create another VPC + an SG in it.
		otherVpcName := webhookUniqueTestName("vpc")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: otherVpcName},
		})).To(Succeed())

		otherSGName := webhookUniqueTestName("sg-other-vpc")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: otherSGName},
			Spec:       juneauv1alpha1.SecurityGroupSpec{Vpc: otherVpcName},
		})).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
				Ingress: []juneauv1alpha1.SecurityGroupIngressRule{{
					From: []juneauv1alpha1.SecurityGroupPeer{{
						SecurityGroupRef: &juneauv1alpha1.SecurityGroupPeerRef{Name: otherSGName},
					}},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("belongs to Vpc"))
	})

	It("rejects vpc immutability violations", func() {
		sg := &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec:       juneauv1alpha1.SecurityGroupSpec{Vpc: "default"},
		}
		Expect(webhookK8sClient.Create(context.Background(), sg)).To(Succeed())

		var current juneauv1alpha1.SecurityGroup
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(sg), &current)).To(Succeed())

		// Make sure target Vpc exists so the only error surfaced is immutability.
		newVpc := webhookUniqueTestName("vpc")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: newVpc},
		})).To(Succeed())
		current.Spec.Vpc = newVpc
		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("vpc is immutable"))
	})

	It("rejects invalid CIDR peers", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
				Ingress: []juneauv1alpha1.SecurityGroupIngressRule{{
					From: []juneauv1alpha1.SecurityGroupPeer{{CIDR: "not-a-cidr"}},
				}},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid CIDR"))
	})
})

var _ = Describe("SecurityGroup webhook entry capacity", func() {
	It("accepts a direction that expands to exactly the entry limit", func() {
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
				Ingress: []juneauv1alpha1.SecurityGroupIngressRule{
					{From: webhookSGPeers(2), Protocol: juneauv1alpha1.SecurityGroupProtocolTCP, Ports: webhookSGPorts(2)},
					{From: webhookSGPeers(2), Protocol: juneauv1alpha1.SecurityGroupProtocolTCP, Ports: webhookSGPorts(2)},
				},
				Egress: &[]juneauv1alpha1.SecurityGroupEgressRule{
					{To: webhookSGPeers(4), Protocol: juneauv1alpha1.SecurityGroupProtocolTCP, Ports: webhookSGPorts(2)},
				},
			},
		})).To(Succeed())
	})

	It("rejects an ingress direction one entry over the limit", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
				Ingress: []juneauv1alpha1.SecurityGroupIngressRule{
					{From: webhookSGPeers(3), Protocol: juneauv1alpha1.SecurityGroupProtocolTCP, Ports: webhookSGPorts(3)},
				},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.ingress"))
		Expect(err.Error()).To(ContainSubstring("Too many: 9"))
		Expect(err.Error()).To(ContainSubstring("must have at most 8 entries"))
		Expect(err.Error()).To(ContainSubstring("costs"))
	})

	It("rejects an egress direction one entry over the limit", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
				Egress: &[]juneauv1alpha1.SecurityGroupEgressRule{
					{To: webhookSGPeers(3), Protocol: juneauv1alpha1.SecurityGroupProtocolTCP, Ports: webhookSGPorts(3)},
				},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.egress"))
		Expect(err.Error()).To(ContainSubstring("Too many: 9"))
	})

	It("rejects a single rule whose peers times ports exceed the direction budget", func() {
		err := webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("sg")},
			Spec: juneauv1alpha1.SecurityGroupSpec{
				Vpc: "default",
				Ingress: []juneauv1alpha1.SecurityGroupIngressRule{
					{From: webhookSGPeers(4), Protocol: juneauv1alpha1.SecurityGroupProtocolTCP, Ports: webhookSGPorts(4)},
				},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Too many: 16"))
		Expect(err.Error()).To(ContainSubstring("peers"))
	})
})

func webhookSGPeers(count int) []juneauv1alpha1.SecurityGroupPeer {
	peers := make([]juneauv1alpha1.SecurityGroupPeer, 0, count)
	for i := 0; i < count; i++ {
		peers = append(peers, juneauv1alpha1.SecurityGroupPeer{CIDR: fmt.Sprintf("10.%d.0.0/16", i+1)})
	}
	return peers
}

func webhookSGPorts(count int) []juneauv1alpha1.SecurityGroupPort {
	ports := make([]juneauv1alpha1.SecurityGroupPort, 0, count)
	for i := 0; i < count; i++ {
		port := int32(1000 + i)
		ports = append(ports, juneauv1alpha1.SecurityGroupPort{Port: &port})
	}
	return ports
}
