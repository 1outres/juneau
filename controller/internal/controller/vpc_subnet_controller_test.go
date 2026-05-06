package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("Vpc/Subnet controllers", func() {
	It("auto-creates the default VPC", func() {
		Eventually(func(g Gomega) {
			var vpc juneauv1alpha1.Vpc
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: "default"}, &vpc)).To(Succeed())
			g.Expect(vpc.Status.VpcID).To(Equal(uint32(1)))
		}).Should(Succeed())
	})

	It("reconciles a created VPC to Ready", func() {
		name := uniqueTestName("vpc")
		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			var vpc juneauv1alpha1.Vpc
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name}, &vpc)).To(Succeed())
			g.Expect(vpc.Status.MainRouteTable).To(Equal(name))
			g.Expect(vpc.Status.VpcID).NotTo(BeZero())
			g.Expect(vpc.Status.VpcID).NotTo(Equal(uint32(1)))

			ready := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(ready.ObservedGeneration).To(Equal(vpc.Generation))
		}).Should(Succeed())
	})

	It("auto-creates the default Subnet in the default VPC", func() {
		Eventually(func(g Gomega) {
			var subnet juneauv1alpha1.Subnet
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: "default"}, &subnet)).To(Succeed())
			g.Expect(subnet.Spec.Vpc).To(Equal("default"))
		}).Should(Succeed())
	})

	It("reconciles a non-default Subnet in a ready VPC", func() {
		vpcName := uniqueTestName("vpc")
		subnetName := uniqueTestName("subnet")
		cidr := uniqueSubnetCIDR()

		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			var vpc juneauv1alpha1.Vpc
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
			ready := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		}).Should(Succeed())

		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnetName},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: cidr,
			},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			var subnet juneauv1alpha1.Subnet
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: subnetName}, &subnet)).To(Succeed())

			ready := meta.FindStatusCondition(subnet.Status.Conditions, juneauv1alpha1.SubnetStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(ready.ObservedGeneration).To(Equal(subnet.Generation))
			g.Expect(subnet.Status.VNI).NotTo(BeZero())
			g.Expect(subnet.Status.Gateway).NotTo(BeEmpty())
			g.Expect(subnet.Status.GatewayMAC).NotTo(BeEmpty())
			g.Expect(subnet.Status.DNS).NotTo(BeEmpty(), "DNS VIP should be assigned for /24")
			g.Expect(subnet.Status.DNSMAC).NotTo(BeEmpty(), "DNS MAC should be generated when DNS is assigned")
			g.Expect(subnet.Status.DNS).NotTo(Equal(subnet.Status.Gateway), "DNS VIP must differ from Gateway")
			g.Expect(subnet.Status.DNSMAC).NotTo(Equal(subnet.Status.GatewayMAC), "DNS MAC must differ from Gateway MAC")
		}).Should(Succeed())
	})

	// When a Vpc opts in to the cross-Vpc provider role, admission no
	// longer enforces that spec.service.provider.natSourceSubnet
	// resolves; the controller surfaces missing/foreign references via
	// the Ready condition and reconciles back to Ready=True once the
	// Subnet appears with the right ownership.
	It("marks a provider Vpc NotReady when the natSourceSubnet is missing, and recovers when it appears", func() {
		vpcName := uniqueTestName("vpc")
		subnetName := uniqueTestName("subnet")

		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
			Spec: juneauv1alpha1.VpcSpec{Service: &juneauv1alpha1.VpcServiceSpec{
				Provider: &juneauv1alpha1.VpcServiceProviderSpec{NATSourceSubnet: subnetName},
			}},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			var vpc juneauv1alpha1.Vpc
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
			ready := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(vpcReasonProviderSubnetMissing))
		}).Should(Succeed())

		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnetName},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: uniqueSubnetCIDR(),
			},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			var vpc juneauv1alpha1.Vpc
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
			ready := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		}).Should(Succeed())
	})

	It("marks a provider Vpc NotReady when the natSourceSubnet is owned by a different Vpc", func() {
		ownerVpc := uniqueTestName("vpc-owner")
		otherVpc := uniqueTestName("vpc-other")
		subnetName := uniqueTestName("subnet")

		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: ownerVpc},
		})).To(Succeed())
		Eventually(func(g Gomega) {
			var vpc juneauv1alpha1.Vpc
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: ownerVpc}, &vpc)).To(Succeed())
			ready := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		}).Should(Succeed())

		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnetName},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  ownerVpc,
				CIDR: uniqueSubnetCIDR(),
			},
		})).To(Succeed())

		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: otherVpc},
			Spec: juneauv1alpha1.VpcSpec{Service: &juneauv1alpha1.VpcServiceSpec{
				Provider: &juneauv1alpha1.VpcServiceProviderSpec{NATSourceSubnet: subnetName},
			}},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			var vpc juneauv1alpha1.Vpc
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: otherVpc}, &vpc)).To(Succeed())
			ready := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(vpcReasonProviderSubnetForeign))
		}).Should(Succeed())
	})

	It("keeps DNS VIP / MAC stable across reconciles", func() {
		vpcName := uniqueTestName("vpc")
		subnetName := uniqueTestName("subnet")
		cidr := uniqueSubnetCIDR()

		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			var vpc juneauv1alpha1.Vpc
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
			ready := meta.FindStatusCondition(vpc.Status.Conditions, juneauv1alpha1.VpcStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		}).Should(Succeed())

		Expect(k8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnetName},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: cidr,
			},
		})).To(Succeed())

		var firstDNS, firstDNSMAC string
		Eventually(func(g Gomega) {
			var subnet juneauv1alpha1.Subnet
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: subnetName}, &subnet)).To(Succeed())
			ready := meta.FindStatusCondition(subnet.Status.Conditions, juneauv1alpha1.SubnetStatusReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(subnet.Status.DNS).NotTo(BeEmpty())
			g.Expect(subnet.Status.DNSMAC).NotTo(BeEmpty())
			firstDNS = subnet.Status.DNS
			firstDNSMAC = subnet.Status.DNSMAC
		}).Should(Succeed())

		// Touch the resource to trigger another reconcile pass; the
		// generated MAC must not be regenerated. (Annotations do not bump
		// .Status, but the controller still re-reconciles.)
		Eventually(func(g Gomega) {
			var subnet juneauv1alpha1.Subnet
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: subnetName}, &subnet)).To(Succeed())
			if subnet.Annotations == nil {
				subnet.Annotations = map[string]string{}
			}
			subnet.Annotations["test.juneau.loutres.me/touched"] = "1"
			g.Expect(k8sClient.Update(context.Background(), &subnet)).To(Succeed())
		}).Should(Succeed())

		Consistently(func(g Gomega) {
			var subnet juneauv1alpha1.Subnet
			g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: subnetName}, &subnet)).To(Succeed())
			g.Expect(subnet.Status.DNS).To(Equal(firstDNS))
			g.Expect(subnet.Status.DNSMAC).To(Equal(firstDNSMAC))
		}, 2*time.Second, 200*time.Millisecond).Should(Succeed())
	})
})

func uniqueTestName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func uniqueSubnetCIDR() string {
	octet := time.Now().UnixNano()%200 + 20
	return fmt.Sprintf("10.%d.0.0/24", octet)
}

// uniqueExternalIPv4 returns a TEST-NET-3 (RFC 5737) address that is
// guaranteed not to overlap with subnet CIDRs handed out by
// uniqueSubnetCIDR or with the testServiceCIDR (10.96.0.0/12). The
// last two octets vary by wall-clock so concurrent test specs do not
// collide on a single Service externalIP value.
var externalIPCounter uint32

func uniqueExternalIPv4() string {
	externalIPCounter++
	v := externalIPCounter
	return fmt.Sprintf("203.0.113.%d", (v%200)+10)
}
