package v1alpha1

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func uniquePodName() string {
	return fmt.Sprintf("podtest-%d", time.Now().UnixNano())
}

// patchDefaultSubnetDNS makes the default Subnet appear ready with
// fixed DNS / DNSMAC values. Webhook envtest does not run the
// SubnetReconciler, so we hand-author Status the way the
// reconciler would have written it. Returns the values set so each
// spec can assert against them.
func patchDefaultSubnetDNS() juneauv1alpha1.Subnet {
	GinkgoHelper()
	var subnet juneauv1alpha1.Subnet
	Eventually(func(g Gomega) {
		g.Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: "default"}, &subnet)).To(Succeed())
	}).Should(Succeed())
	subnet.Status.DNS = "10.16.0.2"
	subnet.Status.DNSMAC = "02:42:0a:10:00:02"
	subnet.Status.Gateway = "10.16.0.1"
	subnet.Status.GatewayMAC = "02:42:0a:10:00:01"
	if subnet.Status.VNI == 0 {
		subnet.Status.VNI = 1
	}
	meta.SetStatusCondition(&subnet.Status.Conditions, metav1.Condition{
		Type:               juneauv1alpha1.SubnetStatusReady,
		Status:             metav1.ConditionTrue,
		Reason:             "ReconcileSucceeded",
		ObservedGeneration: subnet.Generation,
	})
	Expect(webhookK8sClient.Status().Update(context.Background(), &subnet)).To(Succeed())
	return subnet
}

func makePodWithImage(name, ns string, annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: "registry.example/pause:1"}},
		},
	}
}

var _ = Describe("Pod DNS injection webhook", func() {
	It("rewrites dnsPolicy + dnsConfig to point at the Subnet's DNS VIP", func() {
		subnet := patchDefaultSubnetDNS()

		pod := makePodWithImage(uniquePodName(), "default", nil)
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: pod.Name, Namespace: "default"}, &fetched)).To(Succeed())
		Expect(fetched.Spec.DNSPolicy).To(Equal(corev1.DNSNone))
		Expect(fetched.Spec.DNSConfig).NotTo(BeNil())
		Expect(fetched.Spec.DNSConfig.Nameservers).To(ContainElement(subnet.Status.DNS))
		Expect(fetched.Spec.DNSConfig.Searches).To(ContainElement("default.svc.cluster.local"))
		Expect(fetched.Spec.DNSConfig.Searches).To(ContainElement("svc.cluster.local"))
		Expect(fetched.Spec.DNSConfig.Searches).To(ContainElement("cluster.local"))

		var ndotsValue *string
		for _, opt := range fetched.Spec.DNSConfig.Options {
			if opt.Name == "ndots" {
				ndotsValue = opt.Value
			}
		}
		Expect(ndotsValue).NotTo(BeNil())
		Expect(*ndotsValue).To(Equal("5"))
	})

	It("respects per-Pod opt-out annotation", func() {
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			PodAnnotationDNSInjectSkip: "true",
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: pod.Name, Namespace: "default"}, &fetched)).To(Succeed())
		// "" + nil dnsConfig → kubelet applies its default ClusterFirst.
		Expect(fetched.Spec.DNSPolicy).NotTo(Equal(corev1.DNSNone))
		Expect(fetched.Spec.DNSConfig).To(BeNil())
	})

	It("skips hostNetwork pods", func() {
		pod := makePodWithImage(uniquePodName(), "default", nil)
		pod.Spec.HostNetwork = true
		// hostNetwork requires a matching dnsPolicy hint to be valid.
		pod.Spec.DNSPolicy = corev1.DNSClusterFirstWithHostNet
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: pod.Name, Namespace: "default"}, &fetched)).To(Succeed())
		Expect(fetched.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirstWithHostNet))
		Expect(fetched.Spec.DNSConfig).To(BeNil())
	})

	It("skips pods that explicitly set dnsPolicy=None", func() {
		ndots := "2"
		pod := makePodWithImage(uniquePodName(), "default", nil)
		pod.Spec.DNSPolicy = corev1.DNSNone
		pod.Spec.DNSConfig = &corev1.PodDNSConfig{
			Nameservers: []string{"9.9.9.9"},
			Options:     []corev1.PodDNSConfigOption{{Name: "ndots", Value: &ndots}},
		}
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: pod.Name, Namespace: "default"}, &fetched)).To(Succeed())
		Expect(fetched.Spec.DNSConfig.Nameservers).To(Equal([]string{"9.9.9.9"}))
		Expect(fetched.Spec.DNSConfig.Options).To(HaveLen(1))
	})

	It("uses the subnet selected by the per-Pod annotation", func() {
		// Create a fresh Vpc so the Subnet validation webhook lets us
		// add a non-default Subnet.
		vpcName := webhookUniqueTestName("vpc")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
			Spec:       juneauv1alpha1.VpcSpec{EnableService: true},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: vpcName}})
		})
		// Mark the Vpc Ready so the Subnet validation webhook accepts
		// the Subnet that follows.
		var vpc juneauv1alpha1.Vpc
		Eventually(func(g Gomega) {
			g.Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
		}).Should(Succeed())
		vpc.Status.VpcID = 7
		vpc.Status.MainRouteTable = vpcName
		meta.SetStatusCondition(&vpc.Status.Conditions, metav1.Condition{
			Type:   juneauv1alpha1.VpcStatusReady,
			Status: metav1.ConditionTrue,
			Reason: "ReconcileSucceeded",
		})
		Expect(webhookK8sClient.Status().Update(context.Background(), &vpc)).To(Succeed())

		subnetName := webhookUniqueTestName("subnet")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnetName},
			Spec: juneauv1alpha1.SubnetSpec{
				Vpc:  vpcName,
				CIDR: fmt.Sprintf("10.%d.0.0/24", time.Now().UnixNano()%200+30),
			},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: subnetName}})
		})
		var subnet juneauv1alpha1.Subnet
		Eventually(func(g Gomega) {
			g.Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: subnetName}, &subnet)).To(Succeed())
		}).Should(Succeed())
		subnet.Status.DNS = "10.42.0.2"
		subnet.Status.DNSMAC = "02:42:0a:2a:00:02"
		subnet.Status.Gateway = "10.42.0.1"
		subnet.Status.GatewayMAC = "02:42:0a:2a:00:01"
		subnet.Status.VNI = 99
		meta.SetStatusCondition(&subnet.Status.Conditions, metav1.Condition{
			Type:               juneauv1alpha1.SubnetStatusReady,
			Status:             metav1.ConditionTrue,
			Reason:             "ReconcileSucceeded",
			ObservedGeneration: subnet.Generation,
		})
		Expect(webhookK8sClient.Status().Update(context.Background(), &subnet)).To(Succeed())

		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			PodAnnotationSubnet: subnetName,
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: pod.Name, Namespace: "default"}, &fetched)).To(Succeed())
		Expect(fetched.Spec.DNSPolicy).To(Equal(corev1.DNSNone))
		Expect(fetched.Spec.DNSConfig).NotTo(BeNil())
		Expect(fetched.Spec.DNSConfig.Nameservers).To(ContainElement("10.42.0.2"))
	})

	It("preserves user-supplied search list when injecting", func() {
		_ = patchDefaultSubnetDNS()
		pod := makePodWithImage(uniquePodName(), "default", nil)
		pod.Spec.DNSConfig = &corev1.PodDNSConfig{
			Searches: []string{"custom.example.com"},
		}
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: pod.Name, Namespace: "default"}, &fetched)).To(Succeed())
		Expect(fetched.Spec.DNSPolicy).To(Equal(corev1.DNSNone))
		Expect(fetched.Spec.DNSConfig.Searches).To(Equal([]string{"custom.example.com"}))
	})
})
