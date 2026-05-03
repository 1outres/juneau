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
// fixed DNS / DNSMAC values. Only used to verify the
// "default-Vpc skip" rule: with a real DNS VIP present, the webhook
// would still leave the Pod alone because the Subnet is owned by the
// default Vpc.
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

// customSubnetFixture creates a Vpc + Subnet pair with status patched
// the way the SubnetReconciler would have, so the Pod webhook sees a
// non-default Vpc with a usable DNS VIP. Returns the Subnet — callers
// pin to its DNS VIP for assertions and use its name as the
// PodAnnotationSubnet value.
//
// All resources clean themselves up via DeferCleanup so each spec
// remains hermetic across the parallel envtest run.
func customSubnetFixture() juneauv1alpha1.Subnet {
	GinkgoHelper()
	vpcName := webhookUniqueTestName("vpc")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		Spec:       juneauv1alpha1.VpcSpec{EnableService: true},
	})).To(Succeed())
	DeferCleanup(func() {
		_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: vpcName}})
	})
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
	// Avoid the Service CIDR 10.96.0.0/12 (10.96-111.x.x); Vpc enables Service so
	// overlapping Subnets are rejected by the validating webhook.
	octet := time.Now().UnixNano()%100 + 112
	cidr := fmt.Sprintf("10.%d.0.0/24", octet)
	dnsVIP := fmt.Sprintf("10.%d.0.2", octet)
	gateway := fmt.Sprintf("10.%d.0.1", octet)
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: subnetName},
		Spec: juneauv1alpha1.SubnetSpec{
			Vpc:  vpcName,
			CIDR: cidr,
		},
	})).To(Succeed())
	DeferCleanup(func() {
		_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: subnetName}})
	})

	var subnet juneauv1alpha1.Subnet
	Eventually(func(g Gomega) {
		g.Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: subnetName}, &subnet)).To(Succeed())
	}).Should(Succeed())
	subnet.Status.DNS = dnsVIP
	subnet.Status.DNSMAC = "02:42:0a:2a:00:02"
	subnet.Status.Gateway = gateway
	subnet.Status.GatewayMAC = "02:42:0a:2a:00:01"
	subnet.Status.VNI = 99
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
		subnet := customSubnetFixture()

		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			PodAnnotationSubnet: subnet.Name,
		})
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

	It("skips Pods whose Subnet is owned by the default Vpc", func() {
		// Even with a populated DNS VIP on the default Subnet, Pods
		// landing on it must keep ClusterFirst (kube-dns) — the
		// default Vpc has no isolation so per-Subnet Juneau DNS adds
		// risk without functional benefit.
		_ = patchDefaultSubnetDNS()

		// No PodAnnotationSubnet → falls back to "default" Subnet.
		pod := makePodWithImage(uniquePodName(), "default", nil)
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: pod.Name, Namespace: "default"}, &fetched)).To(Succeed())
		Expect(fetched.Spec.DNSPolicy).NotTo(Equal(corev1.DNSNone))
		Expect(fetched.Spec.DNSConfig).To(BeNil())
	})

	It("respects per-Pod opt-out annotation", func() {
		// Use a custom-Vpc Subnet to make sure the webhook would
		// otherwise inject — the opt-out annotation is what stops it.
		subnet := customSubnetFixture()

		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			PodAnnotationSubnet:        subnet.Name,
			PodAnnotationDNSInjectSkip: "true",
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: pod.Name, Namespace: "default"}, &fetched)).To(Succeed())
		Expect(fetched.Spec.DNSPolicy).NotTo(Equal(corev1.DNSNone))
		Expect(fetched.Spec.DNSConfig).To(BeNil())
	})

	It("skips hostNetwork pods", func() {
		subnet := customSubnetFixture()
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			PodAnnotationSubnet: subnet.Name,
		})
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
		subnet := customSubnetFixture()
		ndots := "2"
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			PodAnnotationSubnet: subnet.Name,
		})
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
		subnet := customSubnetFixture()

		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			PodAnnotationSubnet: subnet.Name,
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: pod.Name, Namespace: "default"}, &fetched)).To(Succeed())
		Expect(fetched.Spec.DNSPolicy).To(Equal(corev1.DNSNone))
		Expect(fetched.Spec.DNSConfig).NotTo(BeNil())
		Expect(fetched.Spec.DNSConfig.Nameservers).To(ContainElement(subnet.Status.DNS))
	})

	It("preserves user-supplied search list when injecting", func() {
		subnet := customSubnetFixture()
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			PodAnnotationSubnet: subnet.Name,
		})
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
