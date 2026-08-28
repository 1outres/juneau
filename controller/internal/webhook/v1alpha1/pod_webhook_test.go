package v1alpha1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	probeconfig "github.com/1outres/juneau/controller/pkg/probe"
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
// juneauv1alpha1.PodAnnotationSubnet value.
//
// All resources clean themselves up via DeferCleanup so each spec
// remains hermetic across the parallel envtest run.
func customSubnetFixture() juneauv1alpha1.Subnet {
	GinkgoHelper()
	return subnetFixtureForVpc(juneauv1alpha1.VpcSpec{Service: &juneauv1alpha1.VpcServiceSpec{Consume: true}})
}

// enforcingSubnetFixture is customSubnetFixture for a Vpc that demands a
// SecurityGroup on every NIC that joins it.
func enforcingSubnetFixture() juneauv1alpha1.Subnet {
	GinkgoHelper()
	return subnetFixtureForVpc(juneauv1alpha1.VpcSpec{EnforceSecurityGroups: true})
}

func subnetFixtureForVpc(vpcSpec juneauv1alpha1.VpcSpec) juneauv1alpha1.Subnet {
	GinkgoHelper()
	vpcName := webhookUniqueTestName("vpc")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
		ObjectMeta: metav1.ObjectMeta{Name: vpcName},
		Spec:       vpcSpec,
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
			juneauv1alpha1.PodAnnotationSubnet: subnet.Name,
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
			juneauv1alpha1.PodAnnotationSubnet:        subnet.Name,
			juneauv1alpha1.PodAnnotationDNSInjectSkip: "true",
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
			juneauv1alpha1.PodAnnotationSubnet: subnet.Name,
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
			juneauv1alpha1.PodAnnotationSubnet: subnet.Name,
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
			juneauv1alpha1.PodAnnotationSubnet: subnet.Name,
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
			juneauv1alpha1.PodAnnotationSubnet: subnet.Name,
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

var _ = Describe("Pod network probe rewrite", func() {
	It("rewrites startup, readiness, and liveness network probes without changing timing", func() {
		service := "worker"
		pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "server",
			Image: "example/server:1",
			Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
			StartupProbe: &corev1.Probe{
				ProbeHandler:        corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(8080)}},
				InitialDelaySeconds: 3, PeriodSeconds: 4, FailureThreshold: 5,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler:   corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromString("http")}},
				TimeoutSeconds: 2, SuccessThreshold: 2,
			},
			LivenessProbe: &corev1.Probe{
				ProbeHandler:  corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: 9090, Service: &service}},
				PeriodSeconds: 7,
			},
		}}}}

		Expect(rewriteNetworkProbes(pod, probeconfig.DefaultProxyPort)).To(Succeed())
		container := &pod.Spec.Containers[0]
		for _, item := range []*corev1.Probe{container.StartupProbe, container.ReadinessProbe, container.LivenessProbe} {
			Expect(item.HTTPGet).NotTo(BeNil())
			Expect(item.HTTPGet.Host).To(Equal("127.0.0.1"))
			Expect(item.HTTPGet.Port.IntVal).To(Equal(probeconfig.DefaultProxyPort))
			Expect(item.HTTPGet.Path).To(HavePrefix(probeconfig.EndpointPathPrefix))
			Expect(item.Exec).To(BeNil())
			Expect(item.TCPSocket).To(BeNil())
			Expect(item.GRPC).To(BeNil())
		}
		Expect(container.StartupProbe.InitialDelaySeconds).To(Equal(int32(3)))
		Expect(container.StartupProbe.PeriodSeconds).To(Equal(int32(4)))
		Expect(container.StartupProbe.FailureThreshold).To(Equal(int32(5)))
		Expect(container.ReadinessProbe.TimeoutSeconds).To(Equal(int32(2)))
		Expect(container.ReadinessProbe.SuccessThreshold).To(Equal(int32(2)))
		Expect(container.LivenessProbe.PeriodSeconds).To(Equal(int32(7)))
		Expect(pod.Spec.InitContainers).To(BeEmpty())
		Expect(pod.Spec.Volumes).To(BeEmpty())
		Expect(container.VolumeMounts).To(BeEmpty())
		Expect(pod.Annotations).To(HaveKeyWithValue(probeconfig.AnnotationRewriteVersion, probeconfig.RewriteVersion))
		configs, err := probeconfig.Parse(pod.Annotations[probeconfig.AnnotationConfigs])
		Expect(err).NotTo(HaveOccurred())
		Expect(configs).To(HaveLen(3))

		// Admission retries must not allocate new tokens.
		encoded := pod.Annotations[probeconfig.AnnotationConfigs]
		Expect(rewriteNetworkProbes(pod, probeconfig.DefaultProxyPort)).To(Succeed())
		Expect(pod.Annotations[probeconfig.AnnotationConfigs]).To(Equal(encoded))

		// Reinvocation must also handle a sidecar added by a later webhook.
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
			Name: "sidecar",
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(15021)},
			}},
		})
		Expect(rewriteNetworkProbes(pod, probeconfig.DefaultProxyPort)).To(Succeed())
		Expect(pod.Spec.Containers[1].ReadinessProbe.HTTPGet.Host).To(Equal("127.0.0.1"))
		configs, err = probeconfig.Parse(pod.Annotations[probeconfig.AnnotationConfigs])
		Expect(err).NotTo(HaveOccurred())
		Expect(configs).To(HaveLen(4))
	})

	It("leaves an explicit exec probe unchanged", func() {
		pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "server",
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{Command: []string{"/bin/check"}},
			}},
		}}}}
		Expect(rewriteNetworkProbes(pod, probeconfig.DefaultProxyPort)).To(Succeed())
		Expect(pod.Spec.Containers[0].ReadinessProbe.Exec.Command).To(Equal([]string{"/bin/check"}))
		Expect(pod.Annotations).NotTo(HaveKey(probeconfig.AnnotationRewriteVersion))
	})

	It("rewrites custom-Vpc Pod probes when the controller option is enabled", func() {
		subnet := customSubnetFixture()
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: subnet.Name,
		})
		pod.Spec.Containers[0].ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromInt32(8080)},
		}}
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pod), &fetched)).To(Succeed())
		Expect(fetched.Spec.Containers[0].ReadinessProbe.HTTPGet.Host).To(Equal("127.0.0.1"))
		Expect(fetched.Annotations).To(HaveKeyWithValue(probeconfig.AnnotationRewriteVersion, probeconfig.RewriteVersion))
	})

	It("leaves default-network Pod probes unchanged", func() {
		pod := makePodWithImage(uniquePodName(), "default", nil)
		pod.Spec.Containers[0].ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromInt32(8080)},
		}}
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pod), &fetched)).To(Succeed())
		Expect(fetched.Spec.Containers[0].ReadinessProbe.HTTPGet).NotTo(BeNil())
		Expect(fetched.Annotations).NotTo(HaveKey(probeconfig.AnnotationRewriteVersion))
	})

	It("leaves explicit-host probes unchanged in compatibility mode", func() {
		subnet := customSubnetFixture()
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: subnet.Name,
		})
		pod.Spec.Containers[0].ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Host: "example.com", Path: "/", Port: intstr.FromInt32(443)},
		}}
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})

		var fetched corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(pod), &fetched)).To(Succeed())
		probe := fetched.Spec.Containers[0].ReadinessProbe
		Expect(probe.HTTPGet.Host).To(Equal("example.com"))
		Expect(probe.HTTPGet.Port.IntVal).To(Equal(int32(443)))
		Expect(fetched.Annotations).NotTo(HaveKey(probeconfig.AnnotationRewriteVersion))
		Expect(fetched.Annotations).NotTo(HaveKey(probeconfig.AnnotationConfigs))
	})

	It("skips explicit-host probes but still rewrites the remaining ones", func() {
		pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "server",
			StartupProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Host: "example.com", Path: "/up", Port: intstr.FromInt32(443)},
			}},
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{Host: "10.0.0.9", Port: intstr.FromInt32(9000)},
			}},
			LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)},
			}},
		}}}}

		Expect(rewriteNetworkProbes(pod, probeconfig.DefaultProxyPort)).To(Succeed())
		container := &pod.Spec.Containers[0]
		Expect(container.StartupProbe.HTTPGet.Host).To(Equal("example.com"))
		Expect(container.StartupProbe.HTTPGet.Path).To(Equal("/up"))
		Expect(container.ReadinessProbe.TCPSocket).NotTo(BeNil())
		Expect(container.ReadinessProbe.TCPSocket.Host).To(Equal("10.0.0.9"))
		Expect(container.LivenessProbe.HTTPGet.Host).To(Equal("127.0.0.1"))
		Expect(container.LivenessProbe.HTTPGet.Path).To(HavePrefix(probeconfig.EndpointPathPrefix))

		Expect(pod.Annotations).To(HaveKeyWithValue(probeconfig.AnnotationRewriteVersion, probeconfig.RewriteVersion))
		configs, err := probeconfig.Parse(pod.Annotations[probeconfig.AnnotationConfigs])
		Expect(err).NotTo(HaveOccurred())
		Expect(configs).To(HaveLen(1))
		for _, config := range configs {
			Expect(config.Path).To(Equal("/healthz"))
		}
	})

	It("leaves a Pod untouched when every probe has an explicit host", func() {
		pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "server",
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{Host: "10.0.0.9", Port: intstr.FromInt32(9000)},
			}},
		}}}}
		Expect(rewriteNetworkProbes(pod, probeconfig.DefaultProxyPort)).To(Succeed())
		Expect(pod.Spec.Containers[0].ReadinessProbe.TCPSocket).NotTo(BeNil())
		Expect(pod.Spec.Containers[0].ReadinessProbe.HTTPGet).To(BeNil())
		Expect(pod.Annotations).NotTo(HaveKey(probeconfig.AnnotationRewriteVersion))
		Expect(pod.Annotations).NotTo(HaveKey(probeconfig.AnnotationConfigs))
	})

	It("rewrites probes on restartable init containers", func() {
		always := corev1.ContainerRestartPolicyAlways
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}, Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:          "sidecar",
				RestartPolicy: &always,
				StartupProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
					TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(9090)},
				}},
			}},
			Containers: []corev1.Container{{Name: "main"}},
		}}
		Expect(rewriteNetworkProbes(pod, probeconfig.DefaultProxyPort)).To(Succeed())
		Expect(pod.Spec.InitContainers[0].StartupProbe.HTTPGet.Host).To(Equal("127.0.0.1"))
		Expect(pod.Spec.InitContainers).To(HaveLen(1))
	})
})

var _ = Describe("Pod SecurityGroup validating webhook", func() {
	It("rejects a Pod referencing a nonexistent SG", func() {
		subnet := customSubnetFixture()
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:         subnet.Name,
			juneauv1alpha1.PodAnnotationSecurityGroups: "no-such-sg",
		})
		err := webhookK8sClient.Create(context.Background(), pod)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not exist"))
	})

	It("accepts a Pod whose SG list is empty", func() {
		subnet := customSubnetFixture()
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: subnet.Name,
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})
	})

	It("rejects SG belonging to a different Vpc", func() {
		subnet := customSubnetFixture()
		// SG in default Vpc; Pod is in custom Vpc → reject.
		sgName := webhookUniqueTestName("sg")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: sgName},
			Spec:       juneauv1alpha1.SecurityGroupSpec{Vpc: "default"},
		})).To(Succeed())

		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:         subnet.Name,
			juneauv1alpha1.PodAnnotationSecurityGroups: sgName,
		})
		err := webhookK8sClient.Create(context.Background(), pod)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("expected"))
	})

	It("accepts SG in same Vpc and propagates to NetworkInterface (via PodReconciler is out of scope; just admission here)", func() {
		subnet := customSubnetFixture()
		sgName := webhookUniqueTestName("sg")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: sgName},
			Spec:       juneauv1alpha1.SecurityGroupSpec{Vpc: subnet.Spec.Vpc},
		})).To(Succeed())
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:         subnet.Name,
			juneauv1alpha1.PodAnnotationSecurityGroups: sgName,
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})
	})

	It("rejects more than the per-NIC SG ceiling", func() {
		subnet := customSubnetFixture()
		var names []string
		for i := 0; i < juneauv1alpha1.PodSecurityGroupsMax+1; i++ {
			n := webhookUniqueTestName("sg")
			Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
				ObjectMeta: metav1.ObjectMeta{Name: n},
				Spec:       juneauv1alpha1.SecurityGroupSpec{Vpc: subnet.Spec.Vpc},
			})).To(Succeed())
			names = append(names, n)
		}
		ann := ""
		for i, n := range names {
			if i > 0 {
				ann += ","
			}
			ann += n
		}
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:         subnet.Name,
			juneauv1alpha1.PodAnnotationSecurityGroups: ann,
		})
		err := webhookK8sClient.Create(context.Background(), pod)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("at most"))
	})

	It("requires SG when Vpc.spec.enforceSecurityGroups=true", func() {
		// Build a custom Vpc with enforceSecurityGroups, plus a Subnet
		// inside it. We deliberately avoid customSubnetFixture so we can
		// flip enforceSecurityGroups before the Pod is created.
		vpcName := webhookUniqueTestName("vpc")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Vpc{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName},
			Spec:       juneauv1alpha1.VpcSpec{EnforceSecurityGroups: true},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Vpc{ObjectMeta: metav1.ObjectMeta{Name: vpcName}})
		})

		subnetName := webhookUniqueTestName("subnet")
		// CIDR octet outside the Service CIDR (10.96.0.0/12) — note we picked
		// a wide-enough offset to remain non-overlapping.
		octet := time.Now().UnixNano()%30 + 200
		cidr := fmt.Sprintf("10.%d.0.0/24", octet)
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{Name: subnetName},
			Spec:       juneauv1alpha1.SubnetSpec{Vpc: vpcName, CIDR: cidr},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: subnetName}})
		})

		// Pod with no SG annotation → rejected.
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: subnetName,
		})
		err := webhookK8sClient.Create(context.Background(), pod)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("enforceSecurityGroups"))

		// Same Pod with a valid SG annotation → succeeds.
		sgName := webhookUniqueTestName("sg")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: sgName},
			Spec:       juneauv1alpha1.SecurityGroupSpec{Vpc: vpcName},
		})).To(Succeed())
		pod2 := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:         subnetName,
			juneauv1alpha1.PodAnnotationSecurityGroups: sgName,
		})
		Expect(webhookK8sClient.Create(context.Background(), pod2)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod2.Name, Namespace: "default"}})
		})
	})
})

var _ = Describe("Pod extra NIC validating webhook", func() {
	newAttachment := func(ifName, subnet string, securityGroups ...string) string {
		GinkgoHelper()
		attachment := juneauv1alpha1.PodNetworkAttachment{
			Interface:      ifName,
			Subnet:         subnet,
			SecurityGroups: securityGroups,
		}
		encoded, err := json.Marshal([]juneauv1alpha1.PodNetworkAttachment{attachment})
		Expect(err).NotTo(HaveOccurred())
		return string(encoded)
	}

	createSecurityGroup := func(vpc string) string {
		GinkgoHelper()
		name := webhookUniqueTestName("sg")
		Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       juneauv1alpha1.SecurityGroupSpec{Vpc: vpc},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Name: name}})
		})
		return name
	}

	createPod := func(annotations map[string]string) error {
		pod := makePodWithImage(uniquePodName(), "default", annotations)
		err := webhookK8sClient.Create(context.Background(), pod)
		if err == nil {
			DeferCleanup(func() {
				_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
			})
		}
		return err
	}

	It("accepts an extra NIC on an existing Subnet", func() {
		primary := customSubnetFixture()
		extra := customSubnetFixture()
		Expect(createPod(map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: newAttachment("eth1", extra.Name),
		})).To(Succeed())
	})

	It("rejects a networks annotation that is not a JSON list", func() {
		primary := customSubnetFixture()
		err := createPod(map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: "eth1=db",
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(juneauv1alpha1.PodAnnotationNetworks))
	})

	It("rejects an extra NIC that claims the primary interface name", func() {
		primary := customSubnetFixture()
		err := createPod(map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: newAttachment("eth0", primary.Name),
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("eth0"))
	})

	It("rejects two extra NICs sharing an interface name", func() {
		primary := customSubnetFixture()
		err := createPod(map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(
				`[{"interface":"eth1","subnet":%q},{"interface":"eth1","subnet":%q}]`, primary.Name, primary.Name),
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Duplicate"))
	})

	It("rejects an extra NIC whose Subnet does not exist", func() {
		primary := customSubnetFixture()
		err := createPod(map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: newAttachment("eth1", "no-such-subnet"),
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not exist"))
	})

	It("rejects a SecurityGroup that belongs to another Vpc than the extra NIC", func() {
		primary := customSubnetFixture()
		extra := customSubnetFixture()
		err := createPod(map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: newAttachment("eth1", extra.Name, createSecurityGroup(primary.Spec.Vpc)),
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(extra.Spec.Vpc))
	})

	It("accepts a SecurityGroup that belongs to the Vpc of the extra NIC", func() {
		primary := customSubnetFixture()
		extra := customSubnetFixture()
		Expect(createPod(map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: newAttachment("eth1", extra.Name, createSecurityGroup(extra.Spec.Vpc)),
		})).To(Succeed())
	})

	It("applies enforceSecurityGroups per NIC", func() {
		primary := customSubnetFixture()
		enforcing := enforcingSubnetFixture()

		err := createPod(map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: newAttachment("eth1", enforcing.Name),
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("enforceSecurityGroups"))

		Expect(createPod(map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: newAttachment("eth1", enforcing.Name, createSecurityGroup(enforcing.Spec.Vpc)),
		})).To(Succeed())
	})

	It("injects the DNS of the primary NIC, not of an extra one", func() {
		primary := customSubnetFixture()
		extra := customSubnetFixture()
		name := uniquePodName()
		pod := makePodWithImage(name, "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet:   primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: newAttachment("eth1", extra.Name),
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}})
		})

		var created corev1.Pod
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: name}, &created)).To(Succeed())
		Expect(created.Spec.DNSPolicy).To(Equal(corev1.DNSNone))
		Expect(created.Spec.DNSConfig).NotTo(BeNil())
		Expect(created.Spec.DNSConfig.Nameservers).To(ContainElement(primary.Status.DNS))
		Expect(created.Spec.DNSConfig.Nameservers).NotTo(ContainElement(extra.Status.DNS))
	})
})

var _ = Describe("Pod overlapping NIC subnets", func() {
	It("rejects two NICs whose subnets overlap", func() {
		primary := customSubnetFixture()
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(
				`[{"interface":"eth1","subnet":%q}]`, primary.Name),
		})
		err := webhookK8sClient.Create(context.Background(), pod)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlap"))
	})

	It("accepts two NICs on subnets that do not overlap", func() {
		primary := customSubnetFixture()
		extra := customSubnetFixture()
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(
				`[{"interface":"eth1","subnet":%q}]`, extra.Name),
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})
	})
})

var _ = Describe("Pod NIC on an L2Network", func() {
	It("accepts an extra NIC on an L2Network with no CIDR", func() {
		primary := customSubnetFixture()
		l2Name := createPodWebhookL2Network(primary.Spec.Vpc, "")

		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(
				`[{"interface":"eth1","l2Network":%q}]`, l2Name),
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})
	})

	It("rejects an extra NIC whose L2Network does not exist", func() {
		primary := customSubnetFixture()
		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(
				`[{"interface":"eth1","l2Network":%q}]`, webhookUniqueTestName("missing-l2net")),
		})
		err := webhookK8sClient.Create(context.Background(), pod)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("L2Network"))
		Expect(err.Error()).To(ContainSubstring("does not exist"))
	})

	It("rejects a SecurityGroup from a Vpc other than the one of the L2Network", func() {
		primary := customSubnetFixture()
		other := customSubnetFixture()
		// The segment needs a gateway, or the NIC is rejected for
		// naming a SecurityGroup that could never be consulted before
		// the Vpc of that group is ever looked at.
		l2Name := createPodWebhookGatewayL2Network(primary.Spec.Vpc)
		sgName := createPodWebhookSecurityGroup(other.Spec.Vpc)

		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(
				`[{"interface":"eth1","l2Network":%q,"securityGroups":[%q]}]`, l2Name, sgName),
		})
		err := webhookK8sClient.Create(context.Background(), pod)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(sgName))
		Expect(err.Error()).To(ContainSubstring("belongs to Vpc"))
	})

	// Two NICs of one pod may sit in different Vpcs, and Vpcs are free
	// to reuse a prefix, so this is the only way the two can collide.
	It("rejects an L2Network whose CIDR overlaps the Subnet of another NIC", func() {
		primary := customSubnetFixture()
		l2Name := createPodWebhookL2Network(customSubnetFixture().Spec.Vpc, primary.Spec.CIDR)

		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(
				`[{"interface":"eth1","l2Network":%q}]`, l2Name),
		})
		err := webhookK8sClient.Create(context.Background(), pod)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("overlap"))
	})

	It("leaves an L2Network with no CIDR out of the overlap check", func() {
		primary := customSubnetFixture()
		first := createPodWebhookL2Network(primary.Spec.Vpc, "")
		second := createPodWebhookL2Network(primary.Spec.Vpc, "")

		pod := makePodWithImage(uniquePodName(), "default", map[string]string{
			juneauv1alpha1.PodAnnotationSubnet: primary.Name,
			juneauv1alpha1.PodAnnotationNetworks: fmt.Sprintf(
				`[{"interface":"eth1","l2Network":%q},{"interface":"eth2","l2Network":%q}]`, first, second),
		})
		Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: "default"}})
		})
	})
})

// createPodWebhookL2Network builds a segment inside an existing Vpc. The
// CIDR is passed in so a spec can decide whether the segment takes part
// in the NIC overlap check at all.
func createPodWebhookL2Network(vpcName, cidr string) string {
	GinkgoHelper()
	name := webhookUniqueTestName("l2net")
	l2 := newWebhookL2Network(name, vpcName)
	l2.Spec.CIDR = cidr
	Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())
	DeferCleanup(func() {
		_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.L2Network{ObjectMeta: metav1.ObjectMeta{Name: name}})
	})
	return name
}

// createPodWebhookGatewayL2Network builds a segment that can carry a
// SecurityGroup: one with a CIDR and a gateway for the rules to be read
// at.
func createPodWebhookGatewayL2Network(vpcName string) string {
	GinkgoHelper()
	name := webhookUniqueTestName("l2net")
	l2 := newWebhookL2Network(name, vpcName)
	l2.Spec.CIDR = fmt.Sprintf("10.%d.0.0/24", time.Now().UnixNano()%20+232)
	l2.Spec.Gateway = &juneauv1alpha1.L2NetworkGateway{}
	Expect(webhookK8sClient.Create(context.Background(), l2)).To(Succeed())
	DeferCleanup(func() {
		_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.L2Network{ObjectMeta: metav1.ObjectMeta{Name: name}})
	})
	return name
}

func createPodWebhookSecurityGroup(vpcName string) string {
	GinkgoHelper()
	name := webhookUniqueTestName("sg")
	Expect(webhookK8sClient.Create(context.Background(), &juneauv1alpha1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       juneauv1alpha1.SecurityGroupSpec{Vpc: vpcName},
	})).To(Succeed())
	DeferCleanup(func() {
		_ = webhookK8sClient.Delete(context.Background(), &juneauv1alpha1.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Name: name}})
	})
	return name
}
