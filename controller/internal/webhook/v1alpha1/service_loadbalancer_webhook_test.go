package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// newJuneauLoadBalancerService returns a Service shaped like a
// minimum-viable Juneau-managed LoadBalancer. The Service uses the
// bootstrapped default Vpc (provider+consume on bootstrap) so tests
// don't need to hand-roll Vpc state; LB-specific tests only mutate
// the bits they care about.
func newJuneauLoadBalancerService(name, externalNetwork string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Annotations: map[string]string{
				juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork: externalNetwork,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass:     ptr.To(juneauv1alpha1.LoadBalancerClass),
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			Ports: []corev1.ServicePort{
				{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intOrString(8080)},
			},
			Selector: map[string]string{"app": "x"},
		},
	}
}

var _ = Describe("Service LoadBalancer webhook", func() {
	It("accepts a Juneau-managed LoadBalancer Service with valid configuration", func() {
		externalNetwork := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		name := webhookUniqueTestName("lb-svc")
		svc := newJuneauLoadBalancerService(name, externalNetwork)
		Expect(webhookK8sClient.Create(context.Background(), svc)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			})
		})
	})

	It("rejects Juneau-managed LoadBalancer Service missing the external-network annotation", func() {
		svc := newJuneauLoadBalancerService(webhookUniqueTestName("lb-svc"), "")
		delete(svc.Annotations, juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork)

		err := webhookK8sClient.Create(context.Background(), svc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("load-balancer-external-network"))
	})

	It("rejects Juneau-managed LoadBalancer Service when externalTrafficPolicy is Cluster", func() {
		externalNetwork := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		svc := newJuneauLoadBalancerService(webhookUniqueTestName("lb-svc"), externalNetwork)
		svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster

		err := webhookK8sClient.Create(context.Background(), svc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("externalTrafficPolicy=Local"))
	})

	It("rejects Juneau-managed LoadBalancer Service when externalTrafficPolicy is unset", func() {
		externalNetwork := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		svc := newJuneauLoadBalancerService(webhookUniqueTestName("lb-svc"), externalNetwork)
		svc.Spec.ExternalTrafficPolicy = ""

		err := webhookK8sClient.Create(context.Background(), svc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("externalTrafficPolicy=Local"))
	})

	It("rejects Juneau-managed LoadBalancer Service that references a missing ExternalNetwork", func() {
		svc := newJuneauLoadBalancerService(webhookUniqueTestName("lb-svc"), webhookUniqueTestName("missing-en"))

		err := webhookK8sClient.Create(context.Background(), svc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ExternalNetwork does not exist"))
	})

	It("rejects malformed requested IP", func() {
		externalNetwork := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		svc := newJuneauLoadBalancerService(webhookUniqueTestName("lb-svc"), externalNetwork)
		svc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerRequestedIP] = "not-an-ip"

		err := webhookK8sClient.Create(context.Background(), svc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("requested IP must be a valid IP address"))
	})

	It("rejects IPv6 requested IP in the initial release", func() {
		externalNetwork := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		svc := newJuneauLoadBalancerService(webhookUniqueTestName("lb-svc"), externalNetwork)
		svc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerRequestedIP] = "2001:db8::1"

		err := webhookK8sClient.Create(context.Background(), svc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("IPv4"))
	})

	It("rejects SCTP ports on Juneau-managed LoadBalancer Services", func() {
		externalNetwork := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		svc := newJuneauLoadBalancerService(webhookUniqueTestName("lb-svc"), externalNetwork)
		svc.Spec.Ports = []corev1.ServicePort{
			{Name: "sctp", Protocol: corev1.ProtocolSCTP, Port: 5000, TargetPort: intOrString(5000)},
		}

		err := webhookK8sClient.Create(context.Background(), svc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("supported values"))
	})

	It("accepts a valid requested IP literal", func() {
		externalNetwork := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		name := webhookUniqueTestName("lb-svc")
		svc := newJuneauLoadBalancerService(name, externalNetwork)
		svc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerRequestedIP] = "203.0.113.10"

		Expect(webhookK8sClient.Create(context.Background(), svc)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			})
		})
	})

	It("ignores LoadBalancer Services owned by a different class", func() {
		// Different loadBalancerClass → not Juneau-managed. The webhook
		// must accept the Service even when the LB-specific
		// preconditions (external network annotation, Local policy)
		// are absent.
		name := webhookUniqueTestName("lb-svc")
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:              corev1.ServiceTypeLoadBalancer,
				LoadBalancerClass: ptr.To("other-vendor/lb"),
				Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector:          map[string]string{"app": "x"},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), svc)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			})
		})
	})

	It("ignores LoadBalancer Services that leave loadBalancerClass empty", func() {
		// Empty class → not Juneau-managed by default. Some other
		// implementation (or none) handles it.
		name := webhookUniqueTestName("lb-svc")
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeLoadBalancer,
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		}
		Expect(webhookK8sClient.Create(context.Background(), svc)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			})
		})
	})

	It("re-validates LB annotations on update when the external-network annotation changes", func() {
		externalNetwork := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
		name := webhookUniqueTestName("lb-svc")
		svc := newJuneauLoadBalancerService(name, externalNetwork)
		Expect(webhookK8sClient.Create(context.Background(), svc)).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			})
		})

		var current corev1.Service
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &current)).To(Succeed())
		current.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork] = webhookUniqueTestName("missing-en")
		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced ExternalNetwork does not exist"))
	})
})
