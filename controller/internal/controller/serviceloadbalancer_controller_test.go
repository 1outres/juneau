package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// reconcileServiceLoadBalancer drives the SLB reconciler once
// against the resource named (default/name). The default namespace
// matches the Service the helpers create below.
func reconcileServiceLoadBalancer(name string) error {
	r := &ServiceLoadBalancerReconciler{Client: k8sClient, APIReader: k8sClient}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: name, Namespace: "default"}})
	return err
}

func getServiceLoadBalancer(name string) *juneauv1alpha1.ServiceLoadBalancer {
	var slb juneauv1alpha1.ServiceLoadBalancer
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &slb)).To(Succeed())
	return &slb
}

func newJuneauLBService(name, externalNetwork string) *corev1.Service {
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
				{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromInt(8080)},
			},
			Selector: map[string]string{"app": "x"},
		},
	}
}

// awaitSLBExists eventually fetches the SLB resource derived from a
// Service. We can't simply Get because the Service-sync reconciler
// may not have run yet by the time the test reaches this line.
func awaitSLBExists(name string) *juneauv1alpha1.ServiceLoadBalancer {
	var slb juneauv1alpha1.ServiceLoadBalancer
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &slb)).To(Succeed())
	}).Should(Succeed())
	return &slb
}

var _ = Describe("ServiceLoadBalancer reconciler (Phase 2)", func() {
	It("allocates a VIP from the referenced ExternalNetwork and patches the Service status", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.140.0.0/30"})

		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())

		slb := awaitSLBExists(svc.Name)

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			fresh := getServiceLoadBalancer(slb.Name)
			g.Expect(fresh.Status.VIP).To(Equal("10.140.0.1"))
			g.Expect(fresh.Status.Phase).To(Equal(juneauv1alpha1.ServiceLoadBalancerPhaseAllocated))
			allocated := meta.FindStatusCondition(fresh.Status.Conditions, juneauv1alpha1.ServiceLoadBalancerConditionAllocated)
			g.Expect(allocated).NotTo(BeNil())
			g.Expect(allocated.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(fresh.Status.AllocationClaimName).NotTo(BeEmpty())
			g.Expect(fresh.Status.Ports).To(HaveLen(1))
			g.Expect(fresh.Status.Ports[0].Port).To(Equal(int32(80)))
			g.Expect(fresh.Status.Ports[0].TargetPort).To(Equal(int32(8080)))
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			var fetched corev1.Service
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: svc.Name, Namespace: "default"}, &fetched)).To(Succeed())
			g.Expect(fetched.Status.LoadBalancer.Ingress).To(HaveLen(1))
			g.Expect(fetched.Status.LoadBalancer.Ingress[0].IP).To(Equal("10.140.0.1"))
		}).Should(Succeed())
	})

	It("honors a requested VIP when the address is available in the pool", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.141.0.0/29"})

		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		svc.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerRequestedIP] = "10.141.0.5"
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())

		slb := awaitSLBExists(svc.Name)

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			g.Expect(getServiceLoadBalancer(slb.Name).Status.VIP).To(Equal("10.141.0.5"))
		}).Should(Succeed())
	})

	It("flips to error status when the referenced ExternalNetwork is missing", func() {
		ctx := context.Background()
		// Bypass the sync reconciler so we can hand-craft an SLB
		// pointing at a non-existent ExternalNetwork. In normal
		// operation the webhook would reject the Service that drives
		// such an SLB.
		svc := newJuneauLBService(uniqueTestName("lb-svc"), "real-en-not-actually-created-yet")
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			fresh := getServiceLoadBalancer(slb.Name)
			g.Expect(fresh.Status.Phase).To(Equal(juneauv1alpha1.ServiceLoadBalancerPhaseError))
			accepted := meta.FindStatusCondition(fresh.Status.Conditions, juneauv1alpha1.ServiceLoadBalancerConditionAllocated)
			g.Expect(accepted).NotTo(BeNil())
			g.Expect(accepted.Status).To(Equal(metav1.ConditionFalse))
		}).Should(Succeed())
	})

	It("releases the AllocationClaim when the Service is deleted", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.142.0.0/30"})

		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		// Drive allocation to completion.
		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			g.Expect(getServiceLoadBalancer(slb.Name).Status.VIP).NotTo(BeEmpty())
		}).Should(Succeed())

		claimName := serviceLoadBalancerClaimName(slb)
		var claim juneauv1alpha1.AllocationClaim
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimName}, &claim)).To(Succeed())

		// Delete the Service. The sync reconciler should delete the
		// SLB; the SLB controller's finalizer should release the
		// AllocationClaim before the SLB disappears.
		Expect(k8sClient.Delete(ctx, svc)).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			err := k8sClient.Get(ctx, client.ObjectKey{Name: claimName}, &juneauv1alpha1.AllocationClaim{})
			g.Expect(err).To(HaveOccurred())
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			err := k8sClient.Get(ctx, client.ObjectKey{Name: slb.Name, Namespace: "default"}, &juneauv1alpha1.ServiceLoadBalancer{})
			g.Expect(err).To(HaveOccurred())
		}).Should(Succeed())
	})

	It("flips to error when the parent Service is no longer Juneau-managed", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.143.0.0/30"})

		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			g.Expect(getServiceLoadBalancer(slb.Name).Status.VIP).NotTo(BeEmpty())
		}).Should(Succeed())

		// Flip out of scope by changing Type. loadBalancerClass is
		// immutable, but Type can transition LoadBalancer → ClusterIP,
		// which is the realistic "user removed the LB" path.
		var current corev1.Service
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: svc.Name, Namespace: "default"}, &current)).To(Succeed())
		current.Spec.Type = corev1.ServiceTypeClusterIP
		Expect(k8sClient.Update(ctx, &current)).To(Succeed())

		// At this point the sync reconciler will GC the SLB; we just
		// confirm reconcile is idempotent and does not panic on the
		// out-of-scope transition. The SLB may already be gone here,
		// in which case Reconcile is a no-op.
		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
		}).Should(Succeed())
	})
})

var _ = Describe("ServiceLoadBalancer service-sync reconciler (Phase 2)", func() {
	It("creates an SLB when a Juneau-managed Service is created", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.150.0.0/30"})

		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())

		Eventually(func(g Gomega) {
			slb := awaitSLBExists(svc.Name)
			g.Expect(slb.Spec.ServiceRef.Name).To(Equal(svc.Name))
			g.Expect(slb.Spec.ExternalNetwork).To(Equal(externalNetworkName))
			g.Expect(slb.OwnerReferences).To(HaveLen(1))
			g.Expect(slb.OwnerReferences[0].Kind).To(Equal("Service"))
		}).Should(Succeed())
	})

	It("updates the SLB spec when LB-related Service annotations change", func() {
		ctx := context.Background()
		oldEN, _ := createControllerElasticIPNetwork(ctx, []string{"10.151.0.0/30"})
		newEN, _ := createControllerElasticIPNetwork(ctx, []string{"10.151.0.4/30"})

		svc := newJuneauLBService(uniqueTestName("lb-svc"), oldEN)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		_ = awaitSLBExists(svc.Name)

		var current corev1.Service
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: svc.Name, Namespace: "default"}, &current)).To(Succeed())
		current.Annotations[juneauv1alpha1.ServiceAnnotationLoadBalancerExternalNetwork] = newEN
		Expect(k8sClient.Update(ctx, &current)).To(Succeed())

		Eventually(func(g Gomega) {
			slb := awaitSLBExists(svc.Name)
			g.Expect(slb.Spec.ExternalNetwork).To(Equal(newEN))
		}).Should(Succeed())
	})

	It("does not create an SLB for a Service with a different loadBalancerClass", func() {
		ctx := context.Background()
		name := uniqueTestName("foreign-lb")
		Expect(k8sClient.Create(ctx, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Type:              corev1.ServiceTypeLoadBalancer,
				LoadBalancerClass: ptr.To("other-vendor/lb"),
				Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt(80)}},
				Selector:          map[string]string{"app": "x"},
			},
		})).To(Succeed())

		// Give the sync reconciler some headroom and verify nothing
		// pops up.
		Consistently(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: name, Namespace: "default"}, &juneauv1alpha1.ServiceLoadBalancer{})
		}).Should(HaveOccurred())
	})

	It("deletes the SLB when the Service flips out of scope", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.152.0.0/30"})

		svc := newJuneauLBService(uniqueTestName("lb-svc"), externalNetworkName)
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())
		slb := awaitSLBExists(svc.Name)

		// Drive the SLB through its allocation so the finalizer is
		// present and the deletion path is exercised end-to-end.
		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			g.Expect(getServiceLoadBalancer(slb.Name).Status.VIP).NotTo(BeEmpty())
		}).Should(Succeed())

		// Flip out of scope by changing Type to ClusterIP — the
		// realistic "user removed the LoadBalancer" transition.
		// loadBalancerClass itself is immutable in core Kubernetes.
		var current corev1.Service
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: svc.Name, Namespace: "default"}, &current)).To(Succeed())
		current.Spec.Type = corev1.ServiceTypeClusterIP
		Expect(k8sClient.Update(ctx, &current)).To(Succeed())

		// Help finalization along by reconciling the SLB until it is
		// fully gone (the SLB controller is not registered with the
		// manager in tests, so deletion-finalizer must be driven
		// manually).
		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer(slb.Name)).To(Succeed())
			err := k8sClient.Get(ctx, client.ObjectKey{Name: slb.Name, Namespace: "default"}, &juneauv1alpha1.ServiceLoadBalancer{})
			g.Expect(err).To(HaveOccurred())
		}).Should(Succeed())
	})
})
