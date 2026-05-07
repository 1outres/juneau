/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ServiceLoadBalancer controller", func() {
	It("ignores Services without the Juneau loadBalancerClass", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.140.0.0/30"})

		// type=ClusterIP — class string ignored
		clusterSvc := newControllerLBService(uniqueTestName("svc-cluster"), externalNetworkName)
		clusterSvc.Spec.Type = corev1.ServiceTypeClusterIP
		clusterSvc.Spec.LoadBalancerClass = nil
		Expect(k8sClient.Create(ctx, clusterSvc)).To(Succeed())

		// type=LoadBalancer with foreign class
		foreignSvc := newControllerLBService(uniqueTestName("svc-foreign"), externalNetworkName)
		foreignSvc.Spec.LoadBalancerClass = ptr.To("metallb.io/external")
		Expect(k8sClient.Create(ctx, foreignSvc)).To(Succeed())

		Expect(reconcileServiceLoadBalancer(clusterSvc.Namespace, clusterSvc.Name)).To(Succeed())
		Expect(reconcileServiceLoadBalancer(foreignSvc.Namespace, foreignSvc.Name)).To(Succeed())

		// Status should not be touched.
		Expect(getControllerService(clusterSvc.Namespace, clusterSvc.Name).Status.LoadBalancer.Ingress).To(BeEmpty())
		Expect(getControllerService(foreignSvc.Namespace, foreignSvc.Name).Status.LoadBalancer.Ingress).To(BeEmpty())

		// No AllocationClaim should have been created for either.
		var claims juneauv1alpha1.AllocationClaimList
		Expect(k8sClient.List(ctx, &claims)).To(Succeed())
		for i := range claims.Items {
			ref := claims.Items[i].Spec.ResourceRef
			if ref.Kind != "Service" {
				continue
			}
			Expect(ref.Name).NotTo(Equal(clusterSvc.Name))
			Expect(ref.Name).NotTo(Equal(foreignSvc.Name))
		}
	})

	It("allocates an IP from the referenced ExternalNetwork", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.141.0.0/30"})
		name := uniqueTestName("svc-lb")
		Expect(k8sClient.Create(ctx, newControllerLBService(name, externalNetworkName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer("default", name)).To(Succeed())
			svc := getControllerService("default", name)
			g.Expect(svc.Status.LoadBalancer.Ingress).To(HaveLen(1))
			g.Expect(svc.Status.LoadBalancer.Ingress[0].IP).To(Equal("10.141.0.1"))
			g.Expect(svc.Status.LoadBalancer.Ingress[0].IPMode).NotTo(BeNil())
			g.Expect(*svc.Status.LoadBalancer.Ingress[0].IPMode).To(Equal(corev1.LoadBalancerIPModeVIP))
		}).Should(Succeed())

		svc := getControllerService("default", name)
		ready := meta.FindStatusCondition(svc.Status.Conditions, "LoadBalancerReady")
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(ready.Reason).To(Equal("Allocated"))
	})

	It("honors loadbalancer-ip annotation", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.142.0.0/29"})
		name := uniqueTestName("svc-lb")
		svc := newControllerLBService(name, externalNetworkName)
		svc.Annotations[juneauv1alpha1.ServiceAnnotationLBRequestedIP] = "10.142.0.5"
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer("default", name)).To(Succeed())
			svc := getControllerService("default", name)
			g.Expect(svc.Status.LoadBalancer.Ingress).To(HaveLen(1))
			g.Expect(svc.Status.LoadBalancer.Ingress[0].IP).To(Equal("10.142.0.5"))
		}).Should(Succeed())
	})

	It("stays unallocated when the pool is exhausted", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.143.0.1/32"})

		filler := uniqueTestName("svc-fill")
		Expect(k8sClient.Create(ctx, newControllerLBService(filler, externalNetworkName))).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer("default", filler)).To(Succeed())
			g.Expect(getControllerService("default", filler).Status.LoadBalancer.Ingress).NotTo(BeEmpty())
		}).Should(Succeed())

		name := uniqueTestName("svc-empty")
		Expect(k8sClient.Create(ctx, newControllerLBService(name, externalNetworkName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer("default", name)).To(Succeed())
			svc := getControllerService("default", name)
			g.Expect(svc.Status.LoadBalancer.Ingress).To(BeEmpty())
			ready := meta.FindStatusCondition(svc.Status.Conditions, "LoadBalancerReady")
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal("NoAddressAvailable"))
		}).Should(Succeed())
	})

	It("reports a missing dependency when the ExternalNetwork annotation is empty", func() {
		ctx := context.Background()
		name := uniqueTestName("svc-lb")
		svc := newControllerLBService(name, "missing-extnet")
		Expect(k8sClient.Create(ctx, svc)).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer("default", name)).To(Succeed())
			svc := getControllerService("default", name)
			ready := meta.FindStatusCondition(svc.Status.Conditions, "LoadBalancerReady")
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal("MissingDependency"))
		}).Should(Succeed())
	})

	It("removes the AllocationClaim and finalizer on deletion", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.144.0.0/30"})
		name := uniqueTestName("svc-lb")
		Expect(k8sClient.Create(ctx, newControllerLBService(name, externalNetworkName))).To(Succeed())

		var claimName string
		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer("default", name)).To(Succeed())
			svc := getControllerService("default", name)
			g.Expect(svc.Finalizers).To(ContainElement("loadbalancer.juneau.loutres.me/allocation-claim"))
			g.Expect(svc.Status.LoadBalancer.Ingress).NotTo(BeEmpty())
			claimName = serviceLoadBalancerClaimName(svc)
			var claim juneauv1alpha1.AllocationClaim
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: claimName}, &claim)).To(Succeed())
		}).Should(Succeed())

		// Delete and reconcile; finalizer must be cleared and claim removed.
		Expect(k8sClient.Delete(ctx, getControllerService("default", name))).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(reconcileServiceLoadBalancer("default", name)).To(Succeed())

			var svc corev1.Service
			err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: name}, &svc)
			g.Expect(apierrors.IsNotFound(err)).To(BeTrue())

			var claim juneauv1alpha1.AllocationClaim
			err = k8sClient.Get(ctx, client.ObjectKey{Name: claimName}, &claim)
			g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
		}).Should(Succeed())
	})
})

func newControllerLBService(name, externalNetwork string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Annotations: map[string]string{
				juneauv1alpha1.ServiceAnnotationLBExternalNetwork: externalNetwork,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To(juneauv1alpha1.ServiceLoadBalancerClass),
			Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt(8080), Protocol: corev1.ProtocolTCP}},
			Selector:          map[string]string{"app": "stub"},
		},
	}
}

func getControllerService(namespace, name string) *corev1.Service {
	var svc corev1.Service
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, &svc)).To(Succeed())
	return &svc
}

func reconcileServiceLoadBalancer(namespace, name string) error {
	r := &ServiceLoadBalancerReconciler{Client: k8sClient}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Namespace: namespace, Name: name}})
	return err
}
