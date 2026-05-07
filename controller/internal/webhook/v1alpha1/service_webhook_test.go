package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func intOrString(i int) intstr.IntOrString {
	return intstr.FromInt(i)
}

var _ = Describe("Service webhook", func() {
	It("rejects creating a Service whose Vpc has Service routing disabled", func() {
		vpcName := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:        webhookUniqueTestName("svc"),
				Namespace:   "default",
				Annotations: map[string]string{ServiceAnnotationVpc: vpcName},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not have Service routing enabled"))
	})

	It("rejects Service annotated with juneau.loutres.me/subnet", func() {
		vpcName := createWebhookServiceEnabledVpc()

		err := webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("svc"),
				Namespace: "default",
				Annotations: map[string]string{
					ServiceAnnotationVpc:    vpcName,
					ServiceAnnotationSubnet: "anything",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Service is VPC-scoped"))
	})

	It("rejects Service whose annotated Vpc does not exist", func() {
		err := webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("svc"),
				Namespace: "default",
				Annotations: map[string]string{
					ServiceAnnotationVpc: "non-existent-vpc",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("referenced Vpc does not exist"))
	})

	It("accepts Service when its Vpc has service.consume=true", func() {
		vpcName := createWebhookServiceEnabledVpc()
		name := webhookUniqueTestName("svc")
		Expect(webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   "default",
				Annotations: map[string]string{ServiceAnnotationVpc: vpcName},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			})
		})
	})

	It("rejects shared-service annotation when the owner Vpc has no provider configured", func() {
		vpcName := createWebhookServiceEnabledVpc()

		err := webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("svc"),
				Namespace: "default",
				Annotations: map[string]string{
					ServiceAnnotationVpc:    vpcName,
					ServiceAnnotationShared: "true",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("is not configured as a Service provider"))
	})

	It("accepts shared-service annotation on the default Vpc (provider bootstrapped)", func() {
		name := webhookUniqueTestName("svc")
		Expect(webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
				Annotations: map[string]string{
					// Vpc annotation absent → default Vpc, which the
					// bootstrap promoted to a Service provider.
					ServiceAnnotationShared: "true",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			})
		})
	})

	It("accepts shared-service annotation on a non-default Vpc with provider configured", func() {
		vpcName := createWebhookServiceProviderVpc()
		name := webhookUniqueTestName("svc")
		Expect(webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
				Annotations: map[string]string{
					ServiceAnnotationVpc:    vpcName,
					ServiceAnnotationShared: "true",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			})
		})
	})

	It("rejects allowed-consumer-vpcs annotation without shared-service", func() {
		vpcName := createWebhookServiceEnabledVpc()

		err := webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("svc"),
				Namespace: "default",
				Annotations: map[string]string{
					ServiceAnnotationVpc:                 vpcName,
					ServiceAnnotationAllowedConsumerVpcs: "default",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("has no effect without the shared-service annotation"))
	})

	It("rejects allowed-consumer-vpcs entries that don't have service.consume=true", func() {
		ownerVpc := createWebhookServiceProviderVpc()
		// A Vpc without spec.service ⇒ service.consume is false.
		nonConsumerVpc := createWebhookVpc()

		err := webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      webhookUniqueTestName("svc"),
				Namespace: "default",
				Annotations: map[string]string{
					ServiceAnnotationVpc:                 ownerVpc,
					ServiceAnnotationShared:              "true",
					ServiceAnnotationAllowedConsumerVpcs: nonConsumerVpc,
				},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not have spec.service.consume=true"))
	})

	It("accepts allowed-consumer-vpcs whitelist with consume-enabled Vpcs", func() {
		ownerVpc := createWebhookServiceProviderVpc()
		consumerA := createWebhookServiceEnabledVpc()
		consumerB := createWebhookServiceEnabledVpc()

		name := webhookUniqueTestName("svc")
		Expect(webhookK8sClient.Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
				Annotations: map[string]string{
					ServiceAnnotationVpc:                 ownerVpc,
					ServiceAnnotationShared:              "true",
					ServiceAnnotationAllowedConsumerVpcs: consumerA + "," + consumerB,
				},
			},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
				Selector: map[string]string{"app": "x"},
			},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			})
		})
	})

	Context("LoadBalancer class admission", func() {
		It("rejects loadBalancerClass without external-network annotation", func() {
			err := webhookK8sClient.Create(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      webhookUniqueTestName("svc-lb"),
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					Type:              corev1.ServiceTypeLoadBalancer,
					LoadBalancerClass: ptr.To(juneauv1alpha1.ServiceLoadBalancerClass),
					Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
					Selector:          map[string]string{"app": "x"},
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(juneauv1alpha1.ServiceAnnotationLBExternalNetwork))
		})

		It("rejects loadBalancerClass with a non-existent external-network", func() {
			err := webhookK8sClient.Create(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      webhookUniqueTestName("svc-lb"),
					Namespace: "default",
					Annotations: map[string]string{
						juneauv1alpha1.ServiceAnnotationLBExternalNetwork: "missing-extnet",
					},
				},
				Spec: corev1.ServiceSpec{
					Type:              corev1.ServiceTypeLoadBalancer,
					LoadBalancerClass: ptr.To(juneauv1alpha1.ServiceLoadBalancerClass),
					Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
					Selector:          map[string]string{"app": "x"},
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("rejects loadBalancerClass when the external-network is ARP-typed (BGP only in v1)", func() {
			arpExtNet := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeARP)
			err := webhookK8sClient.Create(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      webhookUniqueTestName("svc-lb"),
					Namespace: "default",
					Annotations: map[string]string{
						juneauv1alpha1.ServiceAnnotationLBExternalNetwork: arpExtNet,
					},
				},
				Spec: corev1.ServiceSpec{
					Type:              corev1.ServiceTypeLoadBalancer,
					LoadBalancerClass: ptr.To(juneauv1alpha1.ServiceLoadBalancerClass),
					Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
					Selector:          map[string]string{"app": "x"},
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be type=bgp"))
		})

		It("rejects spec.loadBalancerIP when the Juneau class is selected", func() {
			extNet := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
			err := webhookK8sClient.Create(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      webhookUniqueTestName("svc-lb"),
					Namespace: "default",
					Annotations: map[string]string{
						juneauv1alpha1.ServiceAnnotationLBExternalNetwork: extNet,
					},
				},
				Spec: corev1.ServiceSpec{
					Type:              corev1.ServiceTypeLoadBalancer,
					LoadBalancerClass: ptr.To(juneauv1alpha1.ServiceLoadBalancerClass),
					LoadBalancerIP:    "10.200.0.1",
					Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
					Selector:          map[string]string{"app": "x"},
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(juneauv1alpha1.ServiceAnnotationLBRequestedIP))
		})

		It("rejects malformed loadbalancer-ip annotation", func() {
			extNet := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
			err := webhookK8sClient.Create(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      webhookUniqueTestName("svc-lb"),
					Namespace: "default",
					Annotations: map[string]string{
						juneauv1alpha1.ServiceAnnotationLBExternalNetwork: extNet,
						juneauv1alpha1.ServiceAnnotationLBRequestedIP:     "not-an-ip",
					},
				},
				Spec: corev1.ServiceSpec{
					Type:              corev1.ServiceTypeLoadBalancer,
					LoadBalancerClass: ptr.To(juneauv1alpha1.ServiceLoadBalancerClass),
					Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
					Selector:          map[string]string{"app": "x"},
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be a valid IPv4"))
		})

		It("accepts a Juneau-class LoadBalancer with a BGP external-network", func() {
			extNet := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
			name := webhookUniqueTestName("svc-lb")
			Expect(webhookK8sClient.Create(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: "default",
					Annotations: map[string]string{
						juneauv1alpha1.ServiceAnnotationLBExternalNetwork: extNet,
					},
				},
				Spec: corev1.ServiceSpec{
					Type:              corev1.ServiceTypeLoadBalancer,
					LoadBalancerClass: ptr.To(juneauv1alpha1.ServiceLoadBalancerClass),
					Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
					Selector:          map[string]string{"app": "x"},
				},
			})).To(Succeed())
			DeferCleanup(func() {
				_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
				})
			})
		})

		It("mutates allocateLoadBalancerNodePorts to false for Juneau-class LBs", func() {
			extNet := createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP)
			name := webhookUniqueTestName("svc-lb")
			Expect(webhookK8sClient.Create(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: "default",
					Annotations: map[string]string{
						juneauv1alpha1.ServiceAnnotationLBExternalNetwork: extNet,
					},
				},
				Spec: corev1.ServiceSpec{
					Type:                          corev1.ServiceTypeLoadBalancer,
					LoadBalancerClass:             ptr.To(juneauv1alpha1.ServiceLoadBalancerClass),
					AllocateLoadBalancerNodePorts: ptr.To(true),
					Ports:                         []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
					Selector:                      map[string]string{"app": "x"},
				},
			})).To(Succeed())
			DeferCleanup(func() {
				_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
				})
			})

			var svc corev1.Service
			Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &svc)).To(Succeed())
			Expect(svc.Spec.AllocateLoadBalancerNodePorts).NotTo(BeNil())
			Expect(*svc.Spec.AllocateLoadBalancerNodePorts).To(BeFalse())
		})

		It("does not mutate allocateLoadBalancerNodePorts for foreign-class LBs", func() {
			name := webhookUniqueTestName("svc-foreign")
			Expect(webhookK8sClient.Create(context.Background(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					Type:                          corev1.ServiceTypeLoadBalancer,
					LoadBalancerClass:             ptr.To("metallb.io/external"),
					AllocateLoadBalancerNodePorts: ptr.To(true),
					Ports:                         []corev1.ServicePort{{Port: 80, TargetPort: intOrString(80)}},
					Selector:                      map[string]string{"app": "x"},
				},
			})).To(Succeed())
			DeferCleanup(func() {
				_ = webhookK8sClient.Delete(context.Background(), &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
				})
			})

			var svc corev1.Service
			Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &svc)).To(Succeed())
			Expect(svc.Spec.AllocateLoadBalancerNodePorts).NotTo(BeNil())
			Expect(*svc.Spec.AllocateLoadBalancerNodePorts).To(BeTrue())
		})
	})

	It("does not re-validate Service updates that leave Juneau annotations unchanged", func() {
		vpcName := createWebhookServiceEnabledVpc()
		name := webhookUniqueTestName("svc")
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   "default",
				Annotations: map[string]string{ServiceAnnotationVpc: vpcName},
			},
			Spec: corev1.ServiceSpec{
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

		var vpc juneauv1alpha1.Vpc
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: vpcName}, &vpc)).To(Succeed())
		vpc.Spec.Service = nil
		Expect(webhookK8sClient.Update(context.Background(), &vpc)).To(Succeed())

		var fetched corev1.Service
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &fetched)).To(Succeed())
		fetched.Spec.Selector = map[string]string{"app": "y"}
		Expect(webhookK8sClient.Update(context.Background(), &fetched)).To(Succeed())
	})
})
