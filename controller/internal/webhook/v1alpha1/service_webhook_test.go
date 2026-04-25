package v1alpha1

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func intOrString(i int) intstr.IntOrString {
	return intstr.FromInt(i)
}

var _ = Describe("Service webhook", func() {
	It("rejects creating a Service whose Vpc has enableService=false", func() {
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
		Expect(err.Error()).To(ContainSubstring("does not have spec.enableService=true"))
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

	It("accepts Service when its Vpc has enableService=true", func() {
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
		vpc.Spec.EnableService = false
		Expect(webhookK8sClient.Update(context.Background(), &vpc)).To(Succeed())

		var fetched corev1.Service
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &fetched)).To(Succeed())
		fetched.Spec.Selector = map[string]string{"app": "y"}
		Expect(webhookK8sClient.Update(context.Background(), &fetched)).To(Succeed())
	})
})
