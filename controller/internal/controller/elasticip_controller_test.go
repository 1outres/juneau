package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ElasticIP controller", func() {
	It("allocates an address from the referenced ExternalNetwork AddressPool", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.120.0.0/30"})
		name := uniqueTestName("elasticip")
		Expect(k8sClient.Create(ctx, newControllerElasticIP(name, externalNetworkName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(name)).To(Succeed())
			elasticIP := getControllerElasticIP(name)
			g.Expect(elasticIP.Status.Address).To(Equal("10.120.0.1"))
			g.Expect(elasticIP.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPPhaseAvailable))
		}).Should(Succeed())
	})

	It("stays pending when no address is available", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.121.0.1/32"})
		allocatedEIP := newControllerElasticIP(uniqueTestName("elasticip"), externalNetworkName)
		Expect(k8sClient.Create(ctx, allocatedEIP)).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(allocatedEIP.Name)).To(Succeed())
			g.Expect(getControllerElasticIP(allocatedEIP.Name).Status.Address).To(Equal("10.121.0.1"))
		}).Should(Succeed())

		name := uniqueTestName("elasticip")
		Expect(k8sClient.Create(ctx, newControllerElasticIP(name, externalNetworkName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(name)).To(Succeed())
			elasticIP := getControllerElasticIP(name)
			g.Expect(elasticIP.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPPhasePending))
			g.Expect(elasticIP.Status.Address).To(BeEmpty())
		}).Should(Succeed())

		elasticIP := getControllerElasticIP(name)

		allocated := meta.FindStatusCondition(elasticIP.Status.Conditions, "Allocated")
		Expect(allocated).NotTo(BeNil())
		Expect(allocated.Status).To(Equal(metav1.ConditionFalse))
		Expect(allocated.ObservedGeneration).To(Equal(elasticIP.Generation))

		attached := meta.FindStatusCondition(elasticIP.Status.Conditions, "Attached")
		Expect(attached).NotTo(BeNil())
		Expect(attached.Status).To(Equal(metav1.ConditionFalse))
		Expect(attached.ObservedGeneration).To(Equal(elasticIP.Generation))
	})

	It("is available when allocated but unattached", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.122.0.0/30"})
		name := uniqueTestName("elasticip")
		Expect(k8sClient.Create(ctx, newControllerElasticIP(name, externalNetworkName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(name)).To(Succeed())
			elasticIP := getControllerElasticIP(name)
			g.Expect(elasticIP.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPPhaseAvailable))
			g.Expect(elasticIP.Status.AttachmentName).To(BeEmpty())
		}).Should(Succeed())

		elasticIP := getControllerElasticIP(name)

		allocated := meta.FindStatusCondition(elasticIP.Status.Conditions, "Allocated")
		Expect(allocated).NotTo(BeNil())
		Expect(allocated.Status).To(Equal(metav1.ConditionTrue))
		Expect(allocated.ObservedGeneration).To(Equal(elasticIP.Generation))

		attached := meta.FindStatusCondition(elasticIP.Status.Conditions, "Attached")
		Expect(attached).NotTo(BeNil())
		Expect(attached.Status).To(Equal(metav1.ConditionFalse))
		Expect(attached.ObservedGeneration).To(Equal(elasticIP.Generation))
	})

	It("is attached when exactly one attachment exists", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.123.0.0/30"})
		name := uniqueTestName("elasticip")
		attachmentName := uniqueTestName("elasticipattachment")
		Expect(k8sClient.Create(ctx, newControllerElasticIP(name, externalNetworkName))).To(Succeed())
		Expect(k8sClient.Create(ctx, &juneauv1alpha1.ElasticIPAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: attachmentName, Namespace: "default"},
			Spec: juneauv1alpha1.ElasticIPAttachmentSpec{
				ElasticIPRef: juneauv1alpha1.ElasticIPAttachmentElasticIPRef{Name: name},
				TargetRef:    juneauv1alpha1.ElasticIPAttachmentTargetRef{NetworkInterfaceName: uniqueTestName("ni")},
			},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(name)).To(Succeed())
			elasticIP := getControllerElasticIP(name)
			g.Expect(elasticIP.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPPhaseAttached))
			g.Expect(elasticIP.Status.AttachmentName).To(Equal(attachmentName))
		}).Should(Succeed())

		elasticIP := getControllerElasticIP(name)
		Expect(elasticIP.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPPhaseAttached))
		Expect(elasticIP.Status.AttachmentName).To(Equal(attachmentName))

		allocated := meta.FindStatusCondition(elasticIP.Status.Conditions, "Allocated")
		Expect(allocated).NotTo(BeNil())
		Expect(allocated.Status).To(Equal(metav1.ConditionTrue))
		Expect(allocated.ObservedGeneration).To(Equal(elasticIP.Generation))

		attached := meta.FindStatusCondition(elasticIP.Status.Conditions, "Attached")
		Expect(attached).NotTo(BeNil())
		Expect(attached.Status).To(Equal(metav1.ConditionTrue))
		Expect(attached.ObservedGeneration).To(Equal(elasticIP.Generation))
	})

	It("enters error when multiple attachments reference it", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.124.0.0/30"})
		name := uniqueTestName("elasticip")
		Expect(k8sClient.Create(ctx, newControllerElasticIP(name, externalNetworkName))).To(Succeed())
		for i := 0; i < 2; i++ {
			Expect(k8sClient.Create(ctx, &juneauv1alpha1.ElasticIPAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("elasticipattachment"), Namespace: "default"},
				Spec: juneauv1alpha1.ElasticIPAttachmentSpec{
					ElasticIPRef: juneauv1alpha1.ElasticIPAttachmentElasticIPRef{Name: name},
					TargetRef:    juneauv1alpha1.ElasticIPAttachmentTargetRef{NetworkInterfaceName: uniqueTestName("ni")},
				},
			})).To(Succeed())
		}

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(name)).To(Succeed())
			elasticIP := getControllerElasticIP(name)
			g.Expect(elasticIP.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPPhaseError))
		}).Should(Succeed())

		elasticIP := getControllerElasticIP(name)
		Expect(elasticIP.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPPhaseError))

		allocated := meta.FindStatusCondition(elasticIP.Status.Conditions, "Allocated")
		Expect(allocated).NotTo(BeNil())
		Expect(allocated.Status).To(Equal(metav1.ConditionFalse))
		Expect(allocated.ObservedGeneration).To(Equal(elasticIP.Generation))

		attached := meta.FindStatusCondition(elasticIP.Status.Conditions, "Attached")
		Expect(attached).NotTo(BeNil())
		Expect(attached.Status).To(Equal(metav1.ConditionFalse))
		Expect(attached.ObservedGeneration).To(Equal(elasticIP.Generation))
	})
})

func newControllerElasticIP(name, externalNetwork string) *juneauv1alpha1.ElasticIP {
	return &juneauv1alpha1.ElasticIP{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: juneauv1alpha1.ElasticIPSpec{
			ExternalNetwork: externalNetwork,
		},
	}
}

func createControllerElasticIPNetwork(ctx context.Context, addresses []string) (string, string) {
	poolName := uniqueTestName("addresspool")
	Expect(k8sClient.Create(ctx, &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: juneauv1alpha1.AddressPoolAdvertiseModeBGP,
			Addresses:     addresses,
		},
	})).To(Succeed())

	externalNetworkName := uniqueTestName("externalnetwork")
	Expect(k8sClient.Create(ctx, &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: externalNetworkName},
		Spec: juneauv1alpha1.ExternalNetworkSpec{
			Type:         juneauv1alpha1.ExternalNetworkTypeBGP,
			AddressPools: []string{poolName},
		},
	})).To(Succeed())

	return externalNetworkName, poolName
}

func getControllerElasticIP(name string) *juneauv1alpha1.ElasticIP {
	var elasticIP juneauv1alpha1.ElasticIP
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &elasticIP)).To(Succeed())
	return &elasticIP
}

func reconcileElasticIP(name string) error {
	r := &ElasticIPReconciler{Client: k8sClient}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: name, Namespace: "default"}})
	return err
}
