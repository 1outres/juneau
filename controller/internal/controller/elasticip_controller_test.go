package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
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

	It("honors spec.requestedIP when the address is available", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.130.0.0/29"})
		name := uniqueTestName("elasticip")
		eip := newControllerElasticIP(name, externalNetworkName)
		eip.Spec.RequestedIP = "10.130.0.5"
		Expect(k8sClient.Create(ctx, eip)).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(name)).To(Succeed())
			elasticIP := getControllerElasticIP(name)
			g.Expect(elasticIP.Status.Address).To(Equal("10.130.0.5"))
			g.Expect(elasticIP.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPPhaseAvailable))
		}).Should(Succeed())
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

var _ = Describe("ElasticIP controller ARP advertisement", func() {
	It("advertises the address from the node holding the attachment", func() {
		ctx := context.Background()
		poolName := createExternalAddressPool(ctx, juneauv1alpha1.AddressPoolAdvertiseModeARP, []string{"10.125.0.10-10.125.0.20"})
		externalNetworkName := createExternalNetworkWithPools(ctx, juneauv1alpha1.ExternalNetworkTypeARP, poolName)

		name := uniqueTestName("elasticip")
		Expect(k8sClient.Create(ctx, newControllerElasticIP(name, externalNetworkName))).To(Succeed())
		createElasticIPAttachmentOnNode(ctx, name, "node-eip-a")

		address := waitForElasticIPAddress(name)

		var advertisement juneauv1alpha1.ARPAdvertisement
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: elasticIPAdvertisementName("default", name)}, &advertisement)).To(Succeed())
		Expect(advertisement.Spec.ExternalNetwork).To(Equal(externalNetworkName))
		Expect(advertisement.Spec.Address).To(Equal(address))
		Expect(advertisement.Spec.NodeName).To(Equal("node-eip-a"))
	})

	It("removes the advertisement when the attachment goes away", func() {
		ctx := context.Background()
		poolName := createExternalAddressPool(ctx, juneauv1alpha1.AddressPoolAdvertiseModeARP, []string{"10.125.1.10-10.125.1.20"})
		externalNetworkName := createExternalNetworkWithPools(ctx, juneauv1alpha1.ExternalNetworkTypeARP, poolName)

		name := uniqueTestName("elasticip")
		Expect(k8sClient.Create(ctx, newControllerElasticIP(name, externalNetworkName))).To(Succeed())
		attachment := createElasticIPAttachmentOnNode(ctx, name, "node-eip-b")

		waitForElasticIPAddress(name)
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: elasticIPAdvertisementName("default", name)}, &juneauv1alpha1.ARPAdvertisement{})).To(Succeed())

		Expect(k8sClient.Delete(ctx, attachment)).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(name)).To(Succeed())
			err := k8sClient.Get(ctx, client.ObjectKey{Name: elasticIPAdvertisementName("default", name)}, &juneauv1alpha1.ARPAdvertisement{})
			g.Expect(errors.IsNotFound(err)).To(BeTrue())
		}).Should(Succeed())
	})

	It("moves the advertisement in place when the attachment is rescheduled", func() {
		ctx := context.Background()
		poolName := createExternalAddressPool(ctx, juneauv1alpha1.AddressPoolAdvertiseModeARP, []string{"10.125.2.10-10.125.2.20"})
		externalNetworkName := createExternalNetworkWithPools(ctx, juneauv1alpha1.ExternalNetworkTypeARP, poolName)

		name := uniqueTestName("elasticip")
		Expect(k8sClient.Create(ctx, newControllerElasticIP(name, externalNetworkName))).To(Succeed())
		attachment := createElasticIPAttachmentOnNode(ctx, name, "node-eip-c")

		waitForElasticIPAddress(name)

		var before juneauv1alpha1.ARPAdvertisement
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: elasticIPAdvertisementName("default", name)}, &before)).To(Succeed())

		setElasticIPAttachmentNode(ctx, attachment, "node-eip-d")

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(name)).To(Succeed())
			var after juneauv1alpha1.ARPAdvertisement
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: elasticIPAdvertisementName("default", name)}, &after)).To(Succeed())
			g.Expect(after.Spec.NodeName).To(Equal("node-eip-d"))
			g.Expect(after.Spec.Address).To(Equal(before.Spec.Address))
			g.Expect(after.UID).To(Equal(before.UID))
		}).Should(Succeed())
	})

	It("removes the advertisement when the ElasticIP is deleted", func() {
		ctx := context.Background()
		poolName := createExternalAddressPool(ctx, juneauv1alpha1.AddressPoolAdvertiseModeARP, []string{"10.125.3.10-10.125.3.20"})
		externalNetworkName := createExternalNetworkWithPools(ctx, juneauv1alpha1.ExternalNetworkTypeARP, poolName)

		name := uniqueTestName("elasticip")
		elasticIP := newControllerElasticIP(name, externalNetworkName)
		Expect(k8sClient.Create(ctx, elasticIP)).To(Succeed())
		attachment := createElasticIPAttachmentOnNode(ctx, name, "node-eip-e")

		waitForElasticIPAddress(name)
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: elasticIPAdvertisementName("default", name)}, &juneauv1alpha1.ARPAdvertisement{})).To(Succeed())

		Expect(k8sClient.Delete(ctx, attachment)).To(Succeed())
		Expect(k8sClient.Delete(ctx, getControllerElasticIP(name))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIP(name)).To(Succeed())
			err := k8sClient.Get(ctx, client.ObjectKey{Name: elasticIPAdvertisementName("default", name)}, &juneauv1alpha1.ARPAdvertisement{})
			g.Expect(errors.IsNotFound(err)).To(BeTrue())
			g.Expect(errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKey{Name: name, Namespace: "default"}, &juneauv1alpha1.ElasticIP{}))).To(BeTrue())
		}).Should(Succeed())
	})

	It("does not advertise over ARP for a BGP ExternalNetwork", func() {
		ctx := context.Background()
		externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{"10.126.0.0/29"})

		name := uniqueTestName("elasticip")
		Expect(k8sClient.Create(ctx, newControllerElasticIP(name, externalNetworkName))).To(Succeed())
		createElasticIPAttachmentOnNode(ctx, name, "node-eip-bgp")

		waitForElasticIPAddress(name)

		err := k8sClient.Get(ctx, client.ObjectKey{Name: elasticIPAdvertisementName("default", name)}, &juneauv1alpha1.ARPAdvertisement{})
		Expect(errors.IsNotFound(err)).To(BeTrue())
	})
})

func waitForElasticIPAddress(name string) string {
	var address string
	Eventually(func(g Gomega) {
		g.Expect(reconcileElasticIP(name)).To(Succeed())
		elasticIP := getControllerElasticIP(name)
		g.Expect(elasticIP.Status.Address).NotTo(BeEmpty())
		address = elasticIP.Status.Address
	}).Should(Succeed())
	return address
}

func createElasticIPAttachmentOnNode(ctx context.Context, elasticIPName, nodeName string) *juneauv1alpha1.ElasticIPAttachment {
	attachment := &juneauv1alpha1.ElasticIPAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("elasticipattachment"), Namespace: "default"},
		Spec: juneauv1alpha1.ElasticIPAttachmentSpec{
			ElasticIPRef: juneauv1alpha1.ElasticIPAttachmentElasticIPRef{Name: elasticIPName},
			TargetRef:    juneauv1alpha1.ElasticIPAttachmentTargetRef{NetworkInterfaceName: uniqueTestName("ni")},
		},
	}
	Expect(k8sClient.Create(ctx, attachment)).To(Succeed())
	setElasticIPAttachmentNode(ctx, attachment, nodeName)
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, attachment))).To(Succeed())
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &juneauv1alpha1.ARPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: elasticIPAdvertisementName("default", elasticIPName)},
		}))).To(Succeed())
	})
	return attachment
}

func setElasticIPAttachmentNode(ctx context.Context, attachment *juneauv1alpha1.ElasticIPAttachment, nodeName string) {
	Eventually(func(g Gomega) {
		var current juneauv1alpha1.ElasticIPAttachment
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(attachment), &current)).To(Succeed())
		current.Status.NodeName = nodeName
		g.Expect(k8sClient.Status().Update(ctx, &current)).To(Succeed())
	}).Should(Succeed())
}
