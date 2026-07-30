package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ElasticIPAttachment controller", func() {
	It("stays pending while ElasticIP address is not allocated", func() {
		ctx := context.Background()
		name := uniqueTestName("elasticipattachment")
		elasticIPName := uniqueTestName("elasticip")
		networkInterfaceName := uniqueTestName("networkinterface")

		Expect(k8sClient.Create(ctx, newControllerElasticIP(elasticIPName, uniqueTestName("missing-externalnetwork")))).To(Succeed())
		Expect(k8sClient.Create(ctx, newControllerNetworkInterface(networkInterfaceName, "10.16.0.10", "node-a", "pod-uid-1", "pod-a", "net1"))).To(Succeed())
		bindControllerNetworkInterface(ctx, networkInterfaceName, "node-a", "pod-uid-1", "pod-a", "net1")
		Expect(k8sClient.Create(ctx, newControllerElasticIPAttachment(name, elasticIPName, networkInterfaceName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIPAttachment(name)).To(Succeed())
			attachment := getControllerElasticIPAttachment(name)
			g.Expect(attachment.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPAttachmentPhasePending))
			g.Expect(attachment.Status.ElasticIP).To(BeEmpty())
			ready := meta.FindStatusCondition(attachment.Status.Conditions, "Ready")
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.ObservedGeneration).To(Equal(attachment.Generation))
		}).Should(Succeed())
	})

	It("stays pending while NetworkInterface address is not allocated", func() {
		ctx := context.Background()
		name := uniqueTestName("elasticipattachment")
		elasticIPName := uniqueTestName("elasticip")
		networkInterfaceName := uniqueTestName("networkinterface")

		elasticIP := newControllerElasticIP(elasticIPName, createControllerExternalNetwork(ctx))
		Expect(k8sClient.Create(ctx, elasticIP)).To(Succeed())
		setControllerElasticIPStatus(elasticIPName, "10.200.0.10")

		Expect(k8sClient.Create(ctx, newControllerNetworkInterface(networkInterfaceName, "", "node-a", "pod-uid-2", "pod-b", "net1"))).To(Succeed())
		bindControllerNetworkInterface(ctx, networkInterfaceName, "node-a", "pod-uid-2", "pod-b", "net1")
		Expect(k8sClient.Create(ctx, newControllerElasticIPAttachment(name, elasticIPName, networkInterfaceName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIPAttachment(name)).To(Succeed())
			attachment := getControllerElasticIPAttachment(name)
			g.Expect(attachment.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPAttachmentPhasePending))
			g.Expect(attachment.Status.ElasticIP).To(Equal("10.200.0.10"))
			g.Expect(attachment.Status.PodIP).To(BeEmpty())
			ready := meta.FindStatusCondition(attachment.Status.Conditions, "Ready")
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.ObservedGeneration).To(Equal(attachment.Generation))
		}).Should(Succeed())
	})

	It("stays pending when no matching NetworkEndpoint exists", func() {
		ctx := context.Background()
		name := uniqueTestName("elasticipattachment")
		elasticIPName := uniqueTestName("elasticip")
		networkInterfaceName := uniqueTestName("networkinterface")

		elasticIP := newControllerElasticIP(elasticIPName, createControllerExternalNetwork(ctx))
		Expect(k8sClient.Create(ctx, elasticIP)).To(Succeed())
		setControllerElasticIPStatus(elasticIPName, "10.200.0.11")

		networkInterface := newControllerNetworkInterface(networkInterfaceName, "10.16.0.11/24", "node-a", "pod-uid-3", "pod-c", "net1")
		Expect(k8sClient.Create(ctx, networkInterface)).To(Succeed())
		bindControllerNetworkInterface(ctx, networkInterfaceName, "node-a", "pod-uid-3", "pod-c", "net1")
		setControllerNetworkInterfaceStatus(networkInterfaceName, "10.16.0.11/24")

		Expect(k8sClient.Create(ctx, newControllerElasticIPAttachment(name, elasticIPName, networkInterfaceName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIPAttachment(name)).To(Succeed())
			attachment := getControllerElasticIPAttachment(name)
			g.Expect(attachment.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPAttachmentPhasePending))
			g.Expect(attachment.Status.ElasticIP).To(Equal("10.200.0.11"))
			g.Expect(attachment.Status.PodIP).To(Equal("10.16.0.11"))
			g.Expect(attachment.Status.NodeName).To(Equal("node-a"))
			ready := meta.FindStatusCondition(attachment.Status.Conditions, "Ready")
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Reason).To(Equal("WaitingForNetworkEndpoint"))
			g.Expect(ready.ObservedGeneration).To(Equal(attachment.Generation))
		}).Should(Succeed())
	})

	It("becomes attached when exactly one podRef-matching NetworkEndpoint exists", func() {
		ctx := context.Background()
		name := uniqueTestName("elasticipattachment")
		elasticIPName := uniqueTestName("elasticip")
		networkInterfaceName := uniqueTestName("networkinterface")

		elasticIP := newControllerElasticIP(elasticIPName, createControllerExternalNetwork(ctx))
		Expect(k8sClient.Create(ctx, elasticIP)).To(Succeed())
		setControllerElasticIPStatus(elasticIPName, "10.200.0.12")

		networkInterface := newControllerNetworkInterface(networkInterfaceName, "10.16.0.12/24", "node-a", "pod-uid-4", "pod-d", "net1")
		Expect(k8sClient.Create(ctx, networkInterface)).To(Succeed())
		attachmentRef := bindControllerNetworkInterface(ctx, networkInterfaceName, "node-a", "pod-uid-4", "pod-d", "net1")
		setControllerNetworkInterfaceStatus(networkInterfaceName, "10.16.0.12/24")

		Expect(k8sClient.Create(ctx, &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("networkendpoint"), Namespace: "default"},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				Kind:     juneauv1alpha1.EndpointKindPod,
				NodeName: "node-a",
				Subnet:   "default",
				PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
					UID:       "pod-uid-4",
					Name:      "pod-d",
					Interface: "net1",
				},
				NetworkInterfaceRef:           networkInterfaceName,
				NetworkInterfaceAttachmentRef: attachmentRef,
			},
		})).To(Succeed())

		Expect(k8sClient.Create(ctx, newControllerElasticIPAttachment(name, elasticIPName, networkInterfaceName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIPAttachment(name)).To(Succeed())
			attachment := getControllerElasticIPAttachment(name)
			g.Expect(attachment.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPAttachmentPhaseAttached))
			g.Expect(attachment.Status.ElasticIP).To(Equal("10.200.0.12"))
			g.Expect(attachment.Status.PodIP).To(Equal("10.16.0.12"))
			g.Expect(attachment.Status.NodeName).To(Equal("node-a"))
			ready := meta.FindStatusCondition(attachment.Status.Conditions, "Ready")
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(ready.ObservedGeneration).To(Equal(attachment.Generation))
		}).Should(Succeed())
	})

	It("enters error when multiple podRef-matching NetworkEndpoints exist", func() {
		ctx := context.Background()
		name := uniqueTestName("elasticipattachment")
		elasticIPName := uniqueTestName("elasticip")
		networkInterfaceName := uniqueTestName("networkinterface")

		elasticIP := newControllerElasticIP(elasticIPName, createControllerExternalNetwork(ctx))
		Expect(k8sClient.Create(ctx, elasticIP)).To(Succeed())
		setControllerElasticIPStatus(elasticIPName, "10.200.0.13")

		networkInterface := newControllerNetworkInterface(networkInterfaceName, "10.16.0.13/24", "node-a", "pod-uid-5", "pod-e", "net1")
		Expect(k8sClient.Create(ctx, networkInterface)).To(Succeed())
		attachmentRef := bindControllerNetworkInterface(ctx, networkInterfaceName, "node-a", "pod-uid-5", "pod-e", "net1")
		setControllerNetworkInterfaceStatus(networkInterfaceName, "10.16.0.13/24")

		for i := 0; i < 2; i++ {
			Expect(k8sClient.Create(ctx, &juneauv1alpha1.NetworkEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("networkendpoint"), Namespace: "default"},
				Spec: juneauv1alpha1.NetworkEndpointSpec{
					Kind:     juneauv1alpha1.EndpointKindPod,
					NodeName: "node-a",
					Subnet:   "default",
					PodRef: &juneauv1alpha1.NetworkEndpointPodReference{
						UID:       "pod-uid-5",
						Name:      "pod-e",
						Interface: "net1",
					},
					NetworkInterfaceRef:           networkInterfaceName,
					NetworkInterfaceAttachmentRef: attachmentRef.DeepCopy(),
				},
			})).To(Succeed())
		}

		Expect(k8sClient.Create(ctx, newControllerElasticIPAttachment(name, elasticIPName, networkInterfaceName))).To(Succeed())

		Eventually(func(g Gomega) {
			g.Expect(reconcileElasticIPAttachment(name)).To(Succeed())
			attachment := getControllerElasticIPAttachment(name)
			g.Expect(attachment.Status.Phase).To(Equal(juneauv1alpha1.ElasticIPAttachmentPhaseError))
			ready := meta.FindStatusCondition(attachment.Status.Conditions, "Ready")
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal("ReconcileFailed"))
			g.Expect(ready.Message).To(ContainSubstring("multiple NetworkEndpoints match NetworkInterface"))
			g.Expect(ready.ObservedGeneration).To(Equal(attachment.Generation))
		}).Should(Succeed())
	})
})

func newControllerElasticIPAttachment(name, elasticIPName, networkInterfaceName string) *juneauv1alpha1.ElasticIPAttachment {
	return &juneauv1alpha1.ElasticIPAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: juneauv1alpha1.ElasticIPAttachmentSpec{
			ElasticIPRef: juneauv1alpha1.ElasticIPAttachmentElasticIPRef{Name: elasticIPName},
			TargetRef:    juneauv1alpha1.ElasticIPAttachmentTargetRef{NetworkInterfaceName: networkInterfaceName},
		},
	}
}

func createControllerExternalNetwork(ctx context.Context) string {
	externalNetworkName, _ := createControllerElasticIPNetwork(ctx, []string{uniqueControllerElasticIPCIDR()})
	return externalNetworkName
}

func uniqueControllerElasticIPCIDR() string {
	octet := time.Now().UnixNano()%200 + 20
	return fmt.Sprintf("10.%d.0.0/24", octet)
}

func newControllerNetworkInterface(name, address, nodeName, uid, podName, iface string) *juneauv1alpha1.NetworkInterface {
	return &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			Subnet: "default",
		},
		Status: juneauv1alpha1.NetworkInterfaceStatus{Address: address},
	}
}

func bindControllerNetworkInterface(ctx context.Context, name, nodeName, podUID, podName, iface string) *juneauv1alpha1.NetworkInterfaceAttachmentReference {
	attachmentName := name + "-attachment"
	attachment := &juneauv1alpha1.NetworkInterfaceAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: attachmentName, Namespace: "default"},
		Spec: juneauv1alpha1.NetworkInterfaceAttachmentSpec{
			NetworkInterfaceRef: name,
			NodeName:            nodeName,
			PodRef: juneauv1alpha1.NetworkInterfaceAttachmentPodReference{
				UID:       podUID,
				Name:      podName,
				Interface: iface,
			},
		},
	}
	Expect(k8sClient.Create(ctx, attachment)).To(Succeed())
	var networkInterface juneauv1alpha1.NetworkInterface
	Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name, Namespace: "default"}, &networkInterface)).To(Succeed())
	networkInterface.Spec.AttachmentRef = &juneauv1alpha1.NetworkInterfaceAttachmentReference{
		Name: attachment.Name,
		UID:  attachment.UID,
	}
	Expect(k8sClient.Update(ctx, &networkInterface)).To(Succeed())
	return networkInterface.Spec.AttachmentRef.DeepCopy()
}

func setControllerElasticIPStatus(name, address string) {
	Eventually(func() error {
		var elasticIP juneauv1alpha1.ElasticIP
		if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &elasticIP); err != nil {
			return err
		}
		elasticIP.Status.Address = address
		return k8sClient.Status().Update(context.Background(), &elasticIP)
	}).Should(Succeed())
}

func setControllerNetworkInterfaceStatus(name, address string) {
	Eventually(func() error {
		var networkInterface juneauv1alpha1.NetworkInterface
		if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &networkInterface); err != nil {
			return err
		}
		networkInterface.Status.Address = address
		return k8sClient.Status().Update(context.Background(), &networkInterface)
	}).Should(Succeed())
}

func getControllerElasticIPAttachment(name string) *juneauv1alpha1.ElasticIPAttachment {
	var attachment juneauv1alpha1.ElasticIPAttachment
	Expect(k8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: "default"}, &attachment)).To(Succeed())
	return &attachment
}

func reconcileElasticIPAttachment(name string) error {
	r := &ElasticIPAttachmentReconciler{Client: k8sClient}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: name, Namespace: "default"}})
	return err
}
