package v1alpha1

import (
	"context"
	"net/netip"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const webhookTestFinalizer = "test.juneau.loutres.me/finalizer"

// createWebhookElasticIP creates an ElasticIP on an ExternalNetwork of its
// own. No controller runs in this suite, so the ElasticIP stays Pending,
// which is exactly the state a Pod may already reference.
func createWebhookElasticIP() string {
	GinkgoHelper()
	elasticIP := newValidElasticIP(webhookUniqueTestName("elasticip"), createWebhookExternalNetwork(juneauv1alpha1.ExternalNetworkTypeBGP))
	createWebhookElasticIPEventually(elasticIP)
	DeferCleanup(func() {
		_ = webhookK8sClient.Delete(context.Background(), elasticIP)
	})
	return elasticIP.Name
}

// createWebhookPod creates a Pod on the default Subnet. Pass a finalizer
// to keep the Pod around in Terminating after it is deleted.
func createWebhookPod(labels map[string]string, finalizers ...string) *corev1.Pod {
	GinkgoHelper()
	pod := makePodWithImage(uniquePodName(), "default", nil)
	pod.Labels = labels
	pod.Finalizers = finalizers
	Expect(webhookK8sClient.Create(context.Background(), pod)).To(Succeed())
	DeferCleanup(func() {
		releaseWebhookFinalizer(pod)
		_ = webhookK8sClient.Delete(context.Background(), pod)
	})
	return pod
}

// newElasticIPNetworkInterface builds the NetworkInterface the Pod
// controller would create for a NIC of pod that carries elasticIP.
func newElasticIPNetworkInterface(pod *corev1.Pod, ifName, elasticIP string) *juneauv1alpha1.NetworkInterface {
	return &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name + "." + ifName,
			Namespace: pod.Namespace,
		},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			NodeName:  "node-a",
			ElasticIP: elasticIP,
			PodRef: juneauv1alpha1.NetworkInterfacePodReference{
				UID:       string(pod.UID),
				Name:      pod.Name,
				Interface: ifName,
			},
		},
	}
}

// createWebhookElasticIPHolder makes pod hold elasticIP directly through a
// NetworkInterface on its primary NIC.
func createWebhookElasticIPHolder(pod *corev1.Pod, elasticIP string, mutate ...func(*juneauv1alpha1.NetworkInterface)) *juneauv1alpha1.NetworkInterface {
	GinkgoHelper()
	holder := newElasticIPNetworkInterface(pod, juneauv1alpha1.PodPrimaryInterfaceName, elasticIP)
	for _, m := range mutate {
		m(holder)
	}
	Expect(webhookK8sClient.Create(context.Background(), holder)).To(Succeed())
	DeferCleanup(func() {
		releaseWebhookFinalizer(holder)
		_ = webhookK8sClient.Delete(context.Background(), holder)
	})
	return holder
}

// deleteWebhookObjectAndWait deletes an object that carries
// webhookTestFinalizer and waits until the API server shows it Terminating.
func deleteWebhookObjectAndWait(obj client.Object) {
	GinkgoHelper()
	Expect(webhookK8sClient.Delete(context.Background(), obj)).To(Succeed())
	Eventually(func(g Gomega) {
		current := obj.DeepCopyObject().(client.Object)
		g.Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(obj), current)).To(Succeed())
		g.Expect(current.GetDeletionTimestamp()).NotTo(BeNil())
	}).Should(Succeed())
}

func releaseWebhookFinalizer(obj client.Object) {
	current := obj.DeepCopyObject().(client.Object)
	if err := webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(obj), current); err != nil {
		return
	}
	if controllerutil.RemoveFinalizer(current, webhookTestFinalizer) {
		_ = webhookK8sClient.Update(context.Background(), current)
	}
}

var _ = Describe("NetworkInterface on an ElasticIP", func() {
	It("accepts an interface on an ElasticIP that does not exist yet", func() {
		pod := createWebhookPod(nil)

		Expect(webhookK8sClient.Create(context.Background(),
			newElasticIPNetworkInterface(pod, "ext0", webhookUniqueTestName("missing-elasticip")))).To(Succeed())
	})

	It("rejects an interface that names both a Subnet and an ElasticIP", func() {
		pod := createWebhookPod(nil)
		networkInterface := newElasticIPNetworkInterface(pod, "ext0", createWebhookElasticIP())
		networkInterface.Spec.Subnet = "default"

		err := webhookK8sClient.Create(context.Background(), networkInterface)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("set exactly one of spec.subnet, spec.l2Network and spec.elasticIP"))
	})

	It("rejects a pinned address on an ElasticIP interface", func() {
		pod := createWebhookPod(nil)
		networkInterface := newElasticIPNetworkInterface(pod, "ext0", createWebhookElasticIP())
		networkInterface.Spec.Address = "203.0.113.10"

		err := webhookK8sClient.Create(context.Background(), networkInterface)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.address and spec.securityGroups must be empty when spec.elasticIP is set"))
	})

	It("rejects SecurityGroups on an ElasticIP interface", func() {
		pod := createWebhookPod(nil)
		networkInterface := newElasticIPNetworkInterface(pod, "ext0", createWebhookElasticIP())
		networkInterface.Spec.SecurityGroups = []string{"sg-a"}

		err := webhookK8sClient.Create(context.Background(), networkInterface)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.address and spec.securityGroups must be empty when spec.elasticIP is set"))
	})

	It("rejects an immutable spec.elasticIP update", func() {
		pod := createWebhookPod(nil)
		networkInterface := newElasticIPNetworkInterface(pod, "ext0", createWebhookElasticIP())
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		var current juneauv1alpha1.NetworkInterface
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkInterface), &current)).To(Succeed())
		current.Spec.ElasticIP = createWebhookElasticIP()

		err := webhookK8sClient.Update(context.Background(), &current)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.elasticIP is immutable"))
	})

	It("lets an interface on an ElasticIP drop its finalizer", func() {
		pod := createWebhookPod(nil)
		networkInterface := newElasticIPNetworkInterface(pod, "ext0", createWebhookElasticIP())
		networkInterface.Finalizers = []string{webhookTestFinalizer}
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())
		deleteWebhookObjectAndWait(networkInterface)

		var current juneauv1alpha1.NetworkInterface
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkInterface), &current)).To(Succeed())
		current.Finalizers = nil
		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	It("accepts a label update on an interface on an ElasticIP", func() {
		pod := createWebhookPod(nil)
		networkInterface := newElasticIPNetworkInterface(pod, "ext0", createWebhookElasticIP())
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		var current juneauv1alpha1.NetworkInterface
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkInterface), &current)).To(Succeed())
		current.Labels = map[string]string{"example.com/touched": "true"}
		Expect(webhookK8sClient.Update(context.Background(), &current)).To(Succeed())
	})

	It("rejects an ElasticIP an ElasticIPAttachment uses", func() {
		elasticIP := createWebhookElasticIP()
		target := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "")
		Expect(webhookK8sClient.Create(context.Background(), target)).To(Succeed())
		attachment := newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIP, target.Name)
		Expect(webhookK8sClient.Create(context.Background(), attachment)).To(Succeed())

		pod := createWebhookPod(nil)
		err := webhookK8sClient.Create(context.Background(), newElasticIPNetworkInterface(pod, "ext0", elasticIP))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.elasticIP"))
		Expect(err.Error()).To(ContainSubstring("used by ElasticIPAttachment " + `"` + attachment.Name + `"`))
	})

	It("rejects an ElasticIP another interface already carries", func() {
		elasticIP := createWebhookElasticIP()
		holder := createWebhookElasticIPHolder(createWebhookPod(nil), elasticIP)

		err := webhookK8sClient.Create(context.Background(), newElasticIPNetworkInterface(createWebhookPod(nil), "ext0", elasticIP))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("already used by NetworkInterface " + `"` + holder.Name + `"`))
	})

	It("accepts an ElasticIP whose holder Pod is terminating", func() {
		elasticIP := createWebhookElasticIP()
		holderPod := createWebhookPod(nil, webhookTestFinalizer)
		createWebhookElasticIPHolder(holderPod, elasticIP)
		deleteWebhookObjectAndWait(holderPod)

		Expect(webhookK8sClient.Create(context.Background(),
			newElasticIPNetworkInterface(createWebhookPod(nil), "ext0", elasticIP))).To(Succeed())
	})

	It("accepts an ElasticIP whose holder interface is being deleted", func() {
		elasticIP := createWebhookElasticIP()
		holder := createWebhookElasticIPHolder(createWebhookPod(nil), elasticIP, func(ni *juneauv1alpha1.NetworkInterface) {
			ni.Finalizers = []string{webhookTestFinalizer}
		})
		deleteWebhookObjectAndWait(holder)

		Expect(webhookK8sClient.Create(context.Background(),
			newElasticIPNetworkInterface(createWebhookPod(nil), "ext0", elasticIP))).To(Succeed())
	})

	It("accepts an ElasticIP whose holder shares the allocation identity", func() {
		elasticIP := createWebhookElasticIP()
		createWebhookElasticIPHolder(createWebhookPod(nil), elasticIP, func(ni *juneauv1alpha1.NetworkInterface) {
			ni.Spec.AllocationIdentity = "vmi.web-0"
		})

		networkInterface := newElasticIPNetworkInterface(createWebhookPod(nil), "ext0", elasticIP)
		networkInterface.Spec.AllocationIdentity = "vmi.web-0"
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())
	})

	It("stores onLink routes, route tables and policy rules in status", func() {
		pod := createWebhookPod(nil)
		networkInterface := newElasticIPNetworkInterface(pod, "ext0", createWebhookElasticIP())
		Expect(webhookK8sClient.Create(context.Background(), networkInterface)).To(Succeed())

		address := "203.0.113.10"
		table, err := juneauv1alpha1.PodElasticIPRouteTable(netip.MustParseAddr(address))
		Expect(err).NotTo(HaveOccurred())

		var current juneauv1alpha1.NetworkInterface
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkInterface), &current)).To(Succeed())
		current.Status.Address = address + "/32"
		current.Status.Routes = []juneauv1alpha1.NetworkRoute{{
			Dst:    "0.0.0.0/0",
			GW:     juneauv1alpha1.PodElasticIPGateway,
			OnLink: true,
			Table:  table,
		}}
		current.Status.Rules = []juneauv1alpha1.NetworkRoutingRule{{
			From:     address + "/32",
			Table:    table,
			Priority: juneauv1alpha1.PodElasticIPRulePriority,
		}}
		Expect(webhookK8sClient.Status().Update(context.Background(), &current)).To(Succeed())

		var stored juneauv1alpha1.NetworkInterface
		Expect(webhookK8sClient.Get(context.Background(), client.ObjectKeyFromObject(networkInterface), &stored)).To(Succeed())
		Expect(stored.Status.Routes).To(Equal(current.Status.Routes))
		Expect(stored.Status.Rules).To(Equal(current.Status.Rules))
	})
})

var _ = Describe("ElasticIPAttachment on an ElasticIP in direct use", func() {
	It("rejects an ElasticIP an interface carries directly", func() {
		elasticIP := createWebhookElasticIP()
		holder := createWebhookElasticIPHolder(createWebhookPod(nil), elasticIP)
		target := newValidNetworkInterface(webhookUniqueTestName("networkinterface"), "default", "")
		Expect(webhookK8sClient.Create(context.Background(), target)).To(Succeed())

		err := webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), elasticIP, target.Name))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("ElasticIP is used directly by NetworkInterface " + `"` + holder.Name + `"`))
	})

	It("rejects a target interface that carries an ElasticIP directly", func() {
		holder := createWebhookElasticIPHolder(createWebhookPod(nil), createWebhookElasticIP())

		err := webhookK8sClient.Create(context.Background(), newValidElasticIPAttachment(webhookUniqueTestName("elasticipattachment"), createWebhookElasticIP(), holder.Name))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("NetworkInterface carries ElasticIP"))
	})
})
