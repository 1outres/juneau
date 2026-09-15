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
	"net/netip"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("NetworkInterface on an ElasticIP", func() {
	ctx := context.Background()

	It("carries the address as a /32 with an onLink default route on eth0", func() {
		elasticIP := createPodTestElasticIP("203.0.113.50", 4201)
		iface := createElasticIPNetworkInterface(elasticIP, juneauv1alpha1.PodPrimaryInterfaceName)
		setElasticIPHolder(elasticIP, juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface, iface.Name)

		reconcileNetworkInterface(iface)

		current := getNetworkInterface(iface)
		Expect(current.Status.Address).To(Equal("203.0.113.50/32"))
		Expect(current.Status.Routes).To(Equal([]juneauv1alpha1.NetworkRoute{
			{Dst: "0.0.0.0/0", GW: juneauv1alpha1.PodElasticIPGateway, OnLink: true},
		}))
		Expect(current.Status.Rules).To(BeEmpty())
		Expect(current.Status.AllocationClaim).To(BeEmpty())
		Expect(current.Status.EffectiveSecurityGroups).To(BeEmpty())
		Expect(current.Status.Phase).To(Equal(juneauv1alpha1.NetworkInterfacePhaseAllocated))
		allocated := meta.FindStatusCondition(current.Status.Conditions, juneauv1alpha1.NetworkInterfaceStatusAllocated)
		Expect(allocated).NotTo(BeNil())
		Expect(allocated.Status).To(Equal(metav1.ConditionTrue))
		Expect(allocationClaimsFor(iface)).To(BeEmpty())
	})

	It("sends an extra NIC through a route table of its own", func() {
		elasticIP := createPodTestElasticIP("203.0.113.51", 4202)
		iface := createElasticIPNetworkInterface(elasticIP, "ext0")
		setElasticIPHolder(elasticIP, juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface, iface.Name)

		reconcileNetworkInterface(iface)

		table, err := juneauv1alpha1.PodElasticIPRouteTable(netip.MustParseAddr("203.0.113.51"))
		Expect(err).NotTo(HaveOccurred())
		current := getNetworkInterface(iface)
		Expect(current.Status.Address).To(Equal("203.0.113.51/32"))
		Expect(current.Status.Routes).To(Equal([]juneauv1alpha1.NetworkRoute{
			{Dst: "0.0.0.0/0", GW: juneauv1alpha1.PodElasticIPGateway, OnLink: true, Table: table},
		}))
		Expect(current.Status.Rules).To(Equal([]juneauv1alpha1.NetworkRoutingRule{
			{From: "203.0.113.51/32", Table: table, Priority: juneauv1alpha1.PodElasticIPRulePriority},
		}))
	})

	It("waits while another NetworkInterface carries the ElasticIP", func() {
		elasticIP := createPodTestElasticIP("203.0.113.52", 4203)
		iface := createElasticIPNetworkInterface(elasticIP, juneauv1alpha1.PodPrimaryInterfaceName)
		setElasticIPHolder(elasticIP, juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface, "previous-pod.eth0")

		reconcileNetworkInterface(iface)

		expectWaitingForElasticIP(iface, `NetworkInterface "previous-pod.eth0"`)
	})

	It("waits while the ElasticIP has picked nobody to carry it", func() {
		elasticIP := createPodTestElasticIP("203.0.113.53", 4204)
		iface := createElasticIPNetworkInterface(elasticIP, juneauv1alpha1.PodPrimaryInterfaceName)

		reconcileNetworkInterface(iface)

		expectWaitingForElasticIP(iface, "has not picked")
	})

	It("waits while an ElasticIPAttachment uses the ElasticIP", func() {
		elasticIP := createPodTestElasticIP("203.0.113.54", 4205)
		iface := createElasticIPNetworkInterface(elasticIP, juneauv1alpha1.PodPrimaryInterfaceName)
		setElasticIPHolder(elasticIP, juneauv1alpha1.ElasticIPStatusAttachmentKindElasticIPAttachment, "nat-use")

		reconcileNetworkInterface(iface)

		expectWaitingForElasticIP(iface, `ElasticIPAttachment "nat-use"`)
	})

	It("names the ElasticIPAttachment that uses the ElasticIP while the ElasticIP is in Error", func() {
		elasticIP := createPodTestElasticIP("203.0.113.58", 4208)
		iface := createElasticIPNetworkInterface(elasticIP, juneauv1alpha1.PodPrimaryInterfaceName)
		attachment := createElasticIPAttachmentOnNode(ctx, elasticIP, "node-nat")
		setElasticIPInConflict(elasticIP)

		reconcileNetworkInterface(iface)

		expectWaitingForElasticIP(iface, `ElasticIPAttachment "`+attachment.Name+`"`)
	})

	It("gives the address up while an ElasticIPAttachment uses the ElasticIP and takes it back once that one is gone", func() {
		elasticIP := createPodTestElasticIP("203.0.113.59", 4209)
		iface := createElasticIPNetworkInterface(elasticIP, juneauv1alpha1.PodPrimaryInterfaceName)
		setElasticIPHolder(elasticIP, juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface, iface.Name)
		reconcileNetworkInterface(iface)
		Expect(getNetworkInterface(iface).Status.Address).To(Equal("203.0.113.59/32"))

		attachment := createElasticIPAttachmentOnNode(ctx, elasticIP, "node-nat")
		reconcileNetworkInterface(iface)
		expectWaitingForElasticIP(iface, `ElasticIPAttachment "`+attachment.Name+`"`)

		Expect(k8sClient.Delete(ctx, attachment)).To(Succeed())
		reconcileNetworkInterface(iface)
		Expect(getNetworkInterface(iface).Status.Address).To(Equal("203.0.113.59/32"))
	})

	It("wakes the NetworkInterfaces that name the ElasticIP of an ElasticIPAttachment", func() {
		elasticIP := createPodTestElasticIP("203.0.113.60", 4210)
		iface := createElasticIPNetworkInterface(elasticIP, juneauv1alpha1.PodPrimaryInterfaceName)
		attachment := &juneauv1alpha1.ElasticIPAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("nat-use"), Namespace: "default"},
			Spec: juneauv1alpha1.ElasticIPAttachmentSpec{
				ElasticIPRef: juneauv1alpha1.ElasticIPAttachmentElasticIPRef{Name: elasticIP},
			},
		}

		r := &NetworkInterfaceReconciler{Client: cachedK8sClient}
		Eventually(func(g Gomega) {
			g.Expect(r.mapElasticIPAttachmentToNetworkInterfaces(ctx, attachment)).To(ConsistOf(
				reconcile.Request{NamespacedName: client.ObjectKeyFromObject(iface)},
			))
		}).Should(Succeed())
	})

	It("waits while the ExternalNetwork of the ElasticIP has no network ID", func() {
		elasticIP := createPodTestElasticIP("203.0.113.55", 0)
		iface := createElasticIPNetworkInterface(elasticIP, juneauv1alpha1.PodPrimaryInterfaceName)
		setElasticIPHolder(elasticIP, juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface, iface.Name)

		reconcileNetworkInterface(iface)

		current := getNetworkInterface(iface)
		Expect(current.Status.Phase).To(Equal(juneauv1alpha1.NetworkInterfacePhasePending))
		Expect(current.Status.Address).To(BeEmpty())
		allocated := meta.FindStatusCondition(current.Status.Conditions, juneauv1alpha1.NetworkInterfaceStatusAllocated)
		Expect(allocated).NotTo(BeNil())
		Expect(allocated.Reason).To(Equal(conditionReasonNetworkNotReady))
		Expect(allocated.Message).To(ContainSubstring("has no network ID yet"))
	})

	It("gives the address up once the ElasticIP stops naming it", func() {
		elasticIP := createPodTestElasticIP("203.0.113.56", 4206)
		iface := createElasticIPNetworkInterface(elasticIP, "ext0")
		setElasticIPHolder(elasticIP, juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface, iface.Name)
		reconcileNetworkInterface(iface)
		Expect(getNetworkInterface(iface).Status.Address).To(Equal("203.0.113.56/32"))

		setElasticIPHolder(elasticIP, juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface, "next-pod.ext0")
		reconcileNetworkInterface(iface)

		current := getNetworkInterface(iface)
		Expect(current.Status.Address).To(BeEmpty())
		Expect(current.Status.Routes).To(BeEmpty())
		Expect(current.Status.Rules).To(BeEmpty())
		expectWaitingForElasticIP(iface, `NetworkInterface "next-pod.ext0"`)
	})

	It("lets go of its finalizer without an AllocationClaim to release", func() {
		elasticIP := createPodTestElasticIP("203.0.113.57", 4207)
		iface := createElasticIPNetworkInterface(elasticIP, juneauv1alpha1.PodPrimaryInterfaceName)
		setElasticIPHolder(elasticIP, juneauv1alpha1.ElasticIPStatusAttachmentKindNetworkInterface, iface.Name)
		reconcileNetworkInterface(iface)
		Expect(getNetworkInterface(iface).Finalizers).To(ContainElement(networkInterfaceFinalizer))

		Expect(k8sClient.Delete(ctx, iface)).To(Succeed())
		reconcileNetworkInterface(iface)

		err := k8sClient.Get(ctx, client.ObjectKeyFromObject(iface), &juneauv1alpha1.NetworkInterface{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})
})

func createElasticIPNetworkInterface(elasticIP, ifName string) *juneauv1alpha1.NetworkInterface {
	GinkgoHelper()
	podName := uniqueTestName("eip-pod")
	iface := &juneauv1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: networkInterfaceNameForPod(podName, ifName), Namespace: "default"},
		Spec: juneauv1alpha1.NetworkInterfaceSpec{
			PodRef:    juneauv1alpha1.NetworkInterfacePodReference{UID: "uid-" + podName, Name: podName, Interface: ifName},
			NodeName:  "node-eip",
			ElasticIP: elasticIP,
		},
	}
	Expect(k8sClient.Create(context.Background(), iface)).To(Succeed())
	DeferCleanup(func() { cleanupNetworkInterface(context.Background(), iface) })
	return iface
}

// setElasticIPHolder writes status.attachment the way the ElasticIP
// controller would. That controller does not run in the suite.
func setElasticIPHolder(elasticIP string, kind juneauv1alpha1.ElasticIPStatusAttachmentKind, name string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		var current juneauv1alpha1.ElasticIP
		g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: elasticIP}, &current)).To(Succeed())
		current.Status.Phase = juneauv1alpha1.ElasticIPPhaseAttached
		current.Status.Attachment = &juneauv1alpha1.ElasticIPStatusAttachment{Kind: kind, Name: name}
		g.Expect(k8sClient.Status().Update(context.Background(), &current)).To(Succeed())
	}).Should(Succeed())
}

// setElasticIPInConflict writes the status the ElasticIP controller
// writes when an ElasticIPAttachment and a NetworkInterface both use the
// ElasticIP: Error, and nothing named in status.attachment.
func setElasticIPInConflict(elasticIP string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		var current juneauv1alpha1.ElasticIP
		g.Expect(k8sClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: elasticIP}, &current)).To(Succeed())
		current.Status.Phase = juneauv1alpha1.ElasticIPPhaseError
		current.Status.Attachment = nil
		g.Expect(k8sClient.Status().Update(context.Background(), &current)).To(Succeed())
	}).Should(Succeed())
}

func getNetworkInterface(iface *juneauv1alpha1.NetworkInterface) *juneauv1alpha1.NetworkInterface {
	GinkgoHelper()
	var current juneauv1alpha1.NetworkInterface
	Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(iface), &current)).To(Succeed())
	return &current
}

func expectWaitingForElasticIP(iface *juneauv1alpha1.NetworkInterface, messagePart string) {
	GinkgoHelper()
	current := getNetworkInterface(iface)
	Expect(current.Status.Phase).To(Equal(juneauv1alpha1.NetworkInterfacePhasePending))
	Expect(current.Status.Address).To(BeEmpty())
	for _, conditionType := range []string{juneauv1alpha1.NetworkInterfaceStatusAllocated, juneauv1alpha1.NetworkInterfaceStatusReady} {
		condition := meta.FindStatusCondition(current.Status.Conditions, conditionType)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(conditionReasonWaitingForElasticIP))
		Expect(condition.Message).To(ContainSubstring(messagePart))
	}
}

func allocationClaimsFor(iface *juneauv1alpha1.NetworkInterface) []juneauv1alpha1.AllocationClaim {
	GinkgoHelper()
	var claims juneauv1alpha1.AllocationClaimList
	Expect(k8sClient.List(context.Background(), &claims)).To(Succeed())
	var out []juneauv1alpha1.AllocationClaim
	for i := range claims.Items {
		ref := claims.Items[i].Spec.ResourceRef
		if ref.Kind == "NetworkInterface" && ref.Namespace == iface.Namespace && ref.Name == iface.Name {
			out = append(out, claims.Items[i])
		}
	}
	return out
}
