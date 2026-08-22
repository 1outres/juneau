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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ExternalNetworkAttachment controller", func() {
	It("advertises the assigned IP with a BGPAdvertisement for a BGP ExternalNetwork", func() {
		ctx := context.Background()
		poolName := createExternalAddressPool(ctx, juneauv1alpha1.AddressPoolAdvertiseModeBGP, []string{"10.132.0.0/29"})
		networkName := createExternalNetworkWithPools(ctx, juneauv1alpha1.ExternalNetworkTypeBGP, poolName)
		attachment := createExternalNetworkAttachment(ctx, networkName, "node-bgp")

		address := waitForAttachmentAddress(ctx, attachment.Name)

		var advertisement juneauv1alpha1.BGPAdvertisement
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: externalNetworkAttachmentAdvertisementName(attachment.Name)}, &advertisement)).To(Succeed())
		Expect(advertisement.Spec.AddressPools).To(ConsistOf(poolName))
		Expect(advertisement.Spec.NodeName).To(Equal("node-bgp"))
		Expect(advertisement.Spec.Prefix).To(Equal(fmt.Sprintf("%s/32", address)))

		var arpAdvertisement juneauv1alpha1.ARPAdvertisement
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: externalNetworkAttachmentAdvertisementName(attachment.Name)}, &arpAdvertisement)).NotTo(Succeed())
	})

	It("advertises the assigned IP with an ARPAdvertisement for an ARP ExternalNetwork", func() {
		ctx := context.Background()
		poolName := createExternalAddressPool(ctx, juneauv1alpha1.AddressPoolAdvertiseModeARP, []string{"10.133.0.10-10.133.0.20"})
		networkName := createExternalNetworkWithPools(ctx, juneauv1alpha1.ExternalNetworkTypeARP, poolName)
		attachment := createExternalNetworkAttachment(ctx, networkName, "node-arp")

		address := waitForAttachmentAddress(ctx, attachment.Name)

		var advertisement juneauv1alpha1.ARPAdvertisement
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: externalNetworkAttachmentAdvertisementName(attachment.Name)}, &advertisement)).To(Succeed())
		Expect(advertisement.Spec.ExternalNetwork).To(Equal(networkName))
		Expect(advertisement.Spec.Address).To(Equal(address))
		Expect(advertisement.Spec.NodeName).To(Equal("node-arp"))

		var bgpAdvertisement juneauv1alpha1.BGPAdvertisement
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: externalNetworkAttachmentAdvertisementName(attachment.Name)}, &bgpAdvertisement)).NotTo(Succeed())
	})

	It("owns the ARPAdvertisement so Kubernetes reaps it with the attachment", func() {
		// envtest does not run the garbage collector, so assert the
		// OwnerReference a real cluster's GC acts on instead.
		ctx := context.Background()
		poolName := createExternalAddressPool(ctx, juneauv1alpha1.AddressPoolAdvertiseModeARP, []string{"10.134.0.10-10.134.0.20"})
		networkName := createExternalNetworkWithPools(ctx, juneauv1alpha1.ExternalNetworkTypeARP, poolName)
		attachment := createExternalNetworkAttachment(ctx, networkName, "node-arp-owner")

		waitForAttachmentAddress(ctx, attachment.Name)

		var advertisement juneauv1alpha1.ARPAdvertisement
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: externalNetworkAttachmentAdvertisementName(attachment.Name)}, &advertisement)).To(Succeed())
		Expect(advertisement.OwnerReferences).To(HaveLen(1))
		ref := advertisement.OwnerReferences[0]
		Expect(ref.Kind).To(Equal("ExternalNetworkAttachment"))
		Expect(ref.Name).To(Equal(attachment.Name))
		Expect(ref.UID).To(Equal(attachment.UID))
		Expect(ref.Controller).NotTo(BeNil())
		Expect(*ref.Controller).To(BeTrue())
		Expect(ref.BlockOwnerDeletion).NotTo(BeNil())
		Expect(*ref.BlockOwnerDeletion).To(BeTrue())
	})

	It("removes an advertisement of the kind the ExternalNetwork no longer uses", func() {
		ctx := context.Background()
		poolName := createExternalAddressPool(ctx, juneauv1alpha1.AddressPoolAdvertiseModeARP, []string{"10.135.0.10-10.135.0.20"})
		networkName := createExternalNetworkWithPools(ctx, juneauv1alpha1.ExternalNetworkTypeARP, poolName)
		attachment := createExternalNetworkAttachment(ctx, networkName, "node-arp-stale")

		waitForAttachmentAddress(ctx, attachment.Name)

		stale := &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: externalNetworkAttachmentAdvertisementName(attachment.Name)},
			Spec: juneauv1alpha1.BGPAdvertisementSpec{
				AddressPools: []string{poolName},
				NodeName:     "node-arp-stale",
				Prefix:       "10.135.0.10/32",
			},
		}
		Expect(k8sClient.Create(ctx, stale)).To(Succeed())

		Expect(reconcileExternalNetworkAttachment(ctx, attachment.Name)).To(Succeed())

		var advertisement juneauv1alpha1.BGPAdvertisement
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: stale.Name}, &advertisement)).NotTo(Succeed())
	})

	It("reports InvalidAddressPool when the AddressPool advertise mode does not match the ExternalNetwork type", func() {
		ctx := context.Background()
		poolName := createExternalAddressPool(ctx, juneauv1alpha1.AddressPoolAdvertiseModeBGP, []string{"10.136.0.0/29"})
		networkName := createExternalNetworkWithPools(ctx, juneauv1alpha1.ExternalNetworkTypeARP, poolName)
		attachment := createExternalNetworkAttachment(ctx, networkName, "node-mismatch")

		Expect(reconcileExternalNetworkAttachment(ctx, attachment.Name)).To(Succeed())

		var current juneauv1alpha1.ExternalNetworkAttachment
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: attachment.Name}, &current)).To(Succeed())
		ready := meta.FindStatusCondition(current.Status.Conditions, externalNetworkAttachmentConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal(externalNetworkAttachmentReasonInvalidPool))
		Expect(ready.Message).To(ContainSubstring("advertiseMode"))
	})
})

func reconcileExternalNetworkAttachment(ctx context.Context, name string) error {
	reconciler := &ExternalNetworkAttachmentReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
	return err
}

func waitForAttachmentAddress(ctx context.Context, name string) string {
	var address string
	Eventually(func(g Gomega) {
		g.Expect(reconcileExternalNetworkAttachment(ctx, name)).To(Succeed())

		var attachment juneauv1alpha1.ExternalNetworkAttachment
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &attachment)).To(Succeed())
		g.Expect(attachment.Status.AssignedIP).NotTo(BeEmpty())
		address = attachment.Status.AssignedIP
	}).Should(Succeed())
	return address
}

func createExternalAddressPool(ctx context.Context, mode juneauv1alpha1.AddressPoolAdvertiseMode, addresses []string) string {
	pool := &juneauv1alpha1.AddressPool{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("addresspool")},
		Spec: juneauv1alpha1.AddressPoolSpec{
			AdvertiseMode: mode,
			Addresses:     addresses,
		},
	}
	Expect(k8sClient.Create(ctx, pool)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, pool))).To(Succeed())
	})
	return pool.Name
}

func createExternalNetworkWithPools(ctx context.Context, networkType juneauv1alpha1.ExternalNetworkType, poolNames ...string) string {
	network := &juneauv1alpha1.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("externalnetwork")},
		Spec: juneauv1alpha1.ExternalNetworkSpec{
			Type:         networkType,
			AddressPools: poolNames,
		},
	}
	Expect(k8sClient.Create(ctx, network)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, network))).To(Succeed())
	})
	return network.Name
}

func createExternalNetworkAttachment(ctx context.Context, networkName, nodeName string) *juneauv1alpha1.ExternalNetworkAttachment {
	attachment := &juneauv1alpha1.ExternalNetworkAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("ena")},
		Spec: juneauv1alpha1.ExternalNetworkAttachmentSpec{
			ExternalNetwork: networkName,
			NodeName:        nodeName,
		},
	}
	Expect(k8sClient.Create(ctx, attachment)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, attachment))).To(Succeed())
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &juneauv1alpha1.ARPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: externalNetworkAttachmentAdvertisementName(attachment.Name)},
		}))).To(Succeed())
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &juneauv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: externalNetworkAttachmentAdvertisementName(attachment.Name)},
		}))).To(Succeed())
	})
	return attachment
}
