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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ExternalNetwork controller", func() {
	It("fans out one attachment per Node for a BGP ExternalNetwork", func() {
		ctx := context.Background()
		createFanoutNodes(ctx, 2)
		networkName := createFanoutExternalNetwork(ctx, juneauv1alpha1.ExternalNetworkTypeBGP)
		createFanoutNATGateway(ctx, networkName)

		Expect(reconcileExternalNetwork(ctx, networkName)).To(Succeed())
		Expect(fanoutAttachmentNodeNames(ctx, networkName)).To(ConsistOf(listNodeNames(ctx)))
	})

	It("fans out one attachment per Node for an ARP ExternalNetwork", func() {
		ctx := context.Background()
		createFanoutNodes(ctx, 2)
		networkName := createFanoutExternalNetwork(ctx, juneauv1alpha1.ExternalNetworkTypeARP)
		createFanoutNATGateway(ctx, networkName)

		Expect(reconcileExternalNetwork(ctx, networkName)).To(Succeed())
		Expect(fanoutAttachmentNodeNames(ctx, networkName)).To(ConsistOf(listNodeNames(ctx)))
	})

	It("owns the attachments it fans out", func() {
		ctx := context.Background()
		createFanoutNodes(ctx, 1)
		networkName := createFanoutExternalNetwork(ctx, juneauv1alpha1.ExternalNetworkTypeARP)
		createFanoutNATGateway(ctx, networkName)

		Expect(reconcileExternalNetwork(ctx, networkName)).To(Succeed())

		var attachments juneauv1alpha1.ExternalNetworkAttachmentList
		Expect(k8sClient.List(ctx, &attachments)).To(Succeed())
		matched := 0
		for i := range attachments.Items {
			if attachments.Items[i].Spec.ExternalNetwork != networkName {
				continue
			}
			matched++
			Expect(attachments.Items[i].OwnerReferences).To(HaveLen(1))
			Expect(attachments.Items[i].OwnerReferences[0].Kind).To(Equal("ExternalNetwork"))
			Expect(attachments.Items[i].OwnerReferences[0].Name).To(Equal(networkName))
		}
		Expect(matched).To(BeNumerically(">", 0))
	})

	It("does not fan out when no NATGateway references the ExternalNetwork", func() {
		ctx := context.Background()
		createFanoutNodes(ctx, 1)
		networkName := createFanoutExternalNetwork(ctx, juneauv1alpha1.ExternalNetworkTypeARP)

		Expect(reconcileExternalNetwork(ctx, networkName)).To(Succeed())
		Expect(fanoutAttachmentNodeNames(ctx, networkName)).To(BeEmpty())
	})
})

var _ = Describe("ExternalNetwork network ID", func() {
	It("takes its network ID from the pool Subnet and L2Network VNIs come from", func() {
		ctx := context.Background()
		networkName := createFanoutExternalNetwork(ctx, juneauv1alpha1.ExternalNetworkTypeBGP)

		networkID := waitForExternalNetworkID(ctx, networkName)

		var network juneauv1alpha1.ExternalNetwork
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: networkName}, &network)).To(Succeed())
		var claim juneauv1alpha1.AllocationClaim
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: externalNetworkIDClaimName(networkName)}, &claim)).To(Succeed())
		Expect(claim.Spec.PoolRefs).To(Equal([]juneauv1alpha1.AllocationPoolReference{{Name: allocationPoolSubnetVNI}}))
		Expect(claim.Spec.Attribute).To(Equal("status.networkID"))
		Expect(claim.Status.Value.Number).To(Equal(uint64(networkID)))
		owner := metav1.GetControllerOf(&claim)
		Expect(owner).NotTo(BeNil())
		Expect(owner.Kind).To(Equal("ExternalNetwork"))
		Expect(owner.UID).To(Equal(network.UID))
	})

	It("never shares a network ID with another ExternalNetwork, a Subnet or an L2Network", func() {
		ctx := context.Background()
		l2 := waitForReadyL2Network(createTestL2Network(createReadyTestVpc(), ""))
		first := waitForExternalNetworkID(ctx, createFanoutExternalNetwork(ctx, juneauv1alpha1.ExternalNetworkTypeBGP))
		second := waitForExternalNetworkID(ctx, createFanoutExternalNetwork(ctx, juneauv1alpha1.ExternalNetworkTypeARP))

		var defaultSubnet juneauv1alpha1.Subnet
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "default"}, &defaultSubnet)).To(Succeed())
		Expect(defaultSubnet.Status.VNI).NotTo(BeZero())

		Expect(first).NotTo(BeElementOf(second, l2.Status.VNI, defaultSubnet.Status.VNI))
		Expect(second).NotTo(BeElementOf(l2.Status.VNI, defaultSubnet.Status.VNI))
	})

	It("keeps the network ID it was given", func() {
		ctx := context.Background()
		networkName := createFanoutExternalNetwork(ctx, juneauv1alpha1.ExternalNetworkTypeARP)
		networkID := waitForExternalNetworkID(ctx, networkName)

		Expect(reconcileExternalNetwork(ctx, networkName)).To(Succeed())
		var network juneauv1alpha1.ExternalNetwork
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: networkName}, &network)).To(Succeed())
		Expect(network.Status.NetworkID).To(Equal(networkID))
	})
})

func waitForExternalNetworkID(ctx context.Context, name string) uint32 {
	GinkgoHelper()
	var networkID uint32
	Eventually(func(g Gomega) {
		g.Expect(reconcileExternalNetwork(ctx, name)).To(Succeed())
		var network juneauv1alpha1.ExternalNetwork
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &network)).To(Succeed())
		g.Expect(network.Status.NetworkID).NotTo(BeZero())
		networkID = network.Status.NetworkID
	}).Should(Succeed())
	DeferCleanup(func() {
		_ = k8sClient.Delete(ctx, &juneauv1alpha1.AllocationClaim{ObjectMeta: metav1.ObjectMeta{Name: externalNetworkIDClaimName(name)}})
	})
	return networkID
}

func reconcileExternalNetwork(ctx context.Context, name string) error {
	reconciler := &ExternalNetworkReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
	return err
}

func createFanoutNodes(ctx context.Context, count int) []string {
	names := make([]string, 0, count)
	for i := 0; i < count; i++ {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("fanout-node")}}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() {
			cleanupNodeTestArtifacts(node.Name)
		})
		names = append(names, node.Name)
	}
	return names
}

func createFanoutExternalNetwork(ctx context.Context, networkType juneauv1alpha1.ExternalNetworkType) string {
	mode := juneauv1alpha1.AddressPoolAdvertiseModeBGP
	addresses := []string{"10.131.0.0/24"}
	if networkType == juneauv1alpha1.ExternalNetworkTypeARP {
		mode = juneauv1alpha1.AddressPoolAdvertiseModeARP
		addresses = []string{"10.131.0.10-10.131.0.20"}
	}
	poolName := createExternalAddressPool(ctx, mode, addresses)
	return createExternalNetworkWithPools(ctx, networkType, poolName)
}

func createFanoutNATGateway(ctx context.Context, networkName string) string {
	natGateway := &juneauv1alpha1.NATGateway{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueTestName("natgateway")},
		Spec: juneauv1alpha1.NATGatewaySpec{
			Vpc:             "default",
			ExternalNetwork: networkName,
		},
	}
	Expect(k8sClient.Create(ctx, natGateway)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, natGateway))).To(Succeed())
	})
	return natGateway.Name
}

func fanoutAttachmentNodeNames(ctx context.Context, networkName string) []string {
	var attachments juneauv1alpha1.ExternalNetworkAttachmentList
	Expect(k8sClient.List(ctx, &attachments)).To(Succeed())

	nodeNames := make([]string, 0, len(attachments.Items))
	for i := range attachments.Items {
		if attachments.Items[i].Spec.ExternalNetwork != networkName {
			continue
		}
		attachment := &attachments.Items[i]
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, attachment))).To(Succeed())
		})
		nodeNames = append(nodeNames, attachment.Spec.NodeName)
	}
	return nodeNames
}

func listNodeNames(ctx context.Context) []string {
	var nodes corev1.NodeList
	Expect(k8sClient.List(ctx, &nodes)).To(Succeed())
	names := make([]string, 0, len(nodes.Items))
	for i := range nodes.Items {
		names = append(names, nodes.Items[i].Name)
	}
	return names
}
