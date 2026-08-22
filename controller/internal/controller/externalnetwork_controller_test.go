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
