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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("NetworkEndpoint controller", func() {
	It("follows the Node's InternalIP into status.nodeIP", func() {
		suffix := time.Now().Format("150405.000000000")[7:]
		nodeName := "nwep-node-" + suffix
		endpointName := "nwep-follow-" + suffix

		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() {
			cleanupNodeTestArtifacts(nodeName)
		})
		setNodeInternalIP(nodeName, "192.0.2.10")

		endpoint := &juneauv1alpha1.NetworkEndpoint{
			ObjectMeta: metav1.ObjectMeta{Namespace: nodeEndpointNamespace, Name: endpointName},
			Spec: juneauv1alpha1.NetworkEndpointSpec{
				Kind:       juneauv1alpha1.EndpointKindNode,
				NodeName:   nodeName,
				Subnet:     JuneauNodeDefaultSubnet,
				Address:    "10.16.0.200/16",
				MACAddress: "02:00:0a:10:00:c8",
			},
		}
		Expect(k8sClient.Create(ctx, endpoint)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, endpoint)
		})

		endpointKey := client.ObjectKey{Namespace: nodeEndpointNamespace, Name: endpointName}
		Eventually(func(g Gomega) {
			var current juneauv1alpha1.NetworkEndpoint
			g.Expect(k8sClient.Get(ctx, endpointKey, &current)).To(Succeed())
			g.Expect(current.Status.NodeIP).To(Equal("192.0.2.10"))
		}).Should(Succeed())

		By("moving the Node to a new underlay IP, as a host restart would")
		setNodeInternalIP(nodeName, "192.0.2.11")

		Eventually(func(g Gomega) {
			var current juneauv1alpha1.NetworkEndpoint
			g.Expect(k8sClient.Get(ctx, endpointKey, &current)).To(Succeed())
			g.Expect(current.Status.NodeIP).To(Equal("192.0.2.11"))
		}).Should(Succeed())
	})
})

func setNodeInternalIP(nodeName, ip string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		var node corev1.Node
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: nodeName}, &node)).To(Succeed())
		node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}
		g.Expect(k8sClient.Status().Update(ctx, &node)).To(Succeed())
	}).Should(Succeed())
}
