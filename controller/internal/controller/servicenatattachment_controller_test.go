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
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

var _ = Describe("ServiceNATAttachment controller", func() {
	It("allocates an IP from the default Subnet and publishes a NetworkEndpoint", func() {
		nodeName := "snat-node-" + time.Now().Format("150405.000000000")[7:]
		// The default Vpc is bootstrapped as a Service provider with
		// natSourceSubnet=default, so the per-(Node, default Vpc)
		// fan-out names this attachment "<nodeName>.default".
		attachmentName := serviceNATAttachmentName(nodeName, defaultVpcName)

		// Adding a Node triggers the provider-Vpc Node fan-out, which
		// is the canonical way ServiceNATAttachment resources come
		// into being. We do not create the attachment directly so
		// that the test exercises the same code path users will hit
		// in production.
		Expect(k8sClient.Create(ctx, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, &juneauv1alpha1.ServiceNATAttachment{ObjectMeta: metav1.ObjectMeta{Name: attachmentName}})
			_ = k8sClient.Delete(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}})
		})

		Eventually(func(g Gomega) {
			var attachment juneauv1alpha1.ServiceNATAttachment
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: attachmentName}, &attachment)).To(Succeed())
			g.Expect(attachment.Spec.NodeName).To(Equal(nodeName))
			g.Expect(attachment.Spec.Vpc).To(Equal(defaultVpcName))
			g.Expect(attachment.Status.AssignedIP).NotTo(BeEmpty())
			ip := net.ParseIP(attachment.Status.AssignedIP)
			g.Expect(ip).NotTo(BeNil(), "assignedIP should be a valid IP")
			g.Expect(ip.To4()).NotTo(BeNil())
			g.Expect(attachment.Status.AssignedMAC).To(MatchRegexp(`^02:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$`))
			g.Expect(attachment.Status.Subnet).To(Equal("default"))
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())

		Eventually(func(g Gomega) {
			var endpoint juneauv1alpha1.NetworkEndpoint
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{
				Namespace: "kube-system",
				Name:      serviceNATEndpointName(attachmentName),
			}, &endpoint)).To(Succeed())
			g.Expect(endpoint.Spec.Kind).To(Equal(juneauv1alpha1.EndpointKindServiceNAT))
			g.Expect(endpoint.Spec.NodeName).To(Equal(nodeName))
			g.Expect(endpoint.Spec.Subnet).To(Equal("default"))
			g.Expect(endpoint.Spec.Address).NotTo(BeEmpty())
			g.Expect(endpoint.Spec.MACAddress).NotTo(BeEmpty())
		}).WithTimeout(10 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
	})
})
