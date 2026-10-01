package v1alpha1

import (
	"context"

	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("VPN admission", func() {
	It("requires a namespaced Secret and protects referenced VPNs from deletion", func() {
		ctx := context.Background()
		vpc := createWebhookVpc()
		subnet := webhookUniqueTestName("subnet")
		Expect(webhookK8sClient.Create(ctx, &juneau.Subnet{ObjectMeta: metav1.ObjectMeta{Name: subnet}, Spec: juneau.SubnetSpec{Vpc: vpc, CIDR: webhookUniqueSubnetCIDR()}})).To(Succeed())
		network := createWebhookExternalNetwork(juneau.ExternalNetworkTypeARP)
		secret := webhookUniqueTestName("psk")
		Expect(webhookK8sClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secret, Namespace: "default"}, Data: map[string][]byte{"key": []byte("test-psk")}})).To(Succeed())
		vpn := &juneau.VPN{ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("vpn"), Namespace: "default"}, Spec: juneau.VPNSpec{Vpc: vpc, Subnet: subnet, ExternalNetwork: network, LocalASN: 65001, RemoteASN: 65002, PeerIKEID: "branch", PSKSecretRef: juneau.VPNSecretRef{Name: secret, Key: "key"}}}
		Expect(webhookK8sClient.Create(ctx, vpn)).To(Succeed())
		var current juneau.VPN
		Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(vpn), &current)).To(Succeed())
		Expect(current.Status.Conditions).To(BeEmpty())
		routes := &juneau.RouteTable{ObjectMeta: metav1.ObjectMeta{Name: webhookUniqueTestName("routes")}, Spec: juneau.RouteTableSpec{Vpc: vpc, Routes: []juneau.Route{{Dst: "192.168.197.0/24", Via: juneau.RouteVia{Type: juneau.ViaVPN, VPN: &juneau.VPNReference{Namespace: vpn.Namespace, Name: vpn.Name}}}}}}
		Expect(webhookK8sClient.Create(ctx, routes)).To(Succeed())
		Expect(webhookK8sClient.Delete(ctx, vpn)).To(MatchError(ContainSubstring("still reference VPN")))
		var rt juneau.RouteTable
		Expect(webhookK8sClient.Get(ctx, client.ObjectKeyFromObject(routes), &rt)).To(Succeed())
		rt.Spec.Routes = nil
		Expect(webhookK8sClient.Update(ctx, &rt)).To(Succeed())
		Expect(webhookK8sClient.Delete(ctx, vpn)).To(Succeed())
	})
})
