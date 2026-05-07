package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Service LoadBalancer end-to-end test.
//
// Scope: VIP allocation, advertisingNodes calculation,
// Service.status.loadBalancer.ingress propagation, and the
// withdraw-on-no-backend transition. The full data-plane round-trip
// (external curl → backend Pod sees original client IP) requires
// extra plumbing (the e2e BGP test environment + an external
// container that can curl the VIP); we leave that path to the
// existing bgp_router_test machinery and exercise the controller
// surface here.
var _ = Describe("Juneau Service LoadBalancer", func() {
	const (
		lbAddressPoolName     = "e2e-lb-pool"
		lbAddressPoolCIDR     = "203.0.113.0/29"
		lbExternalNetworkName = "e2e-lb-extnet"
	)

	It("allocates a VIP, advertises it from nodes with local backends, and clears it on backend loss", func() {
		base := sanitizeName("svc-lb")
		namespace := "e2e-" + base
		svcName := "web"

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", lbExternalNetworkName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "addresspool", lbAddressPoolName, "--ignore-not-found=true")
		})

		By("creating an AddressPool and ExternalNetwork for the LoadBalancer VIPs")
		Expect(applyAddressPool(lbAddressPoolName, []string{lbAddressPoolCIDR})).To(Succeed())
		Expect(applyExternalNetwork(lbExternalNetworkName, []string{lbAddressPoolName})).To(Succeed())

		createNamespace(namespace)

		By("placing the backend Pod on the first worker node so the SLB has a deterministic local backend set")
		Expect(applyManifest(podManifest(namespace, serverPodName, workerNodes[0], "default", true))).To(Succeed())
		waitPodsReady(namespace, serverPodName)

		By("creating a Juneau-managed LoadBalancer Service")
		Expect(applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/load-balancer-external-network: %s
spec:
  type: LoadBalancer
  loadBalancerClass: juneau.loutres.me/load-balancer
  externalTrafficPolicy: Local
  selector:
    app: %s
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 80
`, namespace, svcName, lbExternalNetworkName, serverPodName))).To(Succeed())

		By("waiting for the controller to allocate a VIP")
		var vip string
		Eventually(func(g Gomega) {
			out, err := kubectlJSONPath(repoRoot, "{.status.vip}",
				"-n", namespace, "get", "serviceloadbalancer", svcName)
			g.Expect(err).NotTo(HaveOccurred())
			vip = strings.TrimSpace(out)
			g.Expect(vip).NotTo(BeEmpty())
		}).Should(Succeed())

		By("checking the parent Service status reflects the VIP")
		Eventually(func(g Gomega) {
			out, err := kubectlJSONPath(repoRoot, "{.status.loadBalancer.ingress[0].ip}",
				"-n", namespace, "get", "service", svcName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal(vip))
		}).Should(Succeed())

		By("waiting for advertisingNodes to include the backend's node")
		Eventually(func(g Gomega) {
			out, err := kubectlJSONPath(repoRoot, "{.status.advertisingNodes}",
				"-n", namespace, "get", "serviceloadbalancer", svcName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring(workerNodes[0]))
		}).Should(Succeed())

		By("verifying the Available condition is True")
		Eventually(func(g Gomega) {
			out, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Available")].status}`,
				"-n", namespace, "get", "serviceloadbalancer", svcName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("True"))
		}).Should(Succeed())

		By("deleting the backend Pod and verifying advertisingNodes empties out")
		runBestEffort(repoRoot, "kubectl", "delete", "pod", "-n", namespace, serverPodName, "--ignore-not-found=true", "--timeout=60s")

		Eventually(func(g Gomega) {
			out, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Available")].reason}`,
				"-n", namespace, "get", "serviceloadbalancer", svcName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("NoReadyBackends"))
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			out, err := kubectlJSONPath(repoRoot, "{.status.advertisingNodes}",
				"-n", namespace, "get", "serviceloadbalancer", svcName)
			g.Expect(err).NotTo(HaveOccurred())
			// Empty array literally renders as either nothing or "[]";
			// either way the worker name must be gone.
			g.Expect(out).NotTo(ContainSubstring(workerNodes[0]))
		}).Should(Succeed())

		By("regression: deleting the Service GCs the SLB resource")
		runBestEffort(repoRoot, "kubectl", "delete", "service", "-n", namespace, svcName, "--ignore-not-found=true", "--timeout=60s")
		Eventually(func(g Gomega) {
			_, err := kubectlJSONPath(repoRoot, "{.metadata.name}",
				"-n", namespace, "get", "serviceloadbalancer", svcName)
			g.Expect(err).To(HaveOccurred(), "ServiceLoadBalancer %s/%s should be gone", namespace, svcName)
		}).Should(Succeed())
	})

	It("rejects LoadBalancer Services that do not set externalTrafficPolicy=Local", func() {
		base := sanitizeName("svc-lb-bad-itp")
		namespace := "e2e-" + base

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", lbExternalNetworkName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "addresspool", lbAddressPoolName, "--ignore-not-found=true")
		})

		Expect(applyAddressPool(lbAddressPoolName, []string{lbAddressPoolCIDR})).To(Succeed())
		Expect(applyExternalNetwork(lbExternalNetworkName, []string{lbAddressPoolName})).To(Succeed())

		createNamespace(namespace)

		// externalTrafficPolicy unset → defaults to Cluster, which the
		// webhook rejects for Juneau-managed LoadBalancer Services.
		err := applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: web
  annotations:
    juneau.loutres.me/load-balancer-external-network: %s
spec:
  type: LoadBalancer
  loadBalancerClass: juneau.loutres.me/load-balancer
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 80
`, namespace, lbExternalNetworkName))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("externalTrafficPolicy=Local"))
	})
})
