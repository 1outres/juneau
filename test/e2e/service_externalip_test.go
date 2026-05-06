package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Service.spec.externalIPs adds extra VIPs that map to the same
// backends as the ClusterIP. The data-plane integration involves both
// sides of the controller: the routetable controller injects a /32
// SERVICE route per externalIP into the owner Vpc's RouteTables, and
// the daemon-side service reconciler programs service_map / backend_map
// entries keyed on each externalIP. Assert both pieces by curling the
// externalIP from a client Pod in the owner Vpc, plus a regression
// check on the ClusterIP path.
var _ = Describe("Juneau Service externalIPs", func() {
	It("routes Pod traffic to backends through Service.spec.externalIPs", func() {
		base := sanitizeName("svc-externalip")
		namespace := "e2e-" + base
		vpcName := "vpc-" + base
		subnetName := "subnet-" + base
		subnetCIDR := "10.220.0.0/24"
		// 198.51.100.0/24 (TEST-NET-2) is well outside both the Subnet
		// CIDR above and the cluster Service CIDR (10.96.0.0/12), so
		// LPM /32 injection is unambiguous and the IP cannot collide
		// with anything else in the kind cluster.
		externalIP := "198.51.100.50"
		svcName := "web"

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpcName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcName, "--ignore-not-found=true")
		})

		By("creating a Vpc with service.consume=true and a Subnet")
		Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  service:
    consume: true
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, vpcName, subnetName, vpcName, subnetCIDR))).To(Succeed())
		waitSubnetReady(subnetName)

		createNamespace(namespace)

		By("placing the server and the client in the custom Vpc Subnet")
		Expect(applyManifest(podManifest(namespace, serverPodName, workerNodes[0], subnetName, true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientPodName, workerNodes[0], subnetName, false))).To(Succeed())
		waitPodsReady(namespace, serverPodName, clientPodName)

		By("creating a Service with externalIPs in the same Vpc")
		Expect(applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/vpc: %s
spec:
  selector:
    app: %s
  externalIPs:
    - %s
  ports:
    - port: 80
      targetPort: 80
`, namespace, svcName, vpcName, serverPodName, externalIP))).To(Succeed())
		waitServiceEndpoints(namespace, svcName)

		clusterIP, err := kubectlJSONPath(repoRoot, `{.spec.clusterIP}`, "-n", namespace, "get", "service", svcName)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(clusterIP)).NotTo(BeEmpty())

		By("verifying the client reaches the backends through the externalIP")
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPodName, "--",
				"curl", "-sS", "--max-time", "5", fmt.Sprintf("http://%s/", externalIP))
			g.Expect(err).NotTo(HaveOccurred(), "curl via externalIP failed: %s", out)
			g.Expect(strings.ToLower(out)).To(ContainSubstring("welcome to nginx"))
		}).Should(Succeed())

		By("regression: the ClusterIP path still works")
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPodName, "--",
				"curl", "-sS", "--max-time", "5", fmt.Sprintf("http://%s/", strings.TrimSpace(clusterIP)))
			g.Expect(err).NotTo(HaveOccurred(), "curl via ClusterIP failed: %s", out)
			g.Expect(strings.ToLower(out)).To(ContainSubstring("welcome to nginx"))
		}).Should(Succeed())
	})
})
