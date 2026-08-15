package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Juneau VpcEndpoint", func() {
	It("reaches a provider Service through a Vpc-local address without enabling Service consumption", func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2))

		const base = "vpc-endpoint"
		namespace := "e2e-" + base
		vpcName := "vpc-" + base
		subnetName := "subnet-" + base
		serviceName := "service-" + base
		endpointName := "endpoint-" + base

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "vpcendpoint", endpointName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpcName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcName, "--ignore-not-found=true")
		})

		By("creating a Vpc without the Service consumer capability")
		Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, vpcName, subnetName, vpcName, cidrForScenario(base, 0)))).To(Succeed())
		waitSubnetReady(subnetName)
		createNamespace(namespace)

		By("creating an ordinary Service in the default Vpc")
		Expect(applyManifest(podManifest(namespace, serverPodName, workerNodes[0], "", true))).To(Succeed())
		Expect(applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
spec:
  selector:
    app: %s
  ports:
    - name: http
      port: 80
      targetPort: 80
`, namespace, serviceName, serverPodName))).To(Succeed())

		By("creating a caller on another Node and a VpcEndpoint")
		Expect(applyManifest(podManifest(namespace, clientPodName, workerNodes[1], subnetName, false))).To(Succeed())
		Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: VpcEndpoint
metadata:
  name: %s
spec:
  vpc: %s
  subnet: %s
  service:
    namespace: %s
    name: %s
`, endpointName, vpcName, subnetName, namespace, serviceName))).To(Succeed())
		waitPodsReady(namespace, serverPodName, clientPodName)
		waitServiceEndpoints(namespace, serviceName)

		var endpointAddress string
		Eventually(func(g Gomega) {
			ready, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].status}`, "get", "vpcendpoint", endpointName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(ready)).To(Equal("True"))
			endpointAddress, err = kubectlJSONPath(repoRoot, `{.status.address}`, "get", "vpcendpoint", endpointName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(endpointAddress)).NotTo(BeEmpty())
		}).Should(Succeed())
		endpointAddress = strings.TrimSpace(endpointAddress)

		By("keeping the consumer Vpc free of the cluster Service CIDR")
		consume, err := kubectlJSONPath(repoRoot, `{.spec.service.consume}`, "get", "vpc", vpcName)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(consume)).To(BeEmpty())
		Eventually(func(g Gomega) {
			routes, routeErr := kubectlJSONPath(repoRoot, `{range .status.routes[*]}{.dst}{"="}{.via.type}{"\n"}{end}`, "get", "routetable", vpcName)
			g.Expect(routeErr).NotTo(HaveOccurred())
			g.Expect(routes).To(ContainSubstring(endpointAddress + "/32=service"))
			g.Expect(routes).NotTo(ContainSubstring("10.96.0.0/"))
		}).Should(Succeed())

		By("reaching the backend through the Vpc-local endpoint address")
		Eventually(func(g Gomega) {
			out, curlErr := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPodName, "--",
				"curl", "-sS", "--max-time", "5", "-w", "%{http_code}", "-o", "/dev/null", "http://"+endpointAddress)
			g.Expect(curlErr).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(strings.TrimSpace(out)).To(Equal("200"))
		}).Should(Succeed())

		By("not exposing the backing ClusterIP directly to the consumer Vpc")
		clusterIP, err := kubectlJSONPath(repoRoot, `{.spec.clusterIP}`, "-n", namespace, "get", "service", serviceName)
		Expect(err).NotTo(HaveOccurred())
		out, curlErr := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPodName, "--",
			"curl", "-sS", "--max-time", "3", strings.TrimSpace("http://"+clusterIP))
		Expect(curlErr).To(HaveOccurred(), "direct ClusterIP unexpectedly succeeded: %s", out)

		By("removing the route and dataplane entry when the VpcEndpoint is deleted")
		Expect(run(repoRoot, "kubectl", "delete", "vpcendpoint", endpointName, "--wait=true")).To(Succeed())
		Eventually(func(g Gomega) {
			routes, routeErr := kubectlJSONPath(repoRoot, `{range .status.routes[*]}{.dst}{"\n"}{end}`, "get", "routetable", vpcName)
			g.Expect(routeErr).NotTo(HaveOccurred())
			g.Expect(routes).NotTo(ContainSubstring(endpointAddress + "/32"))
		}).Should(Succeed())
		out, curlErr = kubectlOutput(repoRoot, "exec", "-n", namespace, clientPodName, "--",
			"curl", "-sS", "--max-time", "3", "http://"+endpointAddress)
		Expect(curlErr).To(HaveOccurred(), "deleted VpcEndpoint unexpectedly remained reachable: %s", out)
	})
})
