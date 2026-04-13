package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Juneau cluster connectivity", Ordered, func() {
	It("provisions a non-default subnet and allows pod-to-pod connectivity", func() {
		By("creating a dedicated VPC and Subnet")
		manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
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
`, testVpcName, testSubnetName, testVpcName, testSubnetCIDR)

		By("applying the VPC and Subnet manifest")
		Expect(applyManifest(manifest)).To(Succeed())

		By("waiting for the subnet to become ready")
		Eventually(func(g Gomega) {
			ready, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].status}`, "get", "subnet", testSubnetName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(ready).To(Equal("True"))

			gateway, err := kubectlJSONPath(repoRoot, `{.status.gateway}`, "get", "subnet", testSubnetName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(gateway).NotTo(BeEmpty())
		}).Should(Succeed())

		By("creating client and server pods on the non-default subnet")
		workload := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
---
apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: server
  annotations:
    juneau.loutres.me/subnet: %s
spec:
  containers:
    - name: server
      image: nginx:1.27
      ports:
        - containerPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: client
  annotations:
    juneau.loutres.me/subnet: %s
spec:
  containers:
    - name: client
      image: curlimages/curl:8.12.1
      command: ["sleep", "3600"]
`, workloadNamespace, workloadNamespace, testSubnetName, workloadNamespace, testSubnetName)
		Expect(applyManifest(workload)).To(Succeed())

		By("waiting for both pods to become Ready")
		Eventually(func(g Gomega) {
			g.Expect(run(repoRoot, "kubectl", "wait", "-n", workloadNamespace, "--for=condition=Ready", "pod/server", "pod/client", "--timeout=30s")).To(Succeed())
		}).Should(Succeed())

		By("verifying that Juneau created the expected runtime resources")
		Eventually(func(g Gomega) {
			nwifaceSubnet, err := kubectlJSONPath(repoRoot, `{.spec.subnet}`, "-n", workloadNamespace, "get", "networkinterface", "server.eth0")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(nwifaceSubnet).To(Equal(testSubnetName))

			nwepSubnet, err := kubectlJSONPath(repoRoot, `{.spec.subnet}`, "-n", workloadNamespace, "get", "networkendpoint", "server.eth0")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(nwepSubnet).To(Equal(testSubnetName))
		}).Should(Succeed())

		By("curling the server pod from the client pod")
		serverIP, err := kubectlJSONPath(repoRoot, `{.status.podIP}`, "-n", workloadNamespace, "get", "pod", "server")
		Expect(err).NotTo(HaveOccurred())
		Expect(serverIP).NotTo(BeEmpty())

		Eventually(func(g Gomega) {
			output, err := kubectlOutput(repoRoot, "exec", "-n", workloadNamespace, "client", "--", "curl", "-sS", fmt.Sprintf("http://%s", serverIP))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.ToLower(output)).To(ContainSubstring("welcome to nginx"))
		}).Should(Succeed())
	})
})

func applyManifest(manifest string) error {
	cmdArgs := []string{"apply", "-f", "-"}
	return runWithStdin(repoRoot, manifest, "kubectl", cmdArgs...)
}
