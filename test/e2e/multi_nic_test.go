package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	multiNICNamespace = "e2e-multi-nic"
	multiNICVpc       = "vpc-multi-nic"

	multiNICPrimarySubnet = "subnet-multi-nic-primary"
	multiNICExtraSubnet   = "subnet-multi-nic-extra"
	multiNICPrimaryCIDR   = "10.240.0.0/24"
	multiNICExtraCIDR     = "10.241.0.0/24"

	multiNICClientPod = "multi-nic-client"
	multiNICServerPod = "multi-nic-server"
	multiNICExtraIf   = "eth1"
)

var _ = Describe("Juneau multi-NIC pods", func() {
	BeforeEach(func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2), "these specs need at least 2 worker nodes")
	})

	It("reaches a pod of another subnet over a second NIC", func() {
		By("creating a VPC with one subnet per NIC")
		Expect(applyManifest(multiNICNetworkManifest())).To(Succeed())
		DeferCleanup(cleanupMultiNICResources)
		waitSubnetReady(multiNICPrimarySubnet)
		waitSubnetReady(multiNICExtraSubnet)

		createNamespace(multiNICNamespace)

		By("creating a client with a second NIC on the extra subnet")
		Expect(applyManifest(multiNICClientManifest(workerNodes[0]))).To(Succeed())
		By("creating a server whose only NIC sits on the extra subnet")
		Expect(applyManifest(multiNICServerManifest(workerNodes[1]))).To(Succeed())
		waitPodsReady(multiNICNamespace, multiNICClientPod, multiNICServerPod)

		By("checking Juneau built runtime resources for both NICs of the client")
		assertPodNetwork(multiNICNamespace, multiNICClientPod, multiNICPrimarySubnet)
		assertPodNICNetwork(multiNICNamespace, multiNICClientPod, multiNICExtraIf, multiNICExtraSubnet)

		By("checking the extra NIC carries an address of the extra subnet")
		extraAddress := podNICAddress(multiNICNamespace, multiNICClientPod, multiNICExtraIf)
		Expect(extraAddress).To(HavePrefix("10.241.0."))
		assertPodInterfaceAddress(multiNICNamespace, multiNICClientPod, multiNICExtraIf, extraAddress)

		By("checking the primary NIC still owns the pod address and the default route")
		Expect(mustPodIP(multiNICNamespace, multiNICClientPod)).To(HavePrefix("10.240.0."))
		assertPodHasSingleDefaultRoute(multiNICNamespace, multiNICClientPod)

		By("checking the extra NIC reaches the server on the same subnet")
		assertPodConnectivity(multiNICNamespace, multiNICClientPod, multiNICServerPod)

		By("checking the server answers back to the address of the extra NIC")
		assertPodPing(multiNICNamespace, multiNICServerPod, extraAddress)
	})
})

// assertPodNICNetwork is assertPodNetwork for a NIC other than the
// primary one.
func assertPodNICNetwork(namespace string, podName string, ifName string, expectedSubnet string) {
	Eventually(func(g Gomega) {
		nwifaceSubnet, err := kubectlJSONPath(repoRoot, `{.spec.subnet}`, "-n", namespace, "get", "networkinterface", podName+"."+ifName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(nwifaceSubnet)).To(Equal(expectedSubnet))

		nwepSubnet, err := kubectlJSONPath(repoRoot, `{.spec.subnet}`, "-n", namespace, "get", "networkendpoint", podName+"."+ifName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(nwepSubnet)).To(Equal(expectedSubnet))
	}).Should(Succeed())
}

// podNICAddress returns the address Juneau allocated to one NIC, without
// its prefix length.
func podNICAddress(namespace string, podName string, ifName string) string {
	GinkgoHelper()
	var address string
	Eventually(func(g Gomega) {
		out, err := kubectlJSONPath(repoRoot, `{.status.address}`, "-n", namespace, "get", "networkinterface", podName+"."+ifName)
		g.Expect(err).NotTo(HaveOccurred())
		address = strings.TrimSpace(out)
		g.Expect(address).To(ContainSubstring("/"))
	}).Should(Succeed())
	return strings.Split(address, "/")[0]
}

// assertPodInterfaceAddress requires the named interface inside the pod
// to carry the address Juneau allocated to it.
func assertPodInterfaceAddress(namespace string, podName string, ifName string, address string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--", "ip", "-o", "-4", "addr", "show", ifName)
		g.Expect(err).NotTo(HaveOccurred(), "ip addr output: %s", out)
		g.Expect(out).To(ContainSubstring(address), "ip addr output: %s", out)
	}).Should(Succeed())
}

// assertPodHasSingleDefaultRoute requires the pod to keep exactly one
// default route. An extra NIC that claimed one too would either fail to
// install it or start stealing traffic from the primary NIC.
func assertPodHasSingleDefaultRoute(namespace string, podName string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--", "ip", "-4", "route", "show", "default")
		g.Expect(err).NotTo(HaveOccurred(), "ip route output: %s", out)
		var defaults []string
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if strings.TrimSpace(line) != "" {
				defaults = append(defaults, line)
			}
		}
		g.Expect(defaults).To(HaveLen(1), "ip route output: %s", out)
		g.Expect(defaults[0]).To(ContainSubstring("dev " + podIfaceName))
	}).Should(Succeed())
}

func multiNICNetworkManifest() string {
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
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
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, multiNICVpc,
		multiNICPrimarySubnet, multiNICVpc, multiNICPrimaryCIDR,
		multiNICExtraSubnet, multiNICVpc, multiNICExtraCIDR)
}

func multiNICClientManifest(nodeName string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/subnet: %s
    juneau.loutres.me/networks: |
      [{"interface": "%s", "subnet": "%s"}]
spec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: client
      image: %s
      command: ["sleep", "3600"]
`, multiNICNamespace, multiNICClientPod, multiNICPrimarySubnet,
		multiNICExtraIf, multiNICExtraSubnet, nodeName, netshootImage)
}

func multiNICServerManifest(nodeName string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/subnet: %s
spec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: server
      image: nginx:1.27
      ports:
        - containerPort: 80
`, multiNICNamespace, multiNICServerPod, multiNICExtraSubnet, nodeName)
}

func cleanupMultiNICResources() {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", multiNICNamespace, "--ignore-not-found=true", "--timeout=60s")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", multiNICPrimarySubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", multiNICExtraSubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", multiNICVpc, "--ignore-not-found=true")
}
