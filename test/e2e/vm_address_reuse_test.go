package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	vmReuseServerContainer = "server"
	vmReuseClientContainer = "client"
	vmReusePeerPodName     = "peer"
)

var _ = Describe("Juneau virtual machine address reuse", func() {
	BeforeEach(func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2), "these specs need at least 2 worker nodes")
	})

	It("keeps the re-used address reachable in both directions", func() {
		const namespace = "e2e-vm-reuse-traffic"
		const vmName = "vm-reuse-traffic"
		firstPod := "virt-launcher-" + vmName + "-aaaaa"
		secondPod := "virt-launcher-" + vmName + "-bbbbb"

		setupVMReuseNamespace(namespace, vmName, firstPod, secondPod)

		By("running a virt-launcher pod and a peer on another node")
		Expect(applyManifest(vmReusePodManifest(namespace, firstPod, workerNodes[0], vmName))).To(Succeed())
		Expect(applyManifest(vmReusePodManifest(namespace, vmReusePeerPodName, workerNodes[1], ""))).To(Succeed())
		waitPodsReady(namespace, firstPod, vmReusePeerPodName)
		vmAddress := podAddress(namespace, firstPod)
		assertBidirectionalConnectivity(namespace, firstPod, vmReusePeerPodName)

		By("restarting the virtual machine under a new pod name")
		Expect(run(repoRoot, "kubectl", "delete", "-n", namespace, "pod", firstPod, "--wait=true")).To(Succeed())
		waitLeaseReleased(identityLeaseName(namespace, vmName))

		Expect(applyManifest(vmReusePodManifest(namespace, secondPod, workerNodes[0], vmName))).To(Succeed())
		waitPodsReady(namespace, secondPod)
		Expect(podAddress(namespace, secondPod)).To(Equal(vmAddress), "the replacement pod must inherit the address of its virtual machine")

		// The address moved to a new veth and a new MAC, so a peer that
		// cached the old one would still resolve but no longer reach it.
		By("checking the inherited address carries traffic both ways again")
		assertBidirectionalConnectivity(namespace, secondPod, vmReusePeerPodName)
	})

	It("gives a second pod of the same virtual machine its own address while the first is alive", func() {
		const namespace = "e2e-vm-reuse-coexist"
		const vmName = "vm-reuse-coexist"
		firstPod := "virt-launcher-" + vmName + "-aaaaa"
		secondPod := "virt-launcher-" + vmName + "-bbbbb"

		setupVMReuseNamespace(namespace, vmName, firstPod, secondPod)

		By("running a virt-launcher pod and a peer on another node")
		Expect(applyManifest(vmReusePodManifest(namespace, firstPod, workerNodes[0], vmName))).To(Succeed())
		Expect(applyManifest(vmReusePodManifest(namespace, vmReusePeerPodName, workerNodes[1], ""))).To(Succeed())
		waitPodsReady(namespace, firstPod, vmReusePeerPodName)
		firstAddress := podAddress(namespace, firstPod)

		By("adding a second pod of the same virtual machine without removing the first")
		Expect(applyManifest(vmReusePodManifest(namespace, secondPod, workerNodes[0], vmName))).To(Succeed())
		waitPodsReady(namespace, secondPod)
		secondAddress := podAddress(namespace, secondPod)

		Expect(secondAddress).NotTo(Equal(firstAddress), "two live pods of one virtual machine must not share an address")

		By("checking the lease still belongs to the pod that took it first")
		holder, err := kubectlJSONPath(repoRoot, `{.spec.claimRef.name}`, "get", "allocationlease", identityLeaseName(namespace, vmName))
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(holder)).To(ContainSubstring(firstPod))
		leaseAddress, err := kubectlJSONPath(repoRoot, `{.spec.value.ip}`, "get", "allocationlease", identityLeaseName(namespace, vmName))
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(leaseAddress)).To(Equal(firstAddress))

		By("checking both pods can carry traffic at the same time")
		assertBidirectionalConnectivity(namespace, firstPod, vmReusePeerPodName)
		assertBidirectionalConnectivity(namespace, secondPod, vmReusePeerPodName)
	})

	It("keeps the re-used address reachable after the virtual machine moves to another node", func() {
		const namespace = "e2e-vm-reuse-move"
		const vmName = "vm-reuse-move"
		firstPod := "virt-launcher-" + vmName + "-aaaaa"
		secondPod := "virt-launcher-" + vmName + "-bbbbb"

		setupVMReuseNamespace(namespace, vmName, firstPod, secondPod)

		// The peer stays put while the virtual machine moves, so the
		// address goes from local to remote from the peer's point of view.
		By("running a virt-launcher pod and a peer on the same node")
		Expect(applyManifest(vmReusePodManifest(namespace, firstPod, workerNodes[0], vmName))).To(Succeed())
		Expect(applyManifest(vmReusePodManifest(namespace, vmReusePeerPodName, workerNodes[0], ""))).To(Succeed())
		waitPodsReady(namespace, firstPod, vmReusePeerPodName)
		vmAddress := podAddress(namespace, firstPod)
		assertBidirectionalConnectivity(namespace, firstPod, vmReusePeerPodName)

		By("restarting the virtual machine on the other node")
		Expect(run(repoRoot, "kubectl", "delete", "-n", namespace, "pod", firstPod, "--wait=true")).To(Succeed())
		waitLeaseReleased(identityLeaseName(namespace, vmName))

		Expect(applyManifest(vmReusePodManifest(namespace, secondPod, workerNodes[1], vmName))).To(Succeed())
		waitPodsReady(namespace, secondPod)
		assertPodPlacement(namespace, secondPod, workerNodes[1])
		Expect(podAddress(namespace, secondPod)).To(Equal(vmAddress), "the address must follow the virtual machine across nodes")

		By("checking the inherited address carries traffic both ways from the other node")
		assertBidirectionalConnectivity(namespace, secondPod, vmReusePeerPodName)
	})
})

// setupVMReuseNamespace creates the namespace for a spec and schedules the
// cleanup of everything it leaves behind. Leases outlive their pods on
// purpose, so they are removed by name rather than with the namespace.
func setupVMReuseNamespace(namespace, vmName string, podNames ...string) {
	createNamespace(namespace)
	DeferCleanup(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
		runBestEffort(repoRoot, "kubectl", "delete", "allocationlease", identityLeaseName(namespace, vmName), "--ignore-not-found=true")
		for _, pod := range append(podNames, vmReusePeerPodName) {
			runBestEffort(repoRoot, "kubectl", "delete", "allocationlease", podInterfaceLeaseName(namespace, pod), "--ignore-not-found=true")
		}
	})
}

// vmReusePodManifest renders a pod that can both answer and start HTTP
// requests: nginx makes it a target, and the curl sidecar shares the pod
// network namespace so a request also leaves from the same address. A
// non-empty vmName adds the labels KubeVirt puts on a virt-launcher pod.
func vmReusePodManifest(namespace, name, nodeName, vmName string) string {
	kubevirtLabels := ""
	if vmName != "" {
		kubevirtLabels = fmt.Sprintf("\n    kubevirt.io: virt-launcher\n    vm.kubevirt.io/name: %s", vmName)
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  labels:
    app: %s%s
spec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: %s
      image: nginx:1.27
      ports:
        - containerPort: 80
    - name: %s
      image: curlimages/curl:8.12.1
      command: ["sleep", "3600"]
`, namespace, name, name, kubevirtLabels, nodeName, vmReuseServerContainer, vmReuseClientContainer)
}

// assertBidirectionalConnectivity checks HTTP in both directions so that a
// re-used address is shown to be reachable and still able to reach out.
func assertBidirectionalConnectivity(namespace, podA, podB string) {
	assertHTTPFromPod(namespace, podA, podB)
	assertHTTPFromPod(namespace, podB, podA)
}

func assertHTTPFromPod(namespace, fromPod, toPod string) {
	target := podAddress(namespace, toPod)
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, fromPod, "-c", vmReuseClientContainer, "--",
			"curl", "-sS", "--max-time", "5", "http://"+target)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.ToLower(out)).To(ContainSubstring("welcome to nginx"))
	}).Should(Succeed(), "%s should reach %s at %s", fromPod, toPod, target)
}

func waitLeaseReleased(leaseName string) {
	Eventually(func(g Gomega) {
		phase, err := kubectlJSONPath(repoRoot, `{.status.phase}`, "get", "allocationlease", leaseName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(phase)).To(Equal("Released"))
	}).Should(Succeed())
}

// podInterfaceLeaseName is the AllocationLease that backs a pod's default
// interface when the address follows the pod name.
func podInterfaceLeaseName(namespace, podName string) string {
	return fmt.Sprintf("subnet-ip-default--networkinterface--%s--%s-eth0--status-address", namespace, podName)
}

// identityLeaseName is the AllocationLease that backs a virtual machine's
// address, which virt-launcher pods share across restarts.
func identityLeaseName(namespace, vmName string) string {
	return podInterfaceLeaseName(namespace, "vmi-"+vmName)
}
