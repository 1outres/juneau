package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A Pod sandbox can be rebuilt while the Pod stays: the Pod UID does not
// change, CNI ADD runs again for it, and the DEL of the old sandbox can
// still arrive afterwards. The daemon used to answer that late DEL by
// deleting the Pod NetworkEndpoint, which took a running Pod off the
// network and left it there (issue #49).
//
// This spec drives the CNI plugin on the node by hand. A Pod lifecycle
// never lets a test put ADD and DEL in that order, so nothing else can
// produce the case.
var _ = Describe("Juneau CNI attachment generation", Ordered, func() {
	const namespace = "e2e-cni-attachment"

	var (
		node string
		pod  cniPod

		first  syntheticSandbox
		second syntheticSandbox

		firstSpec  networkEndpointSpec
		secondSpec networkEndpointSpec
	)

	BeforeAll(func() {
		node = workerNodes[0]

		createNamespace(namespace)
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
				"--ignore-not-found=true", "--timeout=60s")
		})

		Expect(applyManifest(podManifest(namespace, serverPodName, node, "", true))).To(Succeed())
		waitPodsReady(namespace, serverPodName)
		pod = lookupCNIPod(namespace, serverPodName)

		first = newSyntheticSandbox(node, "s1")
		second = newSyntheticSandbox(node, "s2")
		DeferCleanup(first.remove)
		DeferCleanup(second.remove)
		first.create()
		second.create()
	})

	It("points the endpoint at the sandbox ADD ran for", func() {
		expectCNI(node, "ADD", pod, first.cniSandbox)

		firstSpec = waitPodAttachment(namespace, serverPodName, first.containerID)
		Expect(firstSpec.MACAddress).NotTo(BeEmpty())
		assertAttachedVeth(node, first, firstSpec)
	})

	It("refreshes the whole attachment when ADD repeats under the same Pod UID", func() {
		expectCNI(node, "ADD", pod, second.cniSandbox)

		// The Pod MAC belongs to the same veth pair as the attachment,
		// so it has to move with it. The admission webhook holds the
		// other endpoint MACs immutable and would reject this update if
		// it did not make that exception.
		secondSpec = waitPodAttachment(namespace, serverPodName, second.containerID)
		Expect(secondSpec.Attachment.Ifindex).NotTo(Equal(firstSpec.Attachment.Ifindex))
		Expect(secondSpec.Attachment.HostMACAddress).NotTo(Equal(firstSpec.Attachment.HostMACAddress))
		Expect(secondSpec.MACAddress).NotTo(Equal(firstSpec.MACAddress))
		assertAttachedVeth(node, second, secondSpec)
	})

	It("keeps the live attachment when the DEL of the old sandbox arrives late", func() {
		expectCNI(node, "DEL", pod, first.cniSandbox)

		Expect(readPodAttachment(namespace, serverPodName)).To(Equal(secondSpec))
		Expect(hostIfaceNames(node)).NotTo(ContainElement(first.hostVethName()))
		Expect(hostIfaceNames(node)).To(ContainElement(second.hostVethName()))
	})

	It("answers a repeated DEL of the old sandbox the same way", func() {
		expectCNI(node, "DEL", pod, first.cniSandbox)

		Expect(readPodAttachment(namespace, serverPodName)).To(Equal(secondSpec))
		Expect(hostIfaceNames(node)).To(ContainElement(second.hostVethName()))
	})

	It("deletes the endpoint when the DEL of the live sandbox arrives", func() {
		expectCNI(node, "DEL", pod, second.cniSandbox)

		Expect(podNetworkEndpointExists(namespace, serverPodName)).To(BeFalse())
		Expect(hostIfaceNames(node)).NotTo(ContainElement(second.hostVethName()))
	})

	It("answers a repeated DEL of either sandbox without an error", func() {
		expectCNI(node, "DEL", pod, second.cniSandbox)
		expectCNI(node, "DEL", pod, first.cniSandbox)

		Expect(podNetworkEndpointExists(namespace, serverPodName)).To(BeFalse())
	})
})

// The trigger in production is the container runtime rebuilding a Pod's
// sandbox. The Pod stays, so its endpoint has to follow the new sandbox,
// its address has to survive, and the DEL the runtime still owes for the
// old sandbox must not take any of that away.
var _ = Describe("Juneau Pod sandbox recreation", Ordered, func() {
	const namespace = "e2e-cni-sandbox-restart"

	var (
		node string
		peer string
		pod  cniPod

		oldSandboxID string
		newSandboxID string
		serverIP     string
	)

	BeforeAll(func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2),
			"sandbox recreation needs at least 2 worker nodes")
		node = workerNodes[0]
		peer = workerNodes[1]

		createNamespace(namespace)
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
				"--ignore-not-found=true", "--timeout=60s")
		})

		Expect(applyManifest(podManifest(namespace, serverPodName, node, "", true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientPodName, peer, "", false))).To(Succeed())
		waitPodsReady(namespace, serverPodName, clientPodName)

		pod = lookupCNIPod(namespace, serverPodName)
		var err error
		serverIP, err = podIPOf(namespace, serverPodName)
		Expect(err).NotTo(HaveOccurred())
		Expect(serverIP).NotTo(BeEmpty())
	})

	It("records the sandbox the runtime built", func() {
		oldSandboxID = waitRuntimeSandboxID(node, namespace, serverPodName)

		waitPodAttachment(namespace, serverPodName, oldSandboxID)
		assertPodConnectivity(namespace, clientPodName, serverPodName)
	})

	It("follows the Pod onto the sandbox that replaces it", func() {
		By("removing the sandbox, as the runtime does when it has to rebuild one")
		out, err := dockerExecOutput(node, "crictl", "rmp", "-f", oldSandboxID)
		Expect(err).NotTo(HaveOccurred(), "crictl rmp: %s", out)

		By("waiting for kubelet to build a new sandbox for the same Pod")
		Eventually(func(g Gomega) {
			id, err := findRuntimeSandboxID(node, namespace, serverPodName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(id).NotTo(Equal(oldSandboxID))
			newSandboxID = id
		}).Should(Succeed())

		By("checking the endpoint moved onto the new sandbox")
		waitPodAttachment(namespace, serverPodName, newSandboxID)

		By("checking the Pod is the same one, only its sandbox is new")
		Expect(lookupCNIPod(namespace, serverPodName).uid).To(Equal(pod.uid))
		waitPodsReady(namespace, serverPodName)
		Eventually(func(g Gomega) {
			g.Expect(podIPOf(namespace, serverPodName)).To(Equal(serverIP))
		}).Should(Succeed())
	})

	It("keeps the Pod reachable when the old sandbox's DEL arrives late", func() {
		expectCNI(node, "DEL", pod, runtimeSandbox(oldSandboxID))

		spec := readPodAttachment(namespace, serverPodName)
		Expect(spec.Attachment).NotTo(BeNil())
		Expect(spec.Attachment.ContainerID).To(Equal(newSandboxID))

		By("curl the Pod from a Pod on the other node")
		assertPodConnectivity(namespace, clientPodName, serverPodName)
		By("curl the Pod from the host network of its own node")
		assertHostCurlContains(node, "http://"+serverIP, "welcome to nginx")
	})
})
