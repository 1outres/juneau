package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The MAC of juneau_node is the value the controller wrote on the
// NetworkEndpoint (Kind=Node), not the random one the kernel picks when
// it creates the veth. So when a node restarts and the veth is gone,
// the daemon builds it again with the same MAC.
//
// It used to work the other way round: the random kernel MAC was copied
// into spec.macAddress, which is immutable. After a restart the new
// random MAC no longer matched, and the daemon could not start at all
// (issue #46).
//
// Serial: this spec destroys juneau_node on the node it picks, so all
// overlay traffic on that node stops until the daemon rebuilds it. No
// other spec can run at the same time.
var _ = Describe("Juneau node endpoint recovery", Ordered, Serial, func() {
	It("rebuilds juneau_node with the same MAC after the veth is destroyed", func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2),
			"node endpoint recovery needs at least 2 worker nodes")

		node := workerNodes[0]
		peer := workerNodes[1]
		endpoint := juneauNodeEndpointName(node)

		By("recording the identity the controller published")
		wantMAC, err := nodeEndpointField(endpoint, "{.spec.macAddress}")
		Expect(err).NotTo(HaveOccurred())
		Expect(wantMAC).NotTo(BeEmpty())

		wantUID, err := nodeEndpointField(endpoint, "{.metadata.uid}")
		Expect(err).NotTo(HaveOccurred())
		Expect(wantUID).NotTo(BeEmpty())

		hostMAC, err := hostIfaceAttr(node, juneauNodeHostIfaceName, "address")
		Expect(err).NotTo(HaveOccurred())
		Expect(hostMAC).To(Equal(wantMAC), "kernel MAC must already match the published identity")

		DeferCleanup(func() {
			restoreJuneauNodeIface(node)
		})

		By("destroying the veth pair, as a host restart would")
		out, err := dockerExecOutput(node, "ip", "link", "del", juneauNodeIfaceName)
		Expect(err).NotTo(HaveOccurred(), "ip link del: %s", out)

		By("restarting the daemon on that node")
		restartDaemonOnNode(node)

		By("checking the recreated veth carries the same MAC")
		Eventually(func(g Gomega) {
			mac, err := hostIfaceAttr(node, juneauNodeHostIfaceName, "address")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(mac).To(Equal(wantMAC))
		}).Should(Succeed())

		By("checking the NetworkEndpoint survived instead of being recreated")
		uid, err := nodeEndpointField(endpoint, "{.metadata.uid}")
		Expect(err).NotTo(HaveOccurred())
		Expect(uid).To(Equal(wantUID))
		mac, err := nodeEndpointField(endpoint, "{.spec.macAddress}")
		Expect(err).NotTo(HaveOccurred())
		Expect(mac).To(Equal(wantMAC))

		By("checking spec.attachment points at the new veth")
		Eventually(func(g Gomega) {
			ifindex, err := hostIfaceAttr(node, juneauNodeIfaceName, "ifindex")
			g.Expect(err).NotTo(HaveOccurred())

			published, err := nodeEndpointField(endpoint, "{.spec.attachment.ifindex}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(published).To(Equal(ifindex))

			attachedMAC, err := nodeEndpointField(endpoint, "{.spec.attachment.hostMACAddress}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(attachedMAC).To(Equal(wantMAC))
		}).Should(Succeed())

		By("checking traffic through the rebuilt veth")
		namespace := "e2e-junode-recovery"
		createNamespace(namespace)
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
				"--ignore-not-found=true", "--timeout=60s")
		})

		Expect(applyManifest(podManifest(namespace, serverPodName, node, "", true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientPodName, peer, "", false))).To(Succeed())
		waitPodsReady(namespace, serverPodName, clientPodName)

		serverIP, err := kubectlJSONPath(repoRoot, `{.status.podIP}`, "-n", namespace, "get", "pod", serverPodName)
		Expect(err).NotTo(HaveOccurred())
		serverIP = strings.TrimSpace(serverIP)
		Expect(serverIP).NotTo(BeEmpty())

		By(fmt.Sprintf("curl the Pod from the host network of %s", node))
		assertHostCurlContains(node, "http://"+serverIP, "welcome to nginx")

		By(fmt.Sprintf("curl the Pod from a Pod on %s", peer))
		assertPodConnectivity(namespace, clientPodName, serverPodName)
	})
})

const (
	// These mirror the daemon's bootstrap constants. The e2e module is
	// a separate Go module and does not import the daemon.
	juneauNodeIfaceName     = "juneau_node"
	juneauNodeHostIfaceName = "juneau_node_h"
)

// juneauNodeEndpointName mirrors v1alpha1.JuneauNodeEndpointName.
func juneauNodeEndpointName(node string) string {
	return "juneau-node." + node
}

// nodeEndpointField reads one field of a Node's kind=Node
// NetworkEndpoint. The object lives in the controller's namespace
// because the controller, not the daemon, creates it.
func nodeEndpointField(name, jsonPath string) (string, error) {
	out, err := kubectlJSONPath(repoRoot, jsonPath, "-n", controllerNamespace,
		"get", "networkendpoints.juneau.loutres.me", name)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func hostIfaceAttr(node, iface, attr string) (string, error) {
	return dockerExecOutput(node, "cat", fmt.Sprintf("/sys/class/net/%s/%s", iface, attr))
}

func restartDaemonOnNode(node string) {
	GinkgoHelper()
	Expect(run(repoRoot, "kubectl", "delete", "pod", "-n", daemonNamespace,
		"-l", "app=cni-daemon", "--field-selector", "spec.nodeName="+node,
		"--timeout=120s")).To(Succeed())
	waitDaemonReadyOnNode(node)
}

func waitDaemonReadyOnNode(node string) {
	GinkgoHelper()
	// The replacement Pod may not exist yet, and `kubectl wait` fails
	// outright on an empty selection, so retry until one shows up.
	Eventually(func(g Gomega) {
		g.Expect(run(repoRoot, "kubectl", "wait", "--for=condition=Ready", "pod",
			"-n", daemonNamespace, "-l", "app=cni-daemon",
			"--field-selector", "spec.nodeName="+node, "--timeout=30s")).To(Succeed())
	}).Should(Succeed())
}

// restoreJuneauNodeIface leaves the node usable even when the spec
// failed halfway through. The daemon's resync rebuilds a missing veth
// on its own, but a restart does it at once and keeps cleanup short.
func restoreJuneauNodeIface(node string) {
	if _, err := dockerExecOutput(node, "sh", "-c",
		"test -e /sys/class/net/"+juneauNodeIfaceName); err != nil {
		restartDaemonOnNode(node)
	}
	waitDaemonReadyOnNode(node)
}
