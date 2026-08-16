package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The daemon keeps the kernel in line with its kind=Node
// NetworkEndpoint for as long as it runs, not only at startup.
//
// Reading the identity once at startup was not enough. On an upgrade
// the daemon booted first and wrote spec.attachment on the old objects;
// the new controller then deleted those objects and created new ones,
// which carry no attachment. Every node lost Node→Pod and cross-node
// Pod→Pod traffic and stayed that way until someone restarted the
// DaemonSet by hand.
//
// Serial: both specs break the overlay on the node they pick, so no
// other spec can run at the same time.
var _ = Describe("Juneau node endpoint convergence", Ordered, Serial, func() {
	const namespace = "e2e-junode-convergence"

	var node, peer, endpoint, serverIP string

	BeforeAll(func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2),
			"node endpoint convergence needs at least 2 worker nodes")

		node = workerNodes[0]
		peer = workerNodes[1]
		endpoint = juneauNodeEndpointName(node)

		createNamespace(namespace)
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
				"--ignore-not-found=true", "--timeout=60s")
		})

		Expect(applyManifest(podManifest(namespace, serverPodName, node, "", true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientPodName, peer, "", false))).To(Succeed())
		waitPodsReady(namespace, serverPodName, clientPodName)

		out, err := kubectlJSONPath(repoRoot, `{.status.podIP}`, "-n", namespace, "get", "pod", serverPodName)
		Expect(err).NotTo(HaveOccurred())
		serverIP = strings.TrimSpace(out)
		Expect(serverIP).NotTo(BeEmpty())
	})

	It("fills spec.attachment in again after the endpoint is recreated, without a daemon restart", func() {
		oldUID, err := nodeEndpointField(endpoint, "{.metadata.uid}")
		Expect(err).NotTo(HaveOccurred())
		Expect(oldUID).NotTo(BeEmpty())

		daemonPod, daemonRestarts := daemonPodOnNode(node)

		DeferCleanup(func() {
			waitJuneauNodeConverged(node)
		})

		By("deleting the endpoint, as an identity change on the controller would")
		Expect(run(repoRoot, "kubectl", "delete", "networkendpoints.juneau.loutres.me",
			endpoint, "-n", controllerNamespace, "--timeout=60s")).To(Succeed())

		By("waiting for the controller to publish a new endpoint on its own")
		var newUID string
		Eventually(func(g Gomega) {
			uid, err := nodeEndpointField(endpoint, "{.metadata.uid}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(uid).NotTo(BeEmpty())
			g.Expect(uid).NotTo(Equal(oldUID))
			newUID = uid
		}).Should(Succeed())

		By("waiting for the daemon to record the veth on the new endpoint")
		waitJuneauNodeConverged(node)

		By("checking the daemon was never restarted")
		pod, restarts := daemonPodOnNode(node)
		Expect(pod).To(Equal(daemonPod))
		Expect(restarts).To(Equal(daemonRestarts))

		By("checking the endpoint is still the one the controller just created")
		uid, err := nodeEndpointField(endpoint, "{.metadata.uid}")
		Expect(err).NotTo(HaveOccurred())
		Expect(uid).To(Equal(newUID))

		assertJuneauNodeTraffic(node, namespace, serverIP)
	})

	It("puts the juneau_node MAC back after it is changed on the node", func() {
		wantMAC, err := nodeEndpointField(endpoint, "{.spec.macAddress}")
		Expect(err).NotTo(HaveOccurred())
		Expect(wantMAC).NotTo(BeEmpty())

		daemonPod, daemonRestarts := daemonPodOnNode(node)

		DeferCleanup(func() {
			waitJuneauNodeConverged(node)
		})

		By("changing the MAC by hand, as an operator would")
		out, err := dockerExecOutput(node, "ip", "link", "set",
			juneauNodeHostIfaceName, "address", driftMAC)
		Expect(err).NotTo(HaveOccurred(), "ip link set: %s", out)

		By("waiting for the daemon's resync to put the published MAC back")
		Eventually(func(g Gomega) {
			mac, err := hostIfaceAttr(node, juneauNodeHostIfaceName, "address")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(mac).To(Equal(wantMAC))
		}).Should(Succeed())

		By("checking the daemon was never restarted")
		pod, restarts := daemonPodOnNode(node)
		Expect(pod).To(Equal(daemonPod))
		Expect(restarts).To(Equal(daemonRestarts))

		assertJuneauNodeTraffic(node, namespace, serverIP)
	})
})

// driftMAC is outside the 02:00:<ipv4> scheme the controller derives
// its MACs from, so it can never be a value the daemon should keep.
const driftMAC = "02:ff:ff:00:00:01"

// waitJuneauNodeConverged waits until the kernel and the endpoint agree
// on the node's juneau_node identity: the veth carries the published
// MAC and spec.attachment names the live veth.
func waitJuneauNodeConverged(node string) {
	GinkgoHelper()
	endpoint := juneauNodeEndpointName(node)

	Eventually(func(g Gomega) {
		wantMAC, err := nodeEndpointField(endpoint, "{.spec.macAddress}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(wantMAC).NotTo(BeEmpty())

		mac, err := hostIfaceAttr(node, juneauNodeHostIfaceName, "address")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(mac).To(Equal(wantMAC))

		ifindex, err := hostIfaceAttr(node, juneauNodeIfaceName, "ifindex")
		g.Expect(err).NotTo(HaveOccurred())

		published, err := nodeEndpointField(endpoint, "{.spec.attachment.ifindex}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(published).To(Equal(ifindex))

		attachedMAC, err := nodeEndpointField(endpoint, "{.spec.attachment.hostMACAddress}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(attachedMAC).To(Equal(wantMAC))
	}).Should(Succeed())
}

// daemonPodOnNode returns the daemon Pod's name and its container
// restart counts. A spec that claims the daemon repaired something on
// its own has to show both are unchanged.
func daemonPodOnNode(node string) (string, string) {
	GinkgoHelper()
	name, err := daemonPodField(node, "{.items[0].metadata.name}")
	Expect(err).NotTo(HaveOccurred())
	Expect(name).NotTo(BeEmpty())

	restarts, err := daemonPodField(node, "{.items[0].status.containerStatuses[*].restartCount}")
	Expect(err).NotTo(HaveOccurred())
	return name, restarts
}

func daemonPodField(node, jsonPath string) (string, error) {
	out, err := kubectlJSONPath(repoRoot, jsonPath, "-n", daemonNamespace,
		"get", "pod", "-l", "app=cni-daemon", "--field-selector", "spec.nodeName="+node)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// assertJuneauNodeTraffic covers both paths that died in the incident:
// the node's own host network reaching a Pod through juneau_node, and a
// Pod on another node reaching a Pod on this one.
func assertJuneauNodeTraffic(node, namespace, serverIP string) {
	GinkgoHelper()
	By(fmt.Sprintf("curl the Pod from the host network of %s", node))
	assertHostCurlContains(node, "http://"+serverIP, "welcome to nginx")

	By("curl the Pod from a Pod on the other node")
	assertPodConnectivity(namespace, clientPodName, serverPodName)
}
