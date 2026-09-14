package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	directARPAddressPoolName     = "e2e-direct-arp-pool"
	directARPExternalNetworkName = "e2e-direct-arp-extnet"
	directARPNamespace           = "e2e-direct-arp"

	// The NAT ElasticIP the hairpin spec aims at needs a Pod in a Vpc that
	// routes 0/0 through the internet gateway.
	directARPVpcName     = "e2e-direct-arp-vpc"
	directARPSubnetName  = "e2e-direct-arp-subnet"
	directARPSubnetCIDR  = "10.232.0.0/24"
	directARPNATEIPName  = "eip-nat"
	directARPNATPodName  = "nat-server"
	directARPNATAttach   = "eip-att-nat"
	directARPEth0EIPName = "eip-eth0"
	directARPEth1EIPName = "eip-eth1"

	// The block sits below the blocks the ARP suite carves, so the two
	// suites never write overlapping AddressPools.
	directARPBlockOffset = arpEndpointBlockSize + arpGatewayBlockSize
	directARPBlockSize   = 8
)

// A NIC on an ElasticIP holds an address of the Nodes' own link in ARP
// mode, so the specs share the ARP client, its neighbor cache and the
// Nodes' ARP answers with the ARP suite. Serial for the same reason.
var _ = Describe("Juneau direct ElasticIP on an ARP ExternalNetwork", Ordered, Serial, func() {
	var (
		arpClient     *arpClientInstance
		block         arpAddressBlock
		eth0Pod       directElasticIPPod
		eth1Pod       directElasticIPPod
		eth0Address   string
		eth1Address   string
		ownerNode     string
		otherNode     string
		natEIPAddress string
	)

	BeforeAll(func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2), "these specs need at least 2 worker nodes")
		ownerNode = workerNodes[0]
		otherNode = workerNodes[1]

		By("starting an external ARP client on the docker network the Nodes share")
		var err error
		arpClient, err = ensureARPClient()
		Expect(err).NotTo(HaveOccurred())

		block = newARPAddressBlock(directARPBlockOffset, directARPBlockSize)
		By(fmt.Sprintf("creating the ARP AddressPool %s and its ExternalNetwork", block.poolEntry()))
		Expect(applyARPAddressPool(directARPAddressPoolName, []string{block.poolEntry()})).To(Succeed())
		Expect(applyARPExternalNetwork(directARPExternalNetworkName, []string{directARPAddressPoolName})).To(Succeed())

		createNamespace(directARPNamespace)

		By("allocating one ElasticIP per NIC")
		Expect(applyElasticIP(directARPNamespace, directARPEth0EIPName, directARPExternalNetworkName)).To(Succeed())
		Expect(applyElasticIP(directARPNamespace, directARPEth1EIPName, directARPExternalNetworkName)).To(Succeed())
		for _, name := range []string{directARPEth0EIPName, directARPEth1EIPName} {
			address := waitElasticIPAddress(directARPNamespace, name)
			Expect(block.contains(address)).To(BeTrue(), "ElasticIP %s address %s should come from %s", name, address, block.poolEntry())
		}

		eth0Pod = directElasticIPPod{namespace: directARPNamespace, name: "eth0-eip", node: ownerNode, nic: podIfaceName, elasticIP: directARPEth0EIPName}
		eth1Pod = directElasticIPPod{namespace: directARPNamespace, name: "eth1-eip", node: ownerNode, nic: "eth1", elasticIP: directARPEth1EIPName}
		eth0Address = eth0Pod.create()
		eth1Address = eth1Pod.create()
	})

	AfterAll(func() {
		clearMainRouteTableRoutes(directARPVpcName)
		runBestEffort(repoRoot, "kubectl", "delete", "elasticipattachment", "-n", directARPNamespace, directARPNATAttach, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", directARPNamespace, "--ignore-not-found=true", "--timeout=120s")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", directARPVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", directARPSubnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", directARPVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", directARPExternalNetworkName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "addresspool", directARPAddressPoolName, "--ignore-not-found=true")
		teardownARPClient()
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		dumpARPDiagnostics()
		dumpElasticIPDirectDiagnostics(directARPNamespace)
	})

	It("DA1: gives each NIC the ElasticIP it names, with no Subnet behind it", func() {
		for _, pod := range []directElasticIPPod{eth0Pod, eth1Pod} {
			address := waitElasticIPAddress(pod.namespace, pod.elasticIP)
			By(fmt.Sprintf("checking %s carries %s", pod.networkInterfaceName(), address))
			assertDirectElasticIPInterface(pod, address, directARPExternalNetworkName)
			assertDirectElasticIPRouting(pod, address)
		}
	})

	// The ElasticIP controller moves an ARPAdvertisement to the node of
	// whatever uses the address. For a NIC that is the node the Pod runs on.
	It("DA2: has the Pod's node, and only that node, answer ARP for the ElasticIP of either NIC", func() {
		for _, address := range []string{eth0Address, eth1Address} {
			Expect(waitARPAdvertisementNode(address)).To(Equal(ownerNode))
			By(fmt.Sprintf("arping %s from the external client", address))
			assertARPAnsweredBy(arpClient, address, ownerNode)
		}
	})

	It("DA3: serves a Pod on eth0 to the external client and sends from its ElasticIP, with no NAT either way", func() {
		By(fmt.Sprintf("curling http://%s/ from the external client", eth0Address))
		Eventually(func(g Gomega) {
			out, err := arpClient.curl(fmt.Sprintf("http://%s/", eth0Address))
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(strings.ToLower(out)).To(ContainSubstring(directServerBody), "curl body: %s", out)
		}, 90*time.Second, 3*time.Second).Should(Succeed())
		assertPodServerSaw(eth0Pod.namespace, eth0Pod.name, arpClient.ip)

		By(fmt.Sprintf("curling http://%s/ from the Pod", arpClient.ip))
		assertPodCurlFrom(eth0Pod, eth0Address, fmt.Sprintf("http://%s/", arpClient.ip), "ok")

		By(fmt.Sprintf("verifying the external client saw src=%s", eth0Address))
		Eventually(func(g Gomega) {
			logs, err := dockerLogsCombined(arpClientContainerName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(logs).To(ContainSubstring(eth0Address), "httpd access log should record src=%s", eth0Address)
		}).Should(Succeed())
	})

	It("DA4: answers the ElasticIP of an extra NIC from that NIC and sends from it", func() {
		By(fmt.Sprintf("checking a reply from %s is routed out of %s", eth1Address, eth1Pod.nic))
		Eventually(func(g Gomega) {
			out, err := eth1Pod.clientExec("ip", "-4", "route", "get", arpClient.ip, "from", eth1Address)
			g.Expect(err).NotTo(HaveOccurred(), "ip route get output: %s", out)
			g.Expect(out).To(ContainSubstring("dev "+eth1Pod.nic), "ip route get output: %s", out)
		}).Should(Succeed())

		By(fmt.Sprintf("curling http://%s/ from the external client and counting what %s sends", eth1Address, eth1Pod.nic))
		assertAnsweredFromNIC(eth1Pod, func() (string, error) {
			return arpClient.curl(fmt.Sprintf("http://%s/", eth1Address))
		})
		assertPodServerSaw(eth1Pod.namespace, eth1Pod.name, arpClient.ip)

		By(fmt.Sprintf("curling http://%s/ from %s", arpClient.ip, eth1Address))
		assertPodCurlFrom(eth1Pod, eth1Address, fmt.Sprintf("http://%s/", arpClient.ip), "ok")
		Eventually(func(g Gomega) {
			logs, err := dockerLogsCombined(arpClientContainerName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(logs).To(ContainSubstring(eth1Address), "httpd access log should record src=%s", eth1Address)
		}).Should(Succeed())
	})

	// A client whose neighbor entry names another node, one that went stale
	// or one a switch sent elsewhere, still reaches the Pod: every node
	// takes a direct ElasticIP and forwards it to the Pod's node over the
	// ExternalNetwork's VXLAN segment.
	It("DA5: delivers through a node the Pod does not run on", func() {
		otherMAC := nodeExternalMAC(otherNode)
		By(fmt.Sprintf("pinning the client's neighbor entry for %s to %s (%s)", eth0Address, otherNode, otherMAC))
		out, err := arpClient.Exec("ip", "neigh", "replace", eth0Address, "lladdr", otherMAC, "dev", "eth0", "nud", "permanent")
		Expect(err).NotTo(HaveOccurred(), "ip neigh replace output: %s", out)
		DeferCleanup(func() {
			_, _ = arpClient.Exec("ip", "neigh", "del", eth0Address, "dev", "eth0")
		})

		// The Nodes forward IP themselves, so the node could also route the
		// request on to the Pod's node over the link. Only juneau sends it
		// into the VXLAN device, which carries nothing else during the spec.
		By(fmt.Sprintf("curling http://%s/ through %s and counting what its VXLAN device sends", eth0Address, otherNode))
		Eventually(func(g Gomega) {
			before := nodeVXLANTxPackets(g, otherNode)
			out, err := arpClient.curl(fmt.Sprintf("http://%s/", eth0Address))
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(strings.ToLower(out)).To(ContainSubstring(directServerBody), "curl body: %s", out)
			after := nodeVXLANTxPackets(g, otherNode)
			g.Expect(after-before).To(BeNumerically(">=", tcpRequestMinPackets),
				"%s sent %d packets into its VXLAN device for one request", otherNode, after-before)
		}, 90*time.Second, 3*time.Second).Should(Succeed())
	})

	// The kubelet reaches an eth0 on an ElasticIP over the host route the
	// daemon adds, not over a probe rewrite, and such a Pod cannot reach the
	// cluster DNS Service, so it resolves through the node.
	It("DA6: lets the kubelet probe a Pod on eth0 through the node's route, and resolves names through the node", func() {
		By("checking the Pod reached Ready on its readiness probe")
		waitPodsReady(eth0Pod.namespace, eth0Pod.name)

		By(fmt.Sprintf("checking %s routes %s to the Pod's veth", ownerNode, eth0Address))
		assertNodeRoutesToPod(ownerNode, eth0Address)

		By("checking the probe was left as written")
		out, err := kubectlJSONPath(repoRoot,
			`{.metadata.annotations.juneau\.loutres\.me/probe-rewrite-version}{.spec.containers[0].readinessProbe.httpGet.host}`,
			"-n", eth0Pod.namespace, "get", "pod", eth0Pod.name)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(out)).To(BeEmpty(), "probe of a Pod on an ElasticIP eth0 should not be rewritten")

		By("checking the DNS policy of each Pod follows the network of its eth0")
		dnsPolicy, err := kubectlJSONPath(repoRoot, `{.spec.dnsPolicy}`, "-n", eth0Pod.namespace, "get", "pod", eth0Pod.name)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(dnsPolicy)).To(Equal("Default"))

		dnsPolicy, err = kubectlJSONPath(repoRoot, `{.spec.dnsPolicy}`, "-n", eth1Pod.namespace, "get", "pod", eth1Pod.name)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(dnsPolicy)).To(Equal("ClusterFirst"), "eth0 of %s is on the default Subnet", eth1Pod.name)
	})

	// Both ends are on one node, so neither packet may leave it: pod_egress
	// hands what a NIC on an ElasticIP sends to an address this node takes
	// back to node_ingress, which delivers it like a packet from outside.
	It("DA7: hairpins on the node between direct ElasticIPs and to a NAT ElasticIP", func() {
		By(fmt.Sprintf("curling %s on %s from %s on %s", eth1Address, eth1Pod.nic, eth0Address, eth0Pod.nic))
		assertPodCurlFrom(eth0Pod, eth0Address, fmt.Sprintf("http://%s/", eth1Address), directServerBody)
		assertPodServerSaw(eth1Pod.namespace, eth1Pod.name, eth0Address)

		By(fmt.Sprintf("curling %s on %s from %s on %s", eth0Address, eth0Pod.nic, eth1Address, eth1Pod.nic))
		assertPodCurlFrom(eth1Pod, eth1Address, fmt.Sprintf("http://%s/", eth0Address), directServerBody)
		assertPodServerSaw(eth0Pod.namespace, eth0Pod.name, eth1Address)

		By("creating a Subnet Pod on the same node behind a NAT ElasticIP")
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
`, directARPVpcName, directARPSubnetName, directARPVpcName, directARPSubnetCIDR))).To(Succeed())
		setMainRouteTableRoutes(directARPVpcName, internetGatewayRoute("0.0.0.0/0"))
		waitSubnetReady(directARPSubnetName)

		Expect(applyManifest(podManifest(directARPNamespace, directARPNATPodName, ownerNode, directARPSubnetName, true))).To(Succeed())
		waitPodsReady(directARPNamespace, directARPNATPodName)

		Expect(applyElasticIP(directARPNamespace, directARPNATEIPName, directARPExternalNetworkName)).To(Succeed())
		natEIPAddress = waitElasticIPAddress(directARPNamespace, directARPNATEIPName)
		Expect(applyElasticIPAttachment(directARPNamespace, directARPNATAttach, directARPNATEIPName, directARPNATPodName+".eth0")).To(Succeed())
		waitElasticIPAttachmentReady(directARPNamespace, directARPNATAttach)
		Expect(waitARPAdvertisementNode(natEIPAddress)).To(Equal(ownerNode))

		By(fmt.Sprintf("curling the NAT ElasticIP %s from %s", natEIPAddress, eth0Address))
		assertPodCurlFrom(eth0Pod, eth0Address, fmt.Sprintf("http://%s/", natEIPAddress), directServerBody)
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "logs", "-n", directARPNamespace, directARPNATPodName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring(eth0Address+" - "), "the NAT Pod should see the direct ElasticIP as the source")
		}).Should(Succeed())
	})

	// A new Pod may take over an ElasticIP once the old one is gone. The
	// ARP answer has to follow it, or the link keeps sending to a node the
	// address no longer lives behind.
	It("DA8: moves the ARP answer to the node a new Pod with the ElasticIP runs on", func() {
		By(fmt.Sprintf("deleting %s from %s", eth0Pod.name, ownerNode))
		Expect(run(repoRoot, "kubectl", "delete", "pod", "-n", eth0Pod.namespace, eth0Pod.name, "--wait=true", "--timeout=120s")).To(Succeed())
		Eventually(func(g Gomega) {
			_, err := kubectlOutput(repoRoot, "get", "networkinterface", "-n", eth0Pod.namespace, eth0Pod.networkInterfaceName())
			g.Expect(err).To(HaveOccurred(), "networkinterface %s should be gone", eth0Pod.networkInterfaceName())
		}).Should(Succeed())

		moved := eth0Pod
		moved.node = otherNode
		Expect(moved.create()).To(Equal(eth0Address), "the ElasticIP keeps its address across Pods")
		eth0Pod = moved

		Expect(waitARPAdvertisementNode(eth0Address)).To(Equal(otherNode))
		assertARPAnsweredBy(arpClient, eth0Address, otherNode)
		assertNodeRoutesToPod(otherNode, eth0Address)

		By(fmt.Sprintf("curling http://%s/ once the client has forgotten the old MAC", eth0Address))
		Eventually(func(g Gomega) {
			g.Expect(arpClient.flushNeighbor(eth0Address)).To(Succeed())
			out, err := arpClient.curl(fmt.Sprintf("http://%s/", eth0Address))
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(strings.ToLower(out)).To(ContainSubstring(directServerBody), "curl body: %s", out)
		}, 90*time.Second, 3*time.Second).Should(Succeed())

		By(fmt.Sprintf("curling the NAT ElasticIP %s on %s from %s on %s", natEIPAddress, ownerNode, eth0Address, otherNode))
		assertPodCurlFrom(eth0Pod, eth0Address, fmt.Sprintf("http://%s/", natEIPAddress), directServerBody)
	})
})
