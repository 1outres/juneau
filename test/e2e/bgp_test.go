package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	bgpPeerName              = "e2e-bgp-peer"
	bgpAddressPoolName       = "e2e-bgp-pool"
	bgpAdvertisementName     = "e2e-bgp-adv"
	bgpExternalNetworkName   = "e2e-external"
	bgpEIPNamespacePrefixDef = "e2e-bgp-eip"
	bgpClientPodName         = "nginx"
	// node_ingress drops DNAT traffic targeting the default subnet
	// (VNI == 1), and EIP egress needs an InternetGateway route on the
	// Pod's VPC RouteTable, so S3 provisions a dedicated VPC+Subnet.
	bgpVpcName    = "e2e-bgp-vpc"
	bgpSubnetName = "e2e-bgp-subnet"
	bgpSubnetCIDR = "10.200.0.0/24"
)

var bgpRouter *bgpRouterInstance

var _ = Describe("BGP e2e", Ordered, func() {
	BeforeAll(func() {
		By("starting opposing BGP router container")
		router, err := ensureBGPRouter(workerNodes)
		Expect(err).NotTo(HaveOccurred())
		bgpRouter = router

		By("waiting for BGPNodeState resources to exist for every worker")
		Eventually(func(g Gomega) {
			for _, node := range workerNodes {
				_, err := getBGPNodeState(node)
				g.Expect(err).NotTo(HaveOccurred(), "bgpnodestate %s not created yet", node)
			}
		}).Should(Succeed())

		By("applying BGPPeer pointing at the opposing router")
		Expect(applyBGPPeer(bgpPeerName, bgpRouter.ip)).To(Succeed())
	})

	AfterAll(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "bgpadvertisement", bgpAdvertisementName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", bgpExternalNetworkName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "addresspool", bgpAddressPoolName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "bgppeer", bgpPeerName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", bgpSubnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", bgpVpcName, "--ignore-not-found=true")
		teardownBGPRouter()
		bgpRouter = nil
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		dumpBGPDiagnostics(bgpRouter)
	})

	It("S1: establishes BGP sessions on every worker", func() {
		for _, node := range workerNodes {
			By(fmt.Sprintf("waiting for BGP session on %s", node))
			waitBGPSessionUp(node, bgpRouter.ip, bgpPeerName)
		}
	})

	It("S2: advertises pool prefix to opposing router", func() {
		By("creating AddressPool and BGPAdvertisement for the external CIDR")
		Expect(applyAddressPool(bgpAddressPoolName, []string{bgpExternalCIDR})).To(Succeed())
		Expect(applyBGPAdvertisement(bgpAdvertisementName, []string{bgpAddressPoolName})).To(Succeed())

		for _, node := range workerNodes {
			By(fmt.Sprintf("waiting for advertisement to appear on %s", node))
			waitBGPAdvertisement(node, bgpAddressPoolName, bgpExternalCIDR)
		}

		By("waiting for opposing bird/kernel to learn the prefix from both workers")
		waitBirdRouteOnRouter(bgpRouter, bgpExternalCIDR, len(workerNodes))
	})

	// S3 exercises the full external egress path end-to-end:
	//   peer (BGP-learned ECMP) → worker eth0 → node_ingress DNAT → Pod →
	//   pod_egress SNAT (bpf_fib_lookup resolves the real next-hop MAC) →
	//   back out worker eth0 → peer.
	// kind places the peer and workers on the same docker bridge. With
	// bridge-nf-call-iptables=1 the host's netfilter pipeline inspects every
	// bridged frame; distributions that ship iptables strict RPF (e.g. NixOS
	// via xt_rpfilter) drop the SNAT'd response at mangle/PREROUTING because
	// the source IP has no route in the host netns. ensureBGPRouter installs
	// a host route for the advertised CIDR via the kind bridge so RPF has a
	// valid reverse path; that is the minimum workaround required for kind.
	DescribeTable("S3: wires ElasticIP attachment for a Pod",
		func(workerIndex int) {
			Expect(len(workerNodes)).To(BeNumerically(">=", 2), "S3 needs at least 2 worker nodes")
			node := workerNodes[workerIndex]

			By("creating ExternalNetwork referencing the BGP pool")
			Expect(applyExternalNetwork(bgpExternalNetworkName, []string{bgpAddressPoolName})).To(Succeed())

			By("creating a custom VPC+Subnet for EIP traffic (default subnet VNI==1 is dropped by node_ingress DNAT)")
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
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: %s
spec:
  vpc: %s
  routes:
    - dst: 0.0.0.0/0
      via:
        type: internetGateway
`, bgpVpcName, bgpSubnetName, bgpVpcName, bgpSubnetCIDR, bgpVpcName, bgpVpcName))).To(Succeed())
			waitSubnetReady(bgpSubnetName)

			suffix := sanitizeName(fmt.Sprintf("worker%d", workerIndex))
			namespace := fmt.Sprintf("%s-%s", bgpEIPNamespacePrefixDef, suffix)
			eipName := fmt.Sprintf("eip-%s", suffix)
			attachmentName := fmt.Sprintf("eip-att-%s", suffix)

			By("creating an isolated namespace and nginx Pod on the target worker")
			createNamespace(namespace)
			DeferCleanup(func() {
				runBestEffort(repoRoot, "kubectl", "delete", "elasticipattachment", "-n", namespace, attachmentName, "--ignore-not-found=true")
				runBestEffort(repoRoot, "kubectl", "delete", "elasticip", "-n", namespace, eipName, "--ignore-not-found=true")
				runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			})

			Expect(applyManifest(podManifest(namespace, bgpClientPodName, node, bgpSubnetName, true))).To(Succeed())
			waitPodsReady(namespace, bgpClientPodName)
			assertPodPlacement(namespace, bgpClientPodName, node)

			interfaceName := bgpClientPodName + ".eth0"
			By(fmt.Sprintf("waiting for NetworkInterface %s to be created", interfaceName))
			Eventually(func(g Gomega) {
				out, err := kubectlJSONPath(repoRoot, `{.metadata.name}`, "-n", namespace, "get", "networkinterface", interfaceName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(out)).To(Equal(interfaceName))
			}).Should(Succeed())

			By("allocating an ElasticIP and attaching it to the Pod's NetworkInterface")
			Expect(applyElasticIP(namespace, eipName, bgpExternalNetworkName)).To(Succeed())
			eipAddress := waitElasticIPAddress(namespace, eipName)
			Expect(eipAddress).To(HavePrefix("192.0.2."), "EIP should be allocated from %s", bgpExternalCIDR)

			Expect(applyElasticIPAttachment(namespace, attachmentName, eipName, interfaceName)).To(Succeed())
			waitElasticIPAttachmentReady(namespace, attachmentName)
			waitElasticIPAttached(namespace, eipName)

			By("verifying the attachment status reflects the expected node and Pod IP")
			attachedNode, err := kubectlJSONPath(repoRoot, `{.status.nodeName}`, "-n", namespace, "get", "elasticipattachment", attachmentName)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(attachedNode)).To(Equal(node))

			attachedEIP, err := kubectlJSONPath(repoRoot, `{.status.elasticIP}`, "-n", namespace, "get", "elasticipattachment", attachmentName)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(attachedEIP)).To(Equal(eipAddress))

			podIP, err := kubectlJSONPath(repoRoot, `{.status.podIP}`, "-n", namespace, "get", "elasticipattachment", attachmentName)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(podIP)).To(HavePrefix("10.200.0."), "Pod IP should be in %s", bgpSubnetCIDR)

			By(fmt.Sprintf("curling http://%s/ from the opposing router", eipAddress))
			Eventually(func(g Gomega) {
				out, err := bgpRouter.Exec("curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s/", eipAddress))
				g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
				g.Expect(out).To(ContainSubstring("Welcome to nginx"), "curl body: %s", out)
			}, 90*time.Second, 3*time.Second).Should(Succeed())
		},
		Entry("Pod on worker[0]", 0),
		Entry("Pod on worker[1]", 1),
	)

	It("S4: reflects peer disconnect and recovery in BGPNodeState", func() {
		By("stopping the opposing router container")
		Expect(bgpRouter.Stop()).To(Succeed())
		for _, node := range workerNodes {
			By(fmt.Sprintf("waiting for %s session to drop", node))
			waitBGPSessionDown(node, bgpRouter.ip)
		}

		By("starting the opposing router container again")
		Expect(bgpRouter.Start()).To(Succeed())
		for _, node := range workerNodes {
			By(fmt.Sprintf("waiting for %s session to recover", node))
			waitBGPSessionUp(node, bgpRouter.ip, bgpPeerName)
		}
	})
})
