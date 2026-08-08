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

// Serial because BGP and NAT both manage the shared juneau-e2e-bgp-peer
// container and the kind-bridge RPF host workaround; running them in
// parallel processes would race the docker rm -f / route replace calls.
var _ = Describe("BGP e2e", Ordered, Serial, func() {
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

	// S3 exercises the full external egress path end-to-end. A host route on
	// the peer pins ingress to a worker that does not host the Pod, proving
	// every ECMP next-hop can DNAT and forward the packet through the overlay:
	//   peer → non-owner worker eth0 → node_ingress DNAT → VXLAN → Pod →
	//   pod_egress SNAT (bpf_fib_lookup resolves the real next-hop MAC) →
	//   back out owner worker eth0 → peer.
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

			ensureEIPNetwork()

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

			nonOwnerNode := workerNodes[(workerIndex+1)%len(workerNodes)]
			nonOwnerIP := bgpRouter.workerIPs[nonOwnerNode]
			eipPrefix := eipAddress + "/32"
			By(fmt.Sprintf("pinning %s ingress to non-owner node %s (%s)", eipPrefix, nonOwnerNode, nonOwnerIP))
			_, err = bgpRouter.Exec("ip", "route", "replace", eipPrefix, "via", nonOwnerIP)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				_, _ = bgpRouter.Exec("ip", "route", "del", eipPrefix)
			})

			route, err := bgpRouter.Exec("ip", "route", "show", eipPrefix)
			Expect(err).NotTo(HaveOccurred())
			Expect(route).To(ContainSubstring("via " + nonOwnerIP))

			By(fmt.Sprintf("curling http://%s/ through non-owner node %s", eipAddress, nonOwnerNode))
			Eventually(func(g Gomega) {
				out, err := bgpRouter.Exec("curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s/", eipAddress))
				g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
				g.Expect(out).To(ContainSubstring("Welcome to nginx"), "curl body: %s", out)
			}, 90*time.Second, 3*time.Second).Should(Succeed())
		},
		Entry("Pod on worker[0]", 0),
		Entry("Pod on worker[1]", 1),
	)

	// S3.5 / S3.6 / S3.7 are the ElasticIP counterpart of the NATGateway
	// ICMP specs (N5 / N6 / N7). A 1:1 NAT translates no ports, so the
	// only field that moves is the address — in the outer header, and in
	// the copy of the original packet an ICMP error message carries.
	//
	// The three share one ElasticIP and one Pod: attaching an ElasticIP
	// takes an ExternalNetwork, a dedicated VPC, a NetworkInterface and a
	// pinned route on the opposing router, and repeating that per spec
	// buys nothing.
	Describe("ICMP through an ElasticIP", Ordered, func() {
		const (
			icmpNamespace  = "e2e-bgp-eip-icmp"
			icmpPodName    = "icmp-client"
			icmpEIPName    = "eip-icmp"
			icmpAttachName = "eip-att-icmp"
		)
		var eipAddress string

		BeforeAll(func() {
			node := workerNodes[0]

			By("creating ExternalNetwork referencing the BGP pool")
			Expect(applyExternalNetwork(bgpExternalNetworkName, []string{bgpAddressPoolName})).To(Succeed())
			ensureEIPNetwork()

			createNamespace(icmpNamespace)
			DeferCleanup(func() {
				runBestEffort(repoRoot, "kubectl", "delete", "elasticipattachment", "-n", icmpNamespace, icmpAttachName, "--ignore-not-found=true")
				runBestEffort(repoRoot, "kubectl", "delete", "elasticip", "-n", icmpNamespace, icmpEIPName, "--ignore-not-found=true")
				runBestEffort(repoRoot, "kubectl", "delete", "namespace", icmpNamespace, "--ignore-not-found=true", "--timeout=60s")
			})

			By(fmt.Sprintf("creating a netshoot Pod on %s in subnet %s", node, bgpSubnetName))
			Expect(applyManifest(netshootPodManifest(icmpNamespace, icmpPodName, node, bgpSubnetName))).To(Succeed())
			waitPodsReady(icmpNamespace, icmpPodName)
			assertPodPlacement(icmpNamespace, icmpPodName, node)

			interfaceName := icmpPodName + ".eth0"
			By(fmt.Sprintf("waiting for NetworkInterface %s to be created", interfaceName))
			Eventually(func(g Gomega) {
				out, err := kubectlJSONPath(repoRoot, `{.metadata.name}`, "-n", icmpNamespace, "get", "networkinterface", interfaceName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(out)).To(Equal(interfaceName))
			}).Should(Succeed())

			By("allocating an ElasticIP and attaching it to the Pod's NetworkInterface")
			Expect(applyElasticIP(icmpNamespace, icmpEIPName, bgpExternalNetworkName)).To(Succeed())
			eipAddress = waitElasticIPAddress(icmpNamespace, icmpEIPName)
			Expect(applyElasticIPAttachment(icmpNamespace, icmpAttachName, icmpEIPName, interfaceName)).To(Succeed())
			waitElasticIPAttachmentReady(icmpNamespace, icmpAttachName)
			waitElasticIPAttached(icmpNamespace, icmpEIPName)

			ownerIP := bgpRouter.workerIPs[node]
			eipPrefix := eipAddress + "/32"
			By(fmt.Sprintf("pinning %s ingress to owner node %s (%s)", eipPrefix, node, ownerIP))
			_, err := bgpRouter.Exec("ip", "route", "replace", eipPrefix, "via", ownerIP)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				_, _ = bgpRouter.Exec("ip", "route", "del", eipPrefix)
			})

			setupRouterBeyondNetwork(bgpRouter, workerNodes)
			DeferCleanup(func() {
				teardownRouterBeyondNetwork(bgpRouter, workerNodes)
			})
		})

		// An ICMP checksum has no pseudo-header, so neither direction may
		// touch it when only the address moves. A stale ICMP checksum
		// drops the echo silently.
		It("S3.5: passes ICMP echo through an ElasticIP in both directions", func() {
			By(fmt.Sprintf("pinging the ElasticIP %s from the external router", eipAddress))
			assertRouterPing(bgpRouter, eipAddress)

			By(fmt.Sprintf("pinging the external router %s from the Pod behind the ElasticIP", bgpRouter.ip))
			assertPodPing(icmpNamespace, icmpPodName, bgpRouter.ip)
		})

		// The first hop is the opposing router reporting Time Exceeded
		// about a packet that left the Node carrying the ElasticIP. The
		// hop only shows up once node_ingress has put the Pod's own
		// address back into the quoted header.
		It("S3.6: traceroute from a Pod behind an ElasticIP sees the first hop", func() {
			assertPodTraceroute(icmpNamespace, icmpPodName, natBeyondHost, bgpRouter.ip)
		})

		// The Pod's route cache is what this spec is really about. The
		// printed report matches on the Echo Identifier, which a 1:1 NAT
		// preserves, so it appears even when the quoted header still says
		// ElasticIP and the kernel files the route exception under an
		// address the Pod never sends from.
		It("S3.7: Path MTU Discovery from a Pod behind an ElasticIP caches the reduced MTU", func() {
			assertPodLearnsPathMTU(icmpNamespace, icmpPodName, natBeyondHost, natPMTUDPayload, natBeyondMTU)
		})
	})

	It("S4: serves a LoadBalancer VIP to an external BGP client without losing the VIP on reply", func() {
		node := workerNodes[0]
		namespace := "e2e-bgp-loadbalancer"
		const (
			podName = "lb-backend"
			svcName = "lb-service"
		)

		createNamespace(namespace)
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
		})

		By("creating a local backend on one worker")
		Expect(applyManifest(podManifest(namespace, podName, node, defaultSubnetName, true))).To(Succeed())
		waitPodsReady(namespace, podName)
		assertPodPlacement(namespace, podName, node)

		By("creating a Juneau-managed LoadBalancer Service")
		Expect(applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/load-balancer-external-network: %s
spec:
  type: LoadBalancer
  loadBalancerClass: juneau.loutres.me/load-balancer
  externalTrafficPolicy: Local
  selector:
    app: %s
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 80
`, namespace, svcName, bgpExternalNetworkName, podName))).To(Succeed())

		var vip string
		By("waiting for the VIP and its owner-only /32 route")
		Eventually(func(g Gomega) {
			out, err := kubectlJSONPath(repoRoot, `{.status.loadBalancer.ingress[0].ip}`,
				"-n", namespace, "get", "service", svcName)
			g.Expect(err).NotTo(HaveOccurred())
			vip = strings.TrimSpace(out)
			g.Expect(vip).NotTo(BeEmpty())
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			out, err := bgpRouter.Exec("birdc", "show", "route", vip+"/32", "all")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring(bgpRouter.workerIPs[node]),
				"VIP /32 should be advertised only by its local-backend owner: %s", out)
		}).Should(Succeed())

		By("curling the VIP from the external router")
		Eventually(func(g Gomega) {
			out, err := bgpRouter.Exec("curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s/", vip))
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(out).To(ContainSubstring("Welcome to nginx"), "curl body: %s", out)
		}, 90*time.Second, 3*time.Second).Should(Succeed())

		By("verifying that the backend observed the original external client IP")
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "logs", "-n", namespace, podName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring(bgpRouter.ip),
				"backend log should contain the external router IP")
		}).Should(Succeed())
	})

	It("S5: reflects peer disconnect and recovery in BGPNodeState", func() {
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
