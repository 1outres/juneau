package e2e

import (
	"fmt"
	"net"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	directBGPPeerName            = "e2e-direct-bgp-peer"
	directBGPAddressPoolName     = "e2e-direct-bgp-pool"
	directBGPAdvertisementName   = "e2e-direct-bgp-adv"
	directBGPExternalNetworkName = "e2e-direct-bgp-extnet"
	directBGPExternalCIDR        = "203.0.113.160/27"
	directBGPNamespace           = "e2e-direct-bgp"
	directBGPEth0EIPName         = "eip-eth0"
	directBGPEth1EIPName         = "eip-eth1"

	// The NATGateway spec needs a Vpc whose main RouteTable points 0/0 at
	// a NATGateway on the same ExternalNetwork as the direct ElasticIPs.
	directBGPVpcName        = "e2e-direct-bgp-vpc"
	directBGPSubnetName     = "e2e-direct-bgp-subnet"
	directBGPSubnetCIDR     = "10.233.0.0/24"
	directBGPNATGatewayName = "e2e-direct-bgp-nat-gw"

	directBGPLoadBalancerSelector = "direct-lb-backend"
	directBGPLoadBalancerService  = "direct-lb"
)

// directLanding is which node the opposing router sends a packet for an
// ElasticIP to. BGP advertises the pool from every node, so a packet may
// land on any of them.
type directLanding string

const (
	landingOnPodNode   directLanding = "the Pod's node"
	landingOnOtherNode directLanding = "another node"
)

// Serial because the specs share the opposing BGP router container and the
// kind-bridge RPF host workaround with the BGP and NAT suites.
var _ = Describe("Juneau direct ElasticIP on a BGP ExternalNetwork", Ordered, Serial, func() {
	var (
		pods      map[string]directElasticIPPod
		addresses map[string]string
	)

	otherWorker := func(node string) string {
		for _, candidate := range workerNodes[:2] {
			if candidate != node {
				return candidate
			}
		}
		Fail(fmt.Sprintf("no worker other than %s", node))
		return ""
	}

	BeforeAll(func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2), "these specs need at least 2 worker nodes")

		By("ensuring an opposing BGP router container is running")
		if bgpRouter == nil {
			router, err := ensureBGPRouter(workerNodes)
			Expect(err).NotTo(HaveOccurred())
			bgpRouter = router
		}
		// ensureBGPRouter only covers bgpExternalCIDR. A Pod on a direct
		// ElasticIP sends from this pool, so the host needs the same
		// reverse path for it.
		Expect(applyKindBridgeHostRPFWorkaround(directBGPExternalCIDR)).To(Succeed())

		By("waiting for BGPNodeState resources to exist for every worker")
		Eventually(func(g Gomega) {
			for _, node := range workerNodes {
				_, err := getBGPNodeState(node)
				g.Expect(err).NotTo(HaveOccurred(), "bgpnodestate %s not created yet", node)
			}
		}).Should(Succeed())

		By("creating the BGPPeer, AddressPool, BGPAdvertisement and ExternalNetwork")
		Expect(applyBGPPeer(directBGPPeerName, bgpRouter.ip)).To(Succeed())
		Expect(applyAddressPool(directBGPAddressPoolName, []string{directBGPExternalCIDR})).To(Succeed())
		Expect(applyBGPAdvertisement(directBGPAdvertisementName, []string{directBGPAddressPoolName})).To(Succeed())
		Expect(applyExternalNetwork(directBGPExternalNetworkName, []string{directBGPAddressPoolName})).To(Succeed())

		createNamespace(directBGPNamespace)

		By("allocating one ElasticIP per NIC")
		Expect(applyElasticIP(directBGPNamespace, directBGPEth0EIPName, directBGPExternalNetworkName)).To(Succeed())
		Expect(applyElasticIP(directBGPNamespace, directBGPEth1EIPName, directBGPExternalNetworkName)).To(Succeed())
		for _, name := range []string{directBGPEth0EIPName, directBGPEth1EIPName} {
			address := waitElasticIPAddress(directBGPNamespace, name)
			Expect(addressInCIDR(directBGPExternalCIDR, address)).To(BeTrue(),
				"ElasticIP %s address %s should come from %s", name, address, directBGPExternalCIDR)
		}

		pods = map[string]directElasticIPPod{
			podIfaceName: {namespace: directBGPNamespace, name: "eth0-eip", node: workerNodes[0], nic: podIfaceName, elasticIP: directBGPEth0EIPName},
			"eth1":       {namespace: directBGPNamespace, name: "eth1-eip", node: workerNodes[1], nic: "eth1", elasticIP: directBGPEth1EIPName},
		}
		addresses = map[string]string{}
		for nic, pod := range pods {
			addresses[nic] = pod.create()
		}
	})

	AfterAll(func() {
		clearMainRouteTableRoutes(directBGPVpcName)
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", directBGPNamespace, "--ignore-not-found=true", "--timeout=120s")
		runBestEffort(repoRoot, "kubectl", "delete", "natgateway", directBGPNATGatewayName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", directBGPVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", directBGPSubnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", directBGPVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "bgpadvertisement", directBGPAdvertisementName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", directBGPExternalNetworkName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "addresspool", directBGPAddressPoolName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "bgppeer", directBGPPeerName, "--ignore-not-found=true")
		cleanupKindBridgeHostRPFWorkaround(directBGPExternalCIDR)
		teardownBGPRouter()
		bgpRouter = nil
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		dumpNATDiagnostics()
		dumpBGPDiagnostics(bgpRouter)
		dumpElasticIPDirectDiagnostics(directBGPNamespace)
	})

	It("DB1: gives each NIC the ElasticIP it names and advertises the pool from every worker", func() {
		for nic, pod := range pods {
			By(fmt.Sprintf("checking %s carries %s", pod.networkInterfaceName(), addresses[nic]))
			assertDirectElasticIPInterface(pod, addresses[nic], directBGPExternalNetworkName)
			assertDirectElasticIPRouting(pod, addresses[nic])
		}

		for _, node := range workerNodes {
			waitBGPAdvertisement(node, directBGPAddressPoolName, directBGPExternalCIDR)
		}
		waitBirdRouteOnRouter(bgpRouter, directBGPExternalCIDR, len(workerNodes))
	})

	// The pool is advertised from every node, so the router may pick any of
	// them. A packet that lands on a node without the Pod must reach it over
	// the ExternalNetwork's VXLAN segment. A /32 on the router pins the
	// landing node so both cases run every time.
	DescribeTable("DB2: reaches the ElasticIP of a NIC wherever the route lands",
		func(nic string, landing directLanding) {
			pod := pods[nic]
			address := addresses[nic]
			node := pod.node
			if landing == landingOnOtherNode {
				node = otherWorker(pod.node)
			}
			pinRouterRoute(bgpRouter, address, node)

			url := fmt.Sprintf("http://%s/", address)
			By(fmt.Sprintf("curling %s through %s", url, node))
			if nic == podIfaceName {
				assertRouterCurl(bgpRouter, url, directServerBody)
			} else {
				assertAnsweredFromNIC(pod, func() (string, error) {
					return bgpRouter.Exec("curl", "-sS", "--max-time", "3", url)
				})
			}
			assertPodServerSaw(pod.namespace, pod.name, bgpRouter.ip)
		},
		Entry("eth0, landing on the Pod's node", podIfaceName, landingOnPodNode),
		Entry("eth0, landing on another node", podIfaceName, landingOnOtherNode),
		Entry("an extra NIC, landing on the Pod's node", "eth1", landingOnPodNode),
		Entry("an extra NIC, landing on another node", "eth1", landingOnOtherNode),
	)

	It("DB3: sends from the ElasticIP of either NIC, with no NAT", func() {
		for nic, pod := range pods {
			By(fmt.Sprintf("curling http://%s/ from %s on %s", bgpRouter.ip, addresses[nic], nic))
			assertPodCurlFrom(pod, addresses[nic], fmt.Sprintf("http://%s/", bgpRouter.ip), "ok")
			Eventually(func(g Gomega) {
				logs, err := dockerLogsCombined(bgpRouterContainerName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(logs).To(ContainSubstring(addresses[nic]), "httpd access log should record src=%s", addresses[nic])
			}).Should(Succeed())
		}
	})

	// The two Pods run on different nodes. Each packet goes into
	// node_ingress on the sender's node and crosses to the other node over
	// the ExternalNetwork's VXLAN segment, never through the router.
	It("DB4: hairpins between direct ElasticIPs on different nodes", func() {
		eth0, eth1 := pods[podIfaceName], pods["eth1"]

		By(fmt.Sprintf("curling %s on %s from %s on %s", addresses["eth1"], eth1.node, addresses[podIfaceName], eth0.node))
		assertPodCurlFrom(eth0, addresses[podIfaceName], fmt.Sprintf("http://%s/", addresses["eth1"]), directServerBody)
		assertPodServerSaw(eth1.namespace, eth1.name, addresses[podIfaceName])

		By(fmt.Sprintf("curling %s on %s from %s on %s", addresses[podIfaceName], eth0.node, addresses["eth1"], eth1.node))
		assertPodCurlFrom(eth1, addresses["eth1"], fmt.Sprintf("http://%s/", addresses[podIfaceName]), directServerBody)
		assertPodServerSaw(eth0.namespace, eth0.name, addresses["eth1"])
	})

	It("DB5: hairpins to a LoadBalancer VIP whose backend runs on the same node", func() {
		eth0 := pods[podIfaceName]
		backend := directBGPLoadBalancerSelector + "-0"

		By(fmt.Sprintf("creating a backend on %s and a LoadBalancer Service on the ExternalNetwork", eth0.node))
		Expect(applyManifest(arpBackendPodManifest(directBGPNamespace, backend, eth0.node, defaultSubnetName, directBGPLoadBalancerSelector))).To(Succeed())
		waitPodsReady(directBGPNamespace, backend)
		Expect(applyManifest(loadBalancerServiceManifest(directBGPNamespace, directBGPLoadBalancerService,
			directBGPExternalNetworkName, directBGPLoadBalancerSelector))).To(Succeed())
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "service", "-n", directBGPNamespace, directBGPLoadBalancerService, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "pod", "-n", directBGPNamespace, backend, "--ignore-not-found=true", "--timeout=60s")
		})

		vip := waitServiceLoadBalancerVIP(directBGPNamespace, directBGPLoadBalancerService)
		Expect(addressInCIDR(directBGPExternalCIDR, vip)).To(BeTrue(), "VIP %s should come from %s", vip, directBGPExternalCIDR)
		Eventually(func(g Gomega) {
			out, err := bgpRouter.Exec("birdc", "show", "route", vip+"/32", "all")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring(bgpRouter.workerIPs[eth0.node]),
				"VIP /32 should be advertised by the node of its backend: %s", out)
		}).Should(Succeed())

		By(fmt.Sprintf("curling the VIP %s from %s", vip, addresses[podIfaceName]))
		assertPodCurlFrom(eth0, addresses[podIfaceName], fmt.Sprintf("http://%s/", vip), directServerBody)
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "logs", "-n", directBGPNamespace, backend)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring(addresses[podIfaceName]+" - "), "the backend should see the direct ElasticIP as the client")
		}).Should(Succeed())
	})

	// A Subnet Pod behind a NATGateway reaches a direct ElasticIP with its
	// node's NAPT address as the source, and the reply goes to that address.
	// On the same node the reply hairpins into node_ingress. From another
	// node the reply has to leave through the router: the other node's NAPT
	// address is advertised by that node alone, so the Pod's node must not
	// take it for itself.
	It("DB6: serves a Subnet Pod behind a NATGateway on the same node and on another node", func() {
		eth0 := pods[podIfaceName]
		sameNode, crossNode := eth0.node, otherWorker(eth0.node)

		By("creating a Vpc whose main RouteTable points 0/0 at a NATGateway on the ExternalNetwork")
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
`, directBGPVpcName, directBGPSubnetName, directBGPVpcName, directBGPSubnetCIDR))).To(Succeed())
		waitSubnetReady(directBGPSubnetName)
		Expect(applyNATGateway(directBGPNATGatewayName, directBGPVpcName, directBGPExternalNetworkName)).To(Succeed())
		waitNATGatewayReady(directBGPNATGatewayName)
		setMainRouteTableRoutes(directBGPVpcName, natGatewayRoute("0.0.0.0/0", directBGPNATGatewayName))

		clients := map[string]string{sameNode: "nat-client-same", crossNode: "nat-client-cross"}
		for node, name := range clients {
			Expect(applyManifest(podManifest(directBGPNamespace, name, node, directBGPSubnetName, false))).To(Succeed())
		}
		waitPodsReady(directBGPNamespace, clients[sameNode], clients[crossNode])

		url := fmt.Sprintf("http://%s/", addresses[podIfaceName])

		sameNAPT := attachmentIPForNode(directBGPExternalNetworkName, sameNode)
		By(fmt.Sprintf("curling %s from a Subnet Pod on %s (NAPT %s)", url, sameNode, sameNAPT))
		assertSubnetPodCurl(directBGPNamespace, clients[sameNode], url, directServerBody)
		assertPodServerSaw(eth0.namespace, eth0.name, sameNAPT)

		crossNAPT := attachmentIPForNode(directBGPExternalNetworkName, crossNode)
		By(fmt.Sprintf("waiting for the router to learn %s/32 from %s", crossNAPT, crossNode))
		waitRouterLearnsNAPTPrefix(bgpRouter, crossNode, crossNAPT+"/32")
		routeExternalCIDRThroughRouter(bgpRouter, workerNodes, directBGPExternalCIDR)

		By(fmt.Sprintf("curling %s from a Subnet Pod on %s (NAPT %s)", url, crossNode, crossNAPT))
		assertSubnetPodCurl(directBGPNamespace, clients[crossNode], url, directServerBody)
		assertPodServerSaw(eth0.namespace, eth0.name, crossNAPT)
	})

	// The daemon rebuilds what it programmed for a direct ElasticIP from the
	// API when it starts. Every path the specs above used must come back.
	It("DB7: keeps every path to a direct ElasticIP after the daemon restarts", func() {
		for _, node := range workerNodes[:2] {
			By(fmt.Sprintf("restarting the daemon on %s", node))
			restartDaemonOnNode(node)
		}

		for nic, pod := range pods {
			pinRouterRoute(bgpRouter, addresses[nic], otherWorker(pod.node))
			By(fmt.Sprintf("curling %s through a node %s does not run on", addresses[nic], pod.name))
			assertRouterCurl(bgpRouter, fmt.Sprintf("http://%s/", addresses[nic]), directServerBody)
			waitPodsReady(pod.namespace, pod.name)
		}

		eth0 := pods[podIfaceName]
		By("hairpinning across nodes again")
		assertPodCurlFrom(eth0, addresses[podIfaceName], fmt.Sprintf("http://%s/", addresses["eth1"]), directServerBody)
		By("sending to the router again")
		assertPodCurlFrom(pods["eth1"], addresses["eth1"], fmt.Sprintf("http://%s/", bgpRouter.ip), "ok")
	})
})

// pinRouterRoute makes the opposing router send traffic for address to
// node only, until the spec ends.
func pinRouterRoute(router *bgpRouterInstance, address, node string) {
	GinkgoHelper()
	prefix := address + "/32"
	nodeIP := router.workerIPs[node]
	By(fmt.Sprintf("pinning %s on the router to %s (%s)", prefix, node, nodeIP))
	out, err := router.Exec("ip", "route", "replace", prefix, "via", nodeIP)
	Expect(err).NotTo(HaveOccurred(), "ip route replace output: %s", out)
	DeferCleanup(func() {
		_, _ = router.Exec("ip", "route", "del", prefix)
	})
}

func assertRouterCurl(router *bgpRouterInstance, url, want string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := router.Exec("curl", "-sS", "--max-time", "3", url)
		g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
		g.Expect(strings.ToLower(out)).To(ContainSubstring(want), "curl body: %s", out)
	}, 90*time.Second, 3*time.Second).Should(Succeed())
}

func assertSubnetPodCurl(namespace, podName, url, want string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--", "curl", "-sS", "--max-time", "5", url)
		g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
		g.Expect(strings.ToLower(out)).To(ContainSubstring(want), "curl body: %s", out)
	}).Should(Succeed())
}

// routeExternalCIDRThroughRouter makes the opposing router the way from the
// Nodes to the external pool, until the spec ends, the way an upstream
// router is in a real network. In kind the Nodes' default route is the
// docker bridge, which does not know the pool, so a packet from a Node to
// an address another Node advertises would otherwise have nowhere to go.
//
// ip_forward is only written when it is off, for the reason
// setupRouterBeyondNetwork gives.
func routeExternalCIDRThroughRouter(router *bgpRouterInstance, nodes []string, cidr string) {
	GinkgoHelper()
	_, _, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred(), "parse %q", cidr)

	By(fmt.Sprintf("routing %s from every worker through the opposing router %s", cidr, router.ip))
	out, err := router.Exec("sh", "-c", `set -eu
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]; then
  sysctl -wq net.ipv4.ip_forward=1
fi
`)
	Expect(err).NotTo(HaveOccurred(), "router forwarding setup output: %s", out)

	for _, node := range nodes {
		out, err := dockerExecOutput(node, "ip", "route", "replace", cidr, "via", router.ip)
		Expect(err).NotTo(HaveOccurred(), "node %s route output: %s", node, out)
	}
	DeferCleanup(func() {
		for _, node := range nodes {
			_, _ = dockerExecOutput(node, "ip", "route", "del", cidr, "via", router.ip)
		}
	})
}
