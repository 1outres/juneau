package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	arpAddressPoolName        = "e2e-arp-pool"
	arpExternalNetworkName    = "e2e-arp-extnet"
	arpNATAddressPoolName     = "e2e-arp-nat-pool"
	arpNATExternalNetworkName = "e2e-arp-nat-extnet"

	// node_ingress drops DNAT traffic aimed at the default Subnet
	// (VNI == 1), and ElasticIP egress needs an InternetGateway route on
	// the Pod's VPC RouteTable, so the ElasticIP specs get their own
	// network. The NATGateway specs get a second one because its main
	// RouteTable points 0/0 at the gateway instead.
	arpVpcName    = "e2e-arp-vpc"
	arpSubnetName = "e2e-arp-subnet"
	arpSubnetCIDR = "10.230.0.0/24"

	arpNATVpcName     = "e2e-arp-nat-vpc"
	arpNATSubnetName  = "e2e-arp-nat-subnet"
	arpNATSubnetCIDR  = "10.231.0.0/24"
	arpNATGatewayName = "e2e-arp-nat-gw"

	// The endpoint block backs one ElasticIP and one LoadBalancer VIP,
	// the gateway block one ExternalNetworkAttachment per Node.
	arpEndpointBlockSize = 4
	arpGatewayBlockSize  = 4
)

// ARP mode announces external addresses by answering ARP on the Nodes' own
// link, so these specs need a client on that link and the addresses to come
// from its prefix. Both are shared, and so is every peer's ARP cache, which
// is why the block is Serial for the same reason the BGP and NAT blocks are.
var _ = Describe("Juneau ExternalNetwork ARP mode", Ordered, Serial, func() {
	var (
		arpClient       *arpClientInstance
		endpointBlock   arpAddressBlock
		gatewayBlock    arpAddressBlock
		allClusterNodes []string
	)

	BeforeAll(func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2), "the ARP specs need at least 2 worker nodes")

		var err error
		allClusterNodes, err = discoverAllNodes(repoRoot)
		Expect(err).NotTo(HaveOccurred())

		By("starting an external ARP client on the docker network the Nodes share")
		arpClient, err = ensureARPClient()
		Expect(err).NotTo(HaveOccurred())

		endpointBlock = newARPAddressBlock(0, arpEndpointBlockSize)
		gatewayBlock = newARPAddressBlock(arpEndpointBlockSize, arpGatewayBlockSize)

		By(fmt.Sprintf("creating ARP AddressPools %s and %s", endpointBlock.poolEntry(), gatewayBlock.poolEntry()))
		Expect(applyARPAddressPool(arpAddressPoolName, []string{endpointBlock.poolEntry()})).To(Succeed())
		Expect(applyARPAddressPool(arpNATAddressPoolName, []string{gatewayBlock.poolEntry()})).To(Succeed())
		Expect(applyARPExternalNetwork(arpExternalNetworkName, []string{arpAddressPoolName})).To(Succeed())
		Expect(applyARPExternalNetwork(arpNATExternalNetworkName, []string{arpNATAddressPoolName})).To(Succeed())

		By("creating the VPC the ElasticIP specs run in")
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
`, arpVpcName, arpSubnetName, arpVpcName, arpSubnetCIDR, arpVpcName, arpVpcName))).To(Succeed())
		waitSubnetReady(arpSubnetName)

		By("creating the VPC and NATGateway the egress spec runs in")
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
`, arpNATVpcName, arpNATSubnetName, arpNATVpcName, arpNATSubnetCIDR))).To(Succeed())
		waitSubnetReady(arpNATSubnetName)

		Expect(applyNATGateway(arpNATGatewayName, arpNATVpcName, arpNATExternalNetworkName)).To(Succeed())
		waitNATGatewayReady(arpNATGatewayName)

		Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: %s
spec:
  vpc: %s
  routes:
    - dst: 0.0.0.0/0
      via:
        type: natGateway
        natGateway: %s
`, arpNATVpcName, arpNATVpcName, arpNATGatewayName))).To(Succeed())
	})

	AfterAll(func() {
		// The NATGateway cannot be deleted while a RouteTable still routes
		// through it, so the reference goes first.
		clearMain := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: %s
spec:
  vpc: %s
`, arpNATVpcName, arpNATVpcName)
		if err := runWithStdin(repoRoot, clearMain, "kubectl", "apply", "-f", "-"); err != nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "best-effort clear of the NAT RouteTable routes failed: %v\n", err)
		}

		runBestEffort(repoRoot, "kubectl", "delete", "natgateway", arpNATGatewayName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", arpNATVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", arpNATSubnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", arpNATVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", arpVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", arpSubnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", arpVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", arpExternalNetworkName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", arpNATExternalNetworkName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "addresspool", arpAddressPoolName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "addresspool", arpNATAddressPoolName, "--ignore-not-found=true")
		teardownARPClient()
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		dumpARPDiagnostics()
	})

	// A1 is where the ARP address form meets the allocator. An ARP-mode
	// AddressPool writes start-end, which has no CIDR that says the same
	// thing, so it has to reach the AllocationPool as a range.
	It("A1: turns an ARP AddressPool into an AllocationPool of ranges", func() {
		for _, tc := range []struct {
			addressPool string
			block       arpAddressBlock
		}{
			{arpAddressPoolName, endpointBlock},
			{arpNATAddressPoolName, gatewayBlock},
		} {
			name := "addr-" + tc.addressPool
			Eventually(func(g Gomega) {
				pool, err := getAllocationPool(name)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(pool.Spec.IP.Ranges).To(Equal([]allocationPoolIPRange{
					{Start: tc.block.Start, End: tc.block.End},
				}), "allocationpool %s ranges", name)
				g.Expect(pool.Spec.IP.CIDRs).To(BeEmpty(), "allocationpool %s should carry no cidrs", name)
			}).Should(Succeed())
		}
	})

	Describe("ElasticIP on an ARP ExternalNetwork", Ordered, func() {
		const (
			eipNamespace  = "e2e-arp-eip"
			eipPodName    = "nginx"
			eipName       = "eip-arp"
			eipAttachName = "eip-att-arp"
		)
		var (
			eipAddress string
			eipNode    string
		)

		BeforeAll(func() {
			eipNode = workerNodes[0]

			createNamespace(eipNamespace)
			DeferCleanup(func() {
				runBestEffort(repoRoot, "kubectl", "delete", "elasticipattachment", "-n", eipNamespace, eipAttachName, "--ignore-not-found=true")
				runBestEffort(repoRoot, "kubectl", "delete", "elasticip", "-n", eipNamespace, eipName, "--ignore-not-found=true")
				runBestEffort(repoRoot, "kubectl", "delete", "namespace", eipNamespace, "--ignore-not-found=true", "--timeout=60s")
			})

			By(fmt.Sprintf("creating an nginx Pod on %s in subnet %s", eipNode, arpSubnetName))
			Expect(applyManifest(podManifest(eipNamespace, eipPodName, eipNode, arpSubnetName, true))).To(Succeed())
			waitPodsReady(eipNamespace, eipPodName)

			interfaceName := eipPodName + ".eth0"
			By(fmt.Sprintf("waiting for NetworkInterface %s to be created", interfaceName))
			Eventually(func(g Gomega) {
				out, err := kubectlJSONPath(repoRoot, `{.metadata.name}`, "-n", eipNamespace, "get", "networkinterface", interfaceName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(out)).To(Equal(interfaceName))
			}).Should(Succeed())

			By("allocating an ElasticIP and attaching it to the Pod's NetworkInterface")
			Expect(applyElasticIP(eipNamespace, eipName, arpExternalNetworkName)).To(Succeed())
			eipAddress = waitElasticIPAddress(eipNamespace, eipName)
			Expect(endpointBlock.contains(eipAddress)).To(BeTrue(),
				"ElasticIP %s should come from %s", eipAddress, endpointBlock.poolEntry())

			Expect(applyElasticIPAttachment(eipNamespace, eipAttachName, eipName, interfaceName)).To(Succeed())
			waitElasticIPAttachmentReady(eipNamespace, eipAttachName)
			waitElasticIPAttached(eipNamespace, eipName)
		})

		// A2 is the whole promise of ARP mode in one assertion: the address
		// exists on the link only because one node answers for it, and only
		// the node holding the attachment may do so.
		It("A2: has the attachment's node, and only that node, answer for the ElasticIP", func() {
			By("checking the ElasticIP controller published an ARPAdvertisement naming the attachment's node")
			Expect(waitARPAdvertisementNode(eipAddress)).To(Equal(eipNode))

			Eventually(func(g Gomega) {
				node, err := kubectlJSONPath(repoRoot, `{.spec.nodeName}`, "get", "arpadvertisement",
					fmt.Sprintf("eip-%s-%s", eipNamespace, eipName))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(node)).To(Equal(eipNode))
			}).Should(Succeed())

			By(fmt.Sprintf("arping %s from the external client", eipAddress))
			assertARPAnsweredBy(arpClient, eipAddress, eipNode)
		})

		// A3 follows the ARP reply with real traffic. The reply only points
		// at a node; the packet still has to pass the external_address_pools
		// gate and the ElasticIP DNAT before the Pod sees it.
		It("A3: serves the Pod behind the ElasticIP to the external client", func() {
			Eventually(func(g Gomega) {
				out, err := arpClient.curl(fmt.Sprintf("http://%s/", eipAddress))
				g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
				g.Expect(out).To(ContainSubstring("Welcome to nginx"), "curl body: %s", out)
			}, 90*time.Second, 3*time.Second).Should(Succeed())
		})
	})

	Describe("ServiceLoadBalancer on an ARP ExternalNetwork", Ordered, func() {
		const (
			lbNamespace = "e2e-arp-lb"
			lbSelector  = "lb-backend"
			lbService   = "lb-service"
		)
		var (
			vip          string
			electedNode  string
			backendPods  map[string]string
			survivingPod string
		)

		BeforeAll(func() {
			createNamespace(lbNamespace)
			DeferCleanup(func() {
				runBestEffort(repoRoot, "kubectl", "delete", "namespace", lbNamespace, "--ignore-not-found=true", "--timeout=60s")
			})

			By("placing one backend on each worker so both are eligible to answer")
			backendPods = map[string]string{}
			for i, node := range workerNodes[:2] {
				podName := fmt.Sprintf("%s-%d", lbSelector, i)
				backendPods[node] = podName
				Expect(applyManifest(arpBackendPodManifest(lbNamespace, podName, node, defaultSubnetName, lbSelector))).To(Succeed())
			}
			for _, podName := range backendPods {
				waitPodsReady(lbNamespace, podName)
			}

			By("creating a Juneau-managed LoadBalancer Service on the ARP ExternalNetwork")
			Expect(applyManifest(loadBalancerServiceManifest(lbNamespace, lbService, arpExternalNetworkName, lbSelector))).To(Succeed())

			vip = waitServiceLoadBalancerVIP(lbNamespace, lbService)
			Expect(endpointBlock.contains(vip)).To(BeTrue(),
				"VIP %s should come from %s", vip, endpointBlock.poolEntry())

			By("waiting for both workers to advertise the VIP")
			Eventually(func(g Gomega) {
				out, err := kubectlJSONPath(repoRoot, "{.status.advertisingNodes}",
					"-n", lbNamespace, "get", "serviceloadbalancer", lbService)
				g.Expect(err).NotTo(HaveOccurred())
				for _, node := range workerNodes[:2] {
					g.Expect(out).To(ContainSubstring(node), "advertisingNodes %s", out)
				}
			}).Should(Succeed())
		})

		// A4 is the difference between BGP and ARP mode for a VIP. Every
		// node with a ready local backend advertises it over BGP and the
		// upstream router load-balances; on an ARP link exactly one node may
		// answer, or the peers' neighbor entries disagree on where to send.
		It("A4: elects exactly one node to answer for the VIP and serves it", func() {
			electedNode = waitARPAdvertisementNode(vip)
			Expect(workerNodes[:2]).To(ContainElement(electedNode))

			By("checking the ServiceLoadBalancer mirrors the elected node")
			Eventually(func(g Gomega) {
				out, err := kubectlJSONPath(repoRoot, "{.status.arpAnnouncingNode}",
					"-n", lbNamespace, "get", "serviceloadbalancer", lbService)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(out)).To(Equal(electedNode))
			}).Should(Succeed())

			By(fmt.Sprintf("arping the VIP %s from the external client", vip))
			assertARPAnsweredBy(arpClient, vip, electedNode)

			By("curling the VIP from the external client")
			Eventually(func(g Gomega) {
				out, err := arpClient.curl(fmt.Sprintf("http://%s/", vip))
				g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
				g.Expect(out).To(ContainSubstring("Welcome to nginx"), "curl body: %s", out)
			}, 90*time.Second, 3*time.Second).Should(Succeed())
		})

		// A5 takes the elected node's backend away, which drops it out of
		// advertisingNodes and forces the VIP onto the other one.
		//
		// The neighbor flush below is not test scaffolding, it is the
		// documented failover cost: juneau sends no gratuitous ARP, so a
		// peer keeps sending to the old node's MAC until its own neighbor
		// entry ages out. Flushing stands in for that wait; without it the
		// VIP stays unreachable for as long as the peer's cache says
		// otherwise, and that is the behaviour, not a defect.
		It("A5: moves the VIP to another node when the elected node loses its backend", func() {
			Expect(electedNode).NotTo(BeEmpty(), "A4 must have elected a node first")

			var remainingNode string
			for _, node := range workerNodes[:2] {
				if node != electedNode {
					remainingNode = node
					survivingPod = backendPods[node]
				}
			}
			Expect(remainingNode).NotTo(BeEmpty())

			By(fmt.Sprintf("deleting the backend on the elected node %s", electedNode))
			Expect(run(repoRoot, "kubectl", "delete", "pod", "-n", lbNamespace,
				backendPods[electedNode], "--ignore-not-found=true", "--timeout=60s")).To(Succeed())

			By("waiting for the ARPAdvertisement to name the remaining node")
			Eventually(func(g Gomega) {
				g.Expect(waitARPAdvertisementNodeOnce(g, vip)).To(Equal(remainingNode))
			}).Should(Succeed())

			By(fmt.Sprintf("checking %s still backs the VIP", survivingPod))
			waitPodsReady(lbNamespace, survivingPod)

			By(fmt.Sprintf("arping the VIP %s again after the move", vip))
			assertARPAnsweredBy(arpClient, vip, remainingNode)

			By("curling the VIP once the client has forgotten the old MAC")
			Eventually(func(g Gomega) {
				g.Expect(arpClient.flushNeighbor(vip)).To(Succeed())
				out, err := arpClient.curl(fmt.Sprintf("http://%s/", vip))
				g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
				g.Expect(out).To(ContainSubstring("Welcome to nginx"), "curl body: %s", out)
			}, 90*time.Second, 3*time.Second).Should(Succeed())
		})
	})

	// A6 is the egress half. A NATGateway address belongs to one node
	// already, so ARP mode only has to make that node answer for it — but
	// the reply is what lets the answer come back at all.
	It("A6: sends Pod egress out of the ARP NATGateway address the owning node answers for", func() {
		node := workerNodes[0]
		namespace := "e2e-arp-nat-egress"
		podName := "client"

		createNamespace(namespace)
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
		})

		By(fmt.Sprintf("locating the ExternalNetworkAttachment for %s", node))
		assignedIP := attachmentIPForNode(arpNATExternalNetworkName, node)
		Expect(gatewayBlock.contains(assignedIP)).To(BeTrue(),
			"attachment address %s should come from %s", assignedIP, gatewayBlock.poolEntry())

		By(fmt.Sprintf("creating a curl Pod on %s in subnet %s", node, arpNATSubnetName))
		Expect(applyManifest(podManifest(namespace, podName, node, arpNATSubnetName, false))).To(Succeed())
		waitPodsReady(namespace, podName)

		By(fmt.Sprintf("curling http://%s/ from the Pod", arpClient.ip))
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
				"curl", "-sS", "--max-time", "5", fmt.Sprintf("http://%s/", arpClient.ip))
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(strings.TrimSpace(out)).To(Equal("ok"))
		}).Should(Succeed())

		By(fmt.Sprintf("verifying the external client saw src=%s", assignedIP))
		Eventually(func(g Gomega) {
			logs, err := dockerLogsCombined(arpClientContainerName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(logs).To(ContainSubstring(assignedIP), "httpd access log should record src=%s", assignedIP)
		}).Should(Succeed())

		By(fmt.Sprintf("arping the attachment address %s from the external client", assignedIP))
		assertARPAnsweredBy(arpClient, assignedIP, node)
	})

	// A7 guards the one decision that can take a whole cluster off the
	// network. node_ingress runs on the physical NIC and now looks at every
	// ARP request on it; an unknown target has to go to the host stack, so
	// the Node keeps answering for its own InternalIP. Dropping the miss
	// instead would leave every Node unreachable.
	It("A7: keeps answering ARP for the Nodes' own InternalIPs", func() {
		for _, node := range allClusterNodes {
			address := nodeInternalIP(node)
			By(fmt.Sprintf("arping %s (%s) from the external client", node, address))
			assertARPAnsweredBy(arpClient, address, node)
		}
	})
})

// waitARPAdvertisementNodeOnce is the single-shot form of
// waitARPAdvertisementNode, for callers that already run inside an
// Eventually and need to poll on the node name rather than on existence.
func waitARPAdvertisementNodeOnce(g Gomega, address string) string {
	items, err := arpAdvertisementsForAddress(address)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(items).To(HaveLen(1), "expected exactly one ARPAdvertisement for %s, got %v", address, items)
	return strings.TrimSpace(items[0].Spec.NodeName)
}
