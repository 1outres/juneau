package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	natExternalCIDR = "198.51.100.0/24"
	natAddressPool  = "e2e-nat-pool"
	natExternalNet  = "e2e-nat-extnet"
	natGatewayName  = "e2e-nat-gw"
	natVpcName      = "e2e-nat-vpc"
	natSubnetName   = "e2e-nat-subnet"
	natSubnetCIDR   = "10.220.0.0/24"
	natBGPPeer      = "e2e-nat-peer"
)

// Phase 4b-1/2/3/5 introduced the NATGateway + ExternalNetworkAttachment
// + per-node /32 BGP advertisement chain that replaces the old
// hostGateway/MASQUERADE setup. The specs below cover that chain end to
// end. N1/N1.5/N2/N4 run without an external BGP router; the N3+B1
// DescribeTable that follows opts in via E2E_BGP_ROUTER=true.
var _ = Describe("Juneau NATGateway", Ordered, func() {
	BeforeAll(func() {
		By("ensuring an opposing BGP router container is running")
		if bgpRouter == nil {
			router, err := ensureBGPRouter(workerNodes)
			Expect(err).NotTo(HaveOccurred())
			bgpRouter = router
		}

		// kind places the BGP peer and workers on the same docker bridge,
		// so SNAT'd reply packets carry a source in natExternalCIDR. With
		// bridge-nf-call-iptables=1 + strict RPF (xt_rpfilter), the host
		// netfilter pipeline drops those replies because the host has no
		// route for natExternalCIDR. Install the host-side route so RPF
		// has a valid reverse path. ensureBGPRouter only does this for
		// bgpExternalCIDR; we need the equivalent for natExternalCIDR.
		By("installing kind-bridge host RPF workaround for natExternalCIDR")
		Expect(applyKindBridgeHostRPFWorkaround(natExternalCIDR)).To(Succeed())

		By("waiting for BGPNodeState resources to exist for every worker")
		Eventually(func(g Gomega) {
			for _, node := range workerNodes {
				_, err := getBGPNodeState(node)
				g.Expect(err).NotTo(HaveOccurred(), "bgpnodestate %s not created yet", node)
			}
		}).Should(Succeed())

		By("creating BGPPeer / AddressPool / ExternalNetwork")
		Expect(applyBGPPeer(natBGPPeer, bgpRouter.ip)).To(Succeed())
		Expect(applyAddressPool(natAddressPool, []string{natExternalCIDR})).To(Succeed())
		Expect(applyExternalNetwork(natExternalNet, []string{natAddressPool})).To(Succeed())

		By("creating Vpc + Subnet (NATGateway webhook requires the Vpc to exist)")
		vpcSubnetManifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
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
`, natVpcName, natSubnetName, natVpcName, natSubnetCIDR)
		Expect(applyManifest(vpcSubnetManifest)).To(Succeed())
		waitSubnetReady(natSubnetName)

		By("creating NATGateway and waiting for Ready")
		Expect(applyNATGateway(natGatewayName, natVpcName, natExternalNet)).To(Succeed())
		waitNATGatewayReady(natGatewayName)

		// Overwrite the main RouteTable (name = VPC name) with a 0/0
		// route via the NATGateway. The Vpc reconciler treats a
		// pre-existing same-named RT as the main RT, so updating its
		// spec gives every Pod in the default subnet a NAT egress path.
		By("setting 0/0 via natGateway on the main RouteTable")
		rtManifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
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
`, natVpcName, natVpcName, natGatewayName)
		Expect(applyManifest(rtManifest)).To(Succeed())
	})

	AfterAll(func() {
		// Drop the NATGateway reference from the main RT before deleting
		// the NATGateway itself; otherwise the delete is webhook-rejected.
		clearMain := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: %s
spec:
  vpc: %s
`, natVpcName, natVpcName)
		if err := runWithStdin(repoRoot, clearMain, "kubectl", "apply", "-f", "-"); err != nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "best-effort clear of main RT routes failed: %v\n", err)
		}

		runBestEffort(repoRoot, "kubectl", "delete", "natgateway", natGatewayName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", natSubnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", natVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", natVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", natExternalNet, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "addresspool", natAddressPool, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "bgppeer", natBGPPeer, "--ignore-not-found=true")
		cleanupKindBridgeHostRPFWorkaround(natExternalCIDR)
		teardownBGPRouter()
		bgpRouter = nil
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		dumpNATDiagnostics()
		dumpBGPDiagnostics(bgpRouter)
	})

	It("N1: becomes Ready and is assigned a non-zero gatewayID", func() {
		waitNATGatewayReady(natGatewayName)
		obj, err := getNATGateway(natGatewayName)
		Expect(err).NotTo(HaveOccurred())
		Expect(obj.Spec.Vpc).To(Equal(natVpcName))
		Expect(obj.Spec.ExternalNetwork).To(Equal(natExternalNet))
	})

	It("N1.5: is undeletable while a RouteTable references it via spec.routes", func() {
		// The main RouteTable created in BeforeAll already references
		// this NATGateway via 0/0, so the delete must be rejected.
		out, err := kubectlOutput(repoRoot, "delete", "natgateway", natGatewayName)
		Expect(err).To(HaveOccurred(), "delete should be rejected, got %q", out)

		_, err = kubectlJSONPath(repoRoot, "{.metadata.name}", "get", "natgateway", natGatewayName)
		Expect(err).NotTo(HaveOccurred(), "NATGateway should still exist after rejected delete")
	})

	It("N2: ExternalNetworkAttachments fan out to every Node with distinct AssignedIPs owned by the ExternalNetwork", func() {
		// The fan-out is per-Node, including the control-plane node;
		// workerNodes alone is not the right denominator.
		expectedNodes, err := discoverAllNodes(repoRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(expectedNodes).NotTo(BeEmpty())

		Eventually(func(g Gomega) {
			attachments, err := listExternalNetworkAttachments()
			g.Expect(err).NotTo(HaveOccurred())
			relevant := filterAttachmentsByExternalNetwork(attachments, natExternalNet)
			g.Expect(relevant).To(HaveLen(len(expectedNodes)),
				"expected one attachment per node, got %d for nodes %v", len(relevant), expectedNodes)

			seenNodes := map[string]bool{}
			seenIPs := map[string]string{}
			for _, att := range relevant {
				ip := strings.TrimSpace(att.Status.AssignedIP)
				g.Expect(ip).NotTo(BeEmpty(), "attachment %s missing AssignedIP", att.Metadata.Name)
				g.Expect(conditionStatus(att.Status.Conditions, "Ready")).To(Equal("True"), "attachment %s not Ready", att.Metadata.Name)
				g.Expect(att.Spec.NodeName).NotTo(BeEmpty(), "attachment %s missing nodeName", att.Metadata.Name)
				seenNodes[att.Spec.NodeName] = true
				if owner, exists := seenIPs[ip]; exists {
					g.Expect(att.Metadata.Name).To(Equal(owner), "duplicate AssignedIP %s for attachments %s and %s", ip, owner, att.Metadata.Name)
				}
				seenIPs[ip] = att.Metadata.Name

				// Lifetime is tied to the ExternalNetwork (NATGateway
				// removal does not GC the IP), so the ownerRef must be
				// the ExternalNetwork rather than the NATGateway.
				foundExtNetOwner := false
				for _, owner := range att.Metadata.OwnerReferences {
					if owner.Kind == "ExternalNetwork" && owner.Name == natExternalNet {
						foundExtNetOwner = true
						break
					}
				}
				g.Expect(foundExtNetOwner).To(BeTrue(), "attachment %s should be owned by ExternalNetwork %s, got %v",
					att.Metadata.Name, natExternalNet, att.Metadata.OwnerReferences)
			}
			for _, node := range expectedNodes {
				g.Expect(seenNodes).To(HaveKey(node), "no attachment created for node %s", node)
			}
		}).Should(Succeed())
	})

	It("N4: a NATGateway named 'default' triggers 0/0 auto-injection on the default VPC main RouteTable", func() {
		const (
			defaultExtNet   = "e2e-nat-default-extnet"
			defaultPool     = "e2e-nat-default-pool"
			defaultGW       = "default" // the literal name 'default' is what the controller looks for
			defaultPoolCIDR = "203.0.113.0/24"
		)

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "natgateway", defaultGW, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", defaultExtNet, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "addresspool", defaultPool, "--ignore-not-found=true")

			Eventually(func(g Gomega) {
				rt, err := getRouteTableObject(defaultVpcName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(routeWithDst(rt.Status.Routes, "0.0.0.0/0")).To(BeNil(), "default RT should drop 0/0 after default NATGateway is deleted")
			}).Should(Succeed())
		})

		Expect(applyAddressPool(defaultPool, []string{defaultPoolCIDR})).To(Succeed())
		Expect(applyExternalNetwork(defaultExtNet, []string{defaultPool})).To(Succeed())
		Expect(applyNATGateway(defaultGW, defaultVpcName, defaultExtNet)).To(Succeed())

		waitNATGatewayReady(defaultGW)

		Eventually(func(g Gomega) {
			rt, err := getRouteTableObject(defaultVpcName)
			g.Expect(err).NotTo(HaveOccurred())
			route := routeWithDst(rt.Status.Routes, "0.0.0.0/0")
			g.Expect(route).NotTo(BeNil(), "default RT %s missing 0/0 route", defaultVpcName)
			g.Expect(route.Via.Type).To(Equal("natGateway"))
			g.Expect(route.Via.NATGateway).To(Equal(defaultGW))
		}).Should(Succeed())
	})

	// N3 wires the data plane: a Pod on worker[i] sends to an external
	// IP, the per-node attachment IP advertised over BGP from worker[i]
	// only (B1) brings replies back to the right worker, and the SNAT'd
	// source visible in the httpd access log proves both NAPT direction
	// and the napt_src.host_ip byte order are correct.
	DescribeTable("N3+B1: NAPT egress with per-node /32 BGP advertisement",
		func(workerIndex int) {
			Expect(len(workerNodes)).To(BeNumerically(">=", 2), "N3 needs at least 2 worker nodes")
			node := workerNodes[workerIndex]

			By(fmt.Sprintf("locating the ExternalNetworkAttachment for %s", node))
			var assignedIP string
			Eventually(func(g Gomega) {
				attachments, err := listExternalNetworkAttachments()
				g.Expect(err).NotTo(HaveOccurred())
				for _, att := range attachments {
					if att.Spec.ExternalNetwork == natExternalNet && att.Spec.NodeName == node {
						assignedIP = strings.TrimSpace(att.Status.AssignedIP)
						g.Expect(assignedIP).NotTo(BeEmpty())
						return
					}
				}
				g.Expect(false).To(BeTrue(), "no attachment found for node %s on %s", node, natExternalNet)
			}).Should(Succeed())

			prefix := assignedIP + "/32"

			By(fmt.Sprintf("verifying %s is advertised only by %s in BGPNodeState", prefix, node))
			Eventually(func(g Gomega) {
				for _, n := range workerNodes {
					state, err := getBGPNodeState(n)
					g.Expect(err).NotTo(HaveOccurred())
					hasPrefix := false
					for _, adv := range state.Status.Advertisements {
						for _, p := range adv.Prefixes {
							if p == prefix {
								hasPrefix = true
							}
						}
					}
					if n == node {
						g.Expect(hasPrefix).To(BeTrue(), "node %s should advertise %s", n, prefix)
					} else {
						g.Expect(hasPrefix).To(BeFalse(), "node %s should NOT advertise %s", n, prefix)
					}
				}
			}).Should(Succeed())

			By(fmt.Sprintf("waiting for opposing router to install %s with single next-hop %s", prefix, bgpRouter.workerIPs[node]))
			Eventually(func(g Gomega) {
				out, err := bgpRouter.Exec("birdc", "show", "route", prefix, "all")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(ContainSubstring(prefix), "birdc output: %s", out)
				g.Expect(out).To(ContainSubstring(bgpRouter.workerIPs[node]),
					"expected next-hop %s in birdc output: %s", bgpRouter.workerIPs[node], out)
				g.Expect(strings.Count(out, "via ")).To(Equal(1),
					"expected single next-hop for per-node /32, got: %s", out)
			}).Should(Succeed())

			By("waiting for the main RouteTable to reflect 0/0 via natGateway in status")
			Eventually(func(g Gomega) {
				rt, err := getRouteTableObject(natVpcName)
				g.Expect(err).NotTo(HaveOccurred())
				route := routeWithDst(rt.Status.Routes, "0.0.0.0/0")
				g.Expect(route).NotTo(BeNil())
				g.Expect(route.Via.Type).To(Equal("natGateway"))
			}).Should(Succeed())

			suffix := sanitizeName(fmt.Sprintf("worker%d", workerIndex))
			namespace := fmt.Sprintf("e2e-nat-egress-%s", suffix)
			podName := "client"
			createNamespace(namespace)
			DeferCleanup(func() {
				runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			})

			By(fmt.Sprintf("creating a curl Pod on %s in subnet %s", node, natSubnetName))
			Expect(applyManifest(podManifest(namespace, podName, node, natSubnetName, false))).To(Succeed())
			waitPodsReady(namespace, podName)

			By(fmt.Sprintf("curling http://%s/ from the Pod (expect ok)", bgpRouter.ip))
			Eventually(func(g Gomega) {
				out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
					"curl", "-sS", "--max-time", "5", fmt.Sprintf("http://%s/", bgpRouter.ip))
				g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
				g.Expect(strings.TrimSpace(out)).To(Equal("ok"))
			}).Should(Succeed())

			By(fmt.Sprintf("verifying httpd access log records src=%s (post-SNAT)", assignedIP))
			Eventually(func(g Gomega) {
				logs, err := dockerLogsCombined(bgpRouterContainerName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(logs).To(ContainSubstring(assignedIP),
					"httpd access log should record src=%s; if you see a byte-reversed IP instead, the napt_src byte-order bug has regressed", assignedIP)
			}).Should(Succeed())
		},
		Entry("worker[0]", 0),
		Entry("worker[1]", 1),
	)
})

func filterAttachmentsByExternalNetwork(items []externalNetworkAttachmentObject, extNet string) []externalNetworkAttachmentObject {
	out := []externalNetworkAttachmentObject{}
	for _, item := range items {
		if item.Spec.ExternalNetwork == extNet {
			out = append(out, item)
		}
	}
	return out
}

func routeWithDst(routes []routeTableRoute, dst string) *routeTableRoute {
	for i := range routes {
		if routes[i].Dst == dst {
			return &routes[i]
		}
	}
	return nil
}
