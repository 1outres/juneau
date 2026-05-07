package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// LoadBalancer e2e exercises the full external-traffic path for a
// Service.type=LoadBalancer with the Juneau loadBalancerClass:
//
//	BGP peer (ECMP) → worker eth0 → node_ingress: SNAT(NodeIP)+DNAT(backend Pod)
//	  → backend nginx → pod_egress (node_underlay bypass on cross-Node replies)
//	  → receiving worker eth0 → node_ingress LB_IN: reverse rewrite → BGP peer
//
// The suite reuses the BGP infrastructure (peer container + RPF
// workaround) but provisions its own AddressPool / ExternalNetwork /
// Vpc so it never collides with the BGP / NAT specs and can run
// alongside them under -ginkgo.procs=1.
//
// Serial because it shares the kind-bridge RPF workaround and the
// opposing BGP peer container with bgp_test.go and nat_test.go.
const (
	lbExternalCIDR       = "192.0.2.128/26"
	lbAddressPoolName    = "e2e-lb-pool"
	lbAdvertisementName  = "e2e-lb-adv"
	lbExternalNetwork    = "e2e-lb-extnet"
	lbBGPPeerName        = "e2e-lb-peer"
	lbVpcName            = "e2e-lb-vpc"
	lbSubnetName         = "e2e-lb-subnet"
	lbSubnetCIDR         = "10.210.0.0/24"
	lbNamespacePrefix    = "e2e-lb"
	lbLoadBalancerClass  = "juneau.loutres.me/lb"
	lbExtNetAnnotationK  = "juneau.loutres.me/external-network"
	lbRequestedIPAnnoK   = "juneau.loutres.me/loadbalancer-ip"
	lbVpcAnnotationKey   = "juneau.loutres.me/vpc"
	lbServiceConvergence = 90 * time.Second
)

var _ = Describe("Juneau LoadBalancer Service", Ordered, Serial, func() {
	BeforeAll(func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2),
			"LoadBalancer e2e needs >= 2 worker nodes for cross-node backend coverage")

		By("ensuring opposing BGP router container is running")
		if bgpRouter == nil {
			router, err := ensureBGPRouter(workerNodes)
			Expect(err).NotTo(HaveOccurred())
			bgpRouter = router
		}

		By("installing kind-bridge host RPF workaround for the LB CIDR")
		// LB SNATs to the receiver Node's underlay IP, but external
		// clients (the BGP peer container) sourced from lbExternalCIDR
		// would still trigger RPF on a strict-RPF host without a route
		// for that prefix. Re-using the BGP suite's host workaround on
		// our specific CIDR keeps coverage symmetric with bgp_test /
		// nat_test.
		Expect(applyKindBridgeHostRPFWorkaround(lbExternalCIDR)).To(Succeed())

		By("waiting for BGPNodeState resources to exist for every worker")
		Eventually(func(g Gomega) {
			for _, node := range workerNodes {
				_, err := getBGPNodeState(node)
				g.Expect(err).NotTo(HaveOccurred(), "bgpnodestate %s not created yet", node)
			}
		}).Should(Succeed())

		By("creating BGPPeer / AddressPool / BGPAdvertisement / ExternalNetwork")
		Expect(applyBGPPeer(lbBGPPeerName, bgpRouter.ip)).To(Succeed())
		Expect(applyAddressPool(lbAddressPoolName, []string{lbExternalCIDR})).To(Succeed())
		Expect(applyBGPAdvertisement(lbAdvertisementName, []string{lbAddressPoolName})).To(Succeed())
		Expect(applyExternalNetwork(lbExternalNetwork, []string{lbAddressPoolName})).To(Succeed())

		By("waiting for BGP sessions on every worker")
		for _, node := range workerNodes {
			waitBGPSessionUp(node, bgpRouter.ip, lbBGPPeerName)
			waitBGPAdvertisement(node, lbAddressPoolName, lbExternalCIDR)
		}

		By("waiting for the opposing router to learn the LB CIDR with ECMP next-hops")
		waitBirdRouteOnRouter(bgpRouter, lbExternalCIDR, len(workerNodes))

		By("creating a service-enabled Vpc + Subnet for the LB backends")
		// service.consume=true is the umbrella that turns on Service
		// routing for the Vpc, which the daemon's service reconciler
		// requires before it programs service_map entries (LB Services
		// share the same map as ClusterIP). The webhook also enforces
		// this gate.
		Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  service:
    consume: true
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, lbVpcName, lbSubnetName, lbVpcName, lbSubnetCIDR))).To(Succeed())
		waitSubnetReady(lbSubnetName)
	})

	AfterAll(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "bgpadvertisement", lbAdvertisementName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", lbExternalNetwork, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "addresspool", lbAddressPoolName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "bgppeer", lbBGPPeerName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", lbSubnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", lbVpcName, "--ignore-not-found=true")
		cleanupKindBridgeHostRPFWorkaround(lbExternalCIDR)
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		dumpBGPDiagnostics(bgpRouter)
		dumpResource("services", "-A", "-o", "wide")
	})

	It("L1: allocates a LoadBalancer ingress IP and answers from outside the cluster", func() {
		namespace := lbNamespacePrefix + "-" + sanitizeName("l1")
		svcName := "nginx"
		serverPodName := "nginx-l1"

		createNamespace(namespace)
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "service", "-n", namespace, svcName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
		})

		By("placing an nginx Pod on worker[0] in the LB Vpc subnet")
		Expect(applyManifest(podManifest(namespace, serverPodName, workerNodes[0], lbSubnetName, true))).To(Succeed())
		waitPodsReady(namespace, serverPodName)
		labelPodApp(namespace, serverPodName, "lb-l1")
		stampBackend(namespace, serverPodName, "BACKEND-L1")

		By("creating Service.type=LoadBalancer with the Juneau class and ExternalNetwork annotation")
		Expect(applyManifest(loadBalancerServiceManifest(namespace, svcName, "lb-l1", lbVpcName, lbExternalNetwork, "" /* requestedIP */))).To(Succeed())

		By("waiting for status.loadBalancer.ingress[0].ip to be allocated from the LB AddressPool")
		ip := waitLoadBalancerIngressIP(namespace, svcName)
		Expect(ip).To(HavePrefix("192.0.2."), "LB IP should be allocated from %s", lbExternalCIDR)

		By("verifying the mutating webhook turned allocateLoadBalancerNodePorts off")
		nodePortsRaw, err := kubectlJSONPath(repoRoot, `{.spec.allocateLoadBalancerNodePorts}`,
			"-n", namespace, "get", "service", svcName)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(nodePortsRaw)).To(Equal("false"),
			"mutating webhook should set allocateLoadBalancerNodePorts=false")

		By(fmt.Sprintf("curling http://%s/ from the BGP peer container", ip))
		Eventually(func(g Gomega) {
			out, err := bgpRouter.Exec("curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s/", ip))
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(out).To(ContainSubstring("BACKEND-L1"))
		}, lbServiceConvergence, 3*time.Second).Should(Succeed())
	})

	It("L2: distributes traffic across backends on different nodes (cross-node DNAT)", func() {
		namespace := lbNamespacePrefix + "-" + sanitizeName("l2")
		svcName := "nginx"
		serverA := "lb-server-a"
		serverB := "lb-server-b"

		createNamespace(namespace)
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "service", "-n", namespace, svcName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
		})

		By("placing one nginx Pod on each worker (cross-node backend coverage)")
		Expect(applyManifest(podManifest(namespace, serverA, workerNodes[0], lbSubnetName, true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, serverB, workerNodes[1], lbSubnetName, true))).To(Succeed())
		waitPodsReady(namespace, serverA, serverB)
		labelPodApp(namespace, serverA, "lb-l2")
		labelPodApp(namespace, serverB, "lb-l2")
		stampBackend(namespace, serverA, "BACKEND-A")
		stampBackend(namespace, serverB, "BACKEND-B")

		By("creating Service.type=LoadBalancer with two-pod backend set")
		Expect(applyManifest(loadBalancerServiceManifest(namespace, svcName, "lb-l2", lbVpcName, lbExternalNetwork, ""))).To(Succeed())
		waitServiceTwoEndpoints(namespace, svcName)

		ip := waitLoadBalancerIngressIP(namespace, svcName)
		By(fmt.Sprintf("verifying both backends are hit when the BGP peer curls http://%s/ many times", ip))
		// Cross-node DNAT means Node A may pick a backend on Node B and
		// SNAT to Node A's underlay IP. The reverse leg must come back
		// via Node B's pod_egress → kernel underlay → Node A's
		// node_ingress LB_IN reverse path. Hitting both bodies confirms
		// the full cross-Node round-trip works.
		Eventually(func(g Gomega) {
			out, err := bgpRouter.Exec("sh", "-c", fmt.Sprintf(
				"for i in $(seq 1 30); do curl -sS --max-time 3 http://%s/ 2>/dev/null; printf '\\n'; done", ip))
			g.Expect(err).NotTo(HaveOccurred(), "batched curl output: %s", out)
			lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
			seen := distinctSet(lines)
			g.Expect(seen).To(HaveKey("BACKEND-A"), "expected at least one response from BACKEND-A; bodies=%v", lines)
			g.Expect(seen).To(HaveKey("BACKEND-B"), "expected at least one response from BACKEND-B; bodies=%v", lines)
		}, lbServiceConvergence, 5*time.Second).Should(Succeed())
	})

	It("L3: honours the loadbalancer-ip annotation", func() {
		namespace := lbNamespacePrefix + "-" + sanitizeName("l3")
		svcName := "nginx"
		serverPodName := "nginx-l3"
		// 192.0.2.140 sits in the suite's lbExternalCIDR but is far
		// enough from the auto-assigned addresses (.129..) that we
		// avoid collisions with the L1/L2 specs running before us.
		pinnedIP := "192.0.2.140"

		createNamespace(namespace)
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "service", "-n", namespace, svcName, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
		})

		Expect(applyManifest(podManifest(namespace, serverPodName, workerNodes[0], lbSubnetName, true))).To(Succeed())
		waitPodsReady(namespace, serverPodName)
		labelPodApp(namespace, serverPodName, "lb-l3")
		stampBackend(namespace, serverPodName, "BACKEND-L3")

		Expect(applyManifest(loadBalancerServiceManifest(namespace, svcName, "lb-l3", lbVpcName, lbExternalNetwork, pinnedIP))).To(Succeed())

		By("waiting for the requested IP to be reflected in status.loadBalancer.ingress")
		Eventually(func(g Gomega) {
			ip := readLoadBalancerIngressIP(namespace, svcName)
			g.Expect(ip).To(Equal(pinnedIP))
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			out, err := bgpRouter.Exec("curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s/", pinnedIP))
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(out).To(ContainSubstring("BACKEND-L3"))
		}, lbServiceConvergence, 3*time.Second).Should(Succeed())
	})
})

// loadBalancerServiceManifest renders a Service.type=LoadBalancer with
// the Juneau class and required annotations. requestedIP is optional
// (empty string skips the loadbalancer-ip annotation).
func loadBalancerServiceManifest(namespace, name, appLabel, vpc, externalNetwork, requestedIP string) string {
	annotations := []string{
		fmt.Sprintf("    %s: %s", lbExtNetAnnotationK, externalNetwork),
		fmt.Sprintf("    %s: %s", lbVpcAnnotationKey, vpc),
	}
	if requestedIP != "" {
		annotations = append(annotations, fmt.Sprintf("    %s: %q", lbRequestedIPAnnoK, requestedIP))
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
  annotations:
%s
spec:
  type: LoadBalancer
  loadBalancerClass: %s
  selector:
    app: %s
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
`, namespace, name, strings.Join(annotations, "\n"), lbLoadBalancerClass, appLabel)
}

// waitLoadBalancerIngressIP blocks until the controller publishes
// status.loadBalancer.ingress[0].ip and returns it.
func waitLoadBalancerIngressIP(namespace, name string) string {
	var ip string
	Eventually(func(g Gomega) {
		ip = readLoadBalancerIngressIP(namespace, name)
		g.Expect(ip).NotTo(BeEmpty(), "service %s/%s LoadBalancer ingress not yet populated", namespace, name)
	}).Should(Succeed())
	return ip
}

// readLoadBalancerIngressIP returns the current ingress[0].ip without
// blocking. Empty string when not yet populated.
func readLoadBalancerIngressIP(namespace, name string) string {
	out, err := kubectlJSONPath(repoRoot,
		`{.status.loadBalancer.ingress[0].ip}`,
		"-n", namespace, "get", "service", name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
