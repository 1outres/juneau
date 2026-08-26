package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Juneau SecurityGroup E2E coverage:
//
// 1. Default behaviour: when neither Pod has a SG attached, traffic
//    flows as before.
// 2. Default-deny ingress: a server with a SG that has no ingress
//    rules drops every inbound packet.
// 3. CIDR-based ingress allow: a SG that explicitly admits the
//    client's Subnet CIDR (or 0.0.0.0/0) lets traffic through.
// 4. SG-reference ingress allow: a SG that admits members of another
//    SG lets matching peers in but blocks unattached peers.
// 5. Egress allow-list: a client with explicit egress SG can only
//    reach the destinations its rule names; everything else is dropped.
// 6. Cross-Node: same shape as (3) and (4), with client and server
//    pinned to different nodes.
// 7. enforceSecurityGroups: a Vpc with the flag set rejects Pods that
//    do not name at least one SG.
// 8. Enforcing peer: an unlisted peer that carries a SG of its own is
//    still denied, on one Node and across two. Case (4) leaves that
//    peer SG-less, so its sender hook enforces nothing.
// 9. Rule expansion: one rule admits every (peer, port) pair it lists,
//    and nothing else.
// 10. Both directions (issue #52): a SG whose ingress sits at its entry
//    budget still enforces the egress rules it declares.
// 11. Protocols (issue #53): `protocol: all` covers tcp, udp and
//    icmp. Every other IP protocol is dropped however wide the allow
//    rule is written.
// 12. Fragments (issue #53): a rule that names a UDP port admits a
//    datagram the sender had to fragment, not only its first packet.
//
// Every spec creates an isolated namespace + Vpc + Subnets so they can
// run in parallel under Ginkgo --procs.

var _ = Describe("Juneau SecurityGroup", func() {
	It("default: no SG attached → traffic flows", func() {
		base := sanitizeName("sg-default-allow")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// No SG → just baseline pod-to-pod connectivity.
		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("ingress without matching rule → traffic is dropped (default-deny)", func() {
		base := sanitizeName("sg-default-deny")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// Server SG admits TCP from a non-overlapping CIDR (so it does
		// not match the actual client). Empty ingress list also works,
		// but a stray rule guarantees the SG is in "ingress-rules-set"
		// state.
		fix.CreateSG("server-sg", `
  ingress:
    - from:
        - cidr: 192.0.2.0/24
      protocol: tcp
      ports:
        - port: 80`)

		fix.CreatePod(serverPodName, fix.serverSubnet, true, []string{"server-sg"})
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertNoPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("ingress CIDR rule admits the matching client subnet", func() {
		base := sanitizeName("sg-cidr-allow")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// Allow ingress from any IP — matches the client.
		fix.CreateSG("server-sg", `
  ingress:
    - from:
        - cidr: 0.0.0.0/0
      protocol: tcp
      ports:
        - port: 80`)

		fix.CreatePod(serverPodName, fix.serverSubnet, true, []string{"server-sg"})
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("ingress SG-reference admits attached peer, denies unattached peer", func() {
		base := sanitizeName("sg-ref-allow")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		// Three pods: server, client-a (attached to client-sg), client-b (no SG).
		fix.serverSubnetCIDR = cidrForScenario(base, 0)
		fix.CreateNetwork()
		// Add a third subnet for client-b on a different VPC to make its
		// Pod IP look distinctly unattached. Easier: keep on same Subnet.
		fix.CreateSG("client-sg", "")
		fix.CreateSG("server-sg", `
  ingress:
    - from:
        - securityGroupRef:
            name: client-sg
      protocol: tcp
      ports:
        - port: 80`)

		fix.CreatePod(serverPodName, fix.serverSubnet, true, []string{"server-sg"})
		fix.CreatePod("client-a", fix.clientSubnet, false, []string{"client-sg"})
		fix.CreatePod("client-b", fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, "client-a", "client-b")

		assertPodConnectivity(fix.namespace, "client-a", serverPodName)
		assertNoPodConnectivity(fix.namespace, "client-b", serverPodName)
	})

	It("egress allow-list blocks unlisted destinations", func() {
		base := sanitizeName("sg-egress-allowlist")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// server-sg allows all ingress from any peer so the test
		// isolates egress behaviour. We then create a second server
		// (server-b) on a non-overlapping IP that the client's egress
		// SG does NOT permit.
		fix.CreateSG("server-sg", `
  ingress:
    - from:
        - cidr: 0.0.0.0/0
      protocol: tcp
      ports:
        - port: 80`)
		// client-sg permits egress only to server-sg members.
		fix.CreateSG("client-sg", `
  egress:
    - to:
        - securityGroupRef:
            name: server-sg
      protocol: tcp
      ports:
        - port: 80`)

		fix.CreatePod(serverPodName, fix.serverSubnet, true, []string{"server-sg"})
		fix.CreatePod("server-b", fix.serverSubnet, true, nil) // no SG
		fix.CreatePod(clientPodName, fix.clientSubnet, false, []string{"client-sg"})
		waitPodsReady(fix.namespace, serverPodName, "server-b", clientPodName)

		// Allowed destination (member of server-sg) → connects.
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
		// Disallowed destination (not in server-sg) → blocked.
		assertNoPodConnectivity(fix.namespace, clientPodName, "server-b")
	})

	It("cross-Node: SG ingress eval applies to traffic that crossed VXLAN", func() {
		base := sanitizeName("sg-cross-node")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		fix.CreateSG("client-sg", "")
		fix.CreateSG("server-sg", `
  ingress:
    - from:
        - securityGroupRef:
            name: client-sg
      protocol: tcp
      ports:
        - port: 80`)

		// Force the server and client onto different worker nodes.
		fix.serverNode = workerNodes[0]
		fix.clientNode = workerNodes[1]

		fix.CreatePod(serverPodName, fix.serverSubnet, true, []string{"server-sg"})
		fix.CreatePod("client-a", fix.clientSubnet, false, []string{"client-sg"})
		fix.CreatePod("client-b", fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, "client-a", "client-b")

		assertPodConnectivity(fix.namespace, "client-a", serverPodName)
		assertNoPodConnectivity(fix.namespace, "client-b", serverPodName)
	})

	It("Vpc.spec.enforceSecurityGroups rejects Pods without a SG", func() {
		base := sanitizeName("sg-enforce")
		fix := newSGFixture(base)
		fix.enforceSG = true
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// Pod without an SG annotation → admission rejection.
		// Use applyManifestVerbose so the kubectl stderr (which contains
		// the webhook reason) is part of the returned error.
		stderr, err := applyManifestCapturingStderr(podManifestWithSG(fix.namespace, "no-sg-pod", workerNodes[0], fix.serverSubnet, true, nil))
		Expect(err).To(HaveOccurred(), "Pod without SG should be rejected")
		Expect(stderr).To(ContainSubstring("enforceSecurityGroups"))

		// Pod WITH an SG annotation → succeeds.
		fix.CreateSG("guard-sg", `
  ingress:
    - from:
        - cidr: 0.0.0.0/0
      protocol: tcp
      ports:
        - port: 80`)
		fix.CreatePod(serverPodName, fix.serverSubnet, true, []string{"guard-sg"})
		waitPodsReady(fix.namespace, serverPodName)
	})

	DescribeTable("ingress SG-reference denies an unlisted peer that is enforcing too",
		func(placement placementMode) {
			base := sanitizeName("sg-ref-enforcing-peer-" + string(placement))
			fix := newSGFixture(base)
			DeferCleanup(fix.Cleanup)
			fix.applyPlacement(placement)
			fix.CreateNetwork()

			// client-b carries a SG of its own, so its egress hook
			// admits the flow and writes a policy conntrack entry.
			// Before issue #51 that entry was what the server's
			// ingress hook found on the same Node, and the ingress
			// rules never ran. The SG-reference specs above leave
			// client-b without a SG, which is why they stayed green
			// while the bug was live.
			fix.CreateSG("client-sg", "")
			fix.CreateSG("other-sg", "")
			fix.CreateSG("server-sg", `
  ingress:
    - from:
        - securityGroupRef:
            name: client-sg
      protocol: tcp
      ports:
        - port: 80`)

			fix.CreatePod(serverPodName, fix.serverSubnet, true, []string{"server-sg"})
			fix.CreatePod("client-a", fix.clientSubnet, false, []string{"client-sg"})
			fix.CreatePod("client-b", fix.clientSubnet, false, []string{"other-sg"})
			waitPodsReady(fix.namespace, serverPodName, "client-a", "client-b")

			assertPodConnectivity(fix.namespace, "client-a", serverPodName)
			assertNoPodConnectivity(fix.namespace, "client-b", serverPodName)
		},
		Entry("same Node", placementSameNode),
		Entry("different Nodes", placementDifferentNodes),
	)

	It("expansion: one rule admits every peer and port it lists", func() {
		base := sanitizeName("sg-rule-expansion")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// A SG rule costs one data plane entry per (peer, port) pair,
		// so two peers and two ports is four entries. The client
		// matches only the second peer, and one of the ports it
		// reaches is the second one, so a data plane that stopped
		// short of the whole cross-product answers differently than
		// this spec wants.
		fix.CreateSG("server-sg", fmt.Sprintf(`
  ingress:
    - from:
        - cidr: %s
        - cidr: %s
      protocol: tcp
      ports:
        - port: %d
        - port: %d`, policyElsewhereCIDR, fix.clientSubnetCIDR, policyOpenPort, policyThirdPort))
		waitPolicyEntryCounts("securitygroup", fix.SGName("server-sg"), 4, 0)

		fix.CreatePodWithContainers(serverPodName, fix.serverSubnet, fix.serverNode,
			triplePortServerContainers(), []string{"server-sg"})
		fix.CreatePodWithContainers(clientPodName, fix.clientSubnet, fix.clientNode,
			curlClientContainer, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)

		By("admitting the first port of the rule")
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
		By("admitting the second port of the rule")
		assertPodPortConnectivity(fix.namespace, clientPodName, serverPodName, policyThirdPort, policyThirdBody)
		By("dropping the port the rule leaves out")
		assertNoPodPortConnectivity(fix.namespace, clientPodName, serverPodName, policyBlockedPort)
	})

	It("directions: a full ingress budget still leaves egress installed", func() {
		base := sanitizeName("sg-full-ingress-budget")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// server-sg admits both ports, so the only thing that can
		// decide between them is the client's own egress.
		fix.CreateSG("server-sg", fmt.Sprintf(`
  ingress:
    - from:
        - cidr: 0.0.0.0/0
      protocol: tcp
      ports:
        - port: %d
        - port: %d`, policyOpenPort, policyBlockedPort))

		// This is issue #52 on the SecurityGroup side. The ingress
		// rule lands on exactly sgEntriesPerDirection entries and
		// matches nothing in the fixture. Before each direction got
		// its own window in the rule array, those entries filled it,
		// the egress entry fell off the end, and the client's egress
		// closed completely.
		fix.CreateSG("client-sg", fmt.Sprintf(`
  ingress:
    - from:
        - cidr: %s
        - cidr: %s
      protocol: tcp
      ports:%s
  egress:
    - to:
        - cidr: 0.0.0.0/0
      protocol: tcp
      ports:
        - port: %d`,
			policyElsewhereCIDR, sgSecondElsewhereCIDR,
			sgFillerPorts(sgBudgetFillerPorts), policyOpenPort))
		clientSG := fix.SGName("client-sg")
		waitPolicyEntryCounts("securitygroup", clientSG, sgEntriesPerDirection, 1)
		waitResourceReady("securitygroup", clientSG)

		fix.CreatePodWithContainers(serverPodName, fix.serverSubnet, fix.serverNode,
			dualPortServerContainers(), []string{"server-sg"})
		fix.CreatePodWithContainers(clientPodName, fix.clientSubnet, fix.clientNode,
			curlClientContainer, []string{"client-sg"})
		waitPodsReady(fix.namespace, serverPodName, clientPodName)

		By("letting out the port the egress rule names")
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
		By("keeping in the port it does not")
		assertNoPodPortConnectivity(fix.namespace, clientPodName, serverPodName, policyBlockedPort)
	})

	It("protocols: `all` covers tcp, udp and icmp, and nothing else", func() {
		base := sanitizeName("sg-protocol-gate")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// This is issue #53. Both Pods carry a SG that admits every
		// peer on `all` in both directions, so no rule is left that
		// could turn a packet away: a protocol that still does not
		// arrive was stopped by what `all` means, not by a rule.
		fix.CreateSG("server-sg", `
  ingress:
    - from:
        - cidr: 0.0.0.0/0
      protocol: all`)
		fix.CreateSG("client-sg", `
  ingress:
    - from:
        - cidr: 0.0.0.0/0
      protocol: all
  egress:
    - to:
        - cidr: 0.0.0.0/0
      protocol: all`)
		waitPolicyEntryCounts("securitygroup", fix.SGName("server-sg"), 1, 0)
		waitPolicyEntryCounts("securitygroup", fix.SGName("client-sg"), 1, 1)
		waitResourceReady("securitygroup", fix.SGName("server-sg"))
		waitResourceReady("securitygroup", fix.SGName("client-sg"))

		fix.CreatePodWithContainers(serverPodName, fix.serverSubnet, fix.serverNode,
			unsupportedProtocolServerContainers(), []string{"server-sg"})
		fix.CreatePodWithContainers(clientPodName, fix.clientSubnet, fix.clientNode,
			netshootClientContainer, []string{"client-sg"})
		waitPodsReady(fix.namespace, serverPodName, clientPodName)

		assertPolicyDropsUnsupportedProtocol(fix.namespace)
	})

	It("fragments: a port rule admits a UDP datagram larger than the MTU", func() {
		base := sanitizeName("sg-udp-fragments")
		fix := newSGFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// Both directions name the port, so both enforcement points
		// have to know the ports of every fragment and not only of
		// the one that carries the UDP header.
		fix.CreateSG("server-sg", fmt.Sprintf(`
  ingress:
    - from:
        - cidr: 0.0.0.0/0
      protocol: udp
      ports:
        - port: %d`, policyUDPSinkPort))
		fix.CreateSG("client-sg", fmt.Sprintf(`
  ingress:
    - from:
        - cidr: 0.0.0.0/0
      protocol: udp
      ports:
        - port: %d
  egress:
    - to:
        - cidr: 0.0.0.0/0
      protocol: udp
      ports:
        - port: %d`, policyUDPSinkPort, policyUDPSinkPort))
		waitPolicyEntryCounts("securitygroup", fix.SGName("server-sg"), 1, 0)
		waitPolicyEntryCounts("securitygroup", fix.SGName("client-sg"), 1, 1)
		waitResourceReady("securitygroup", fix.SGName("server-sg"))
		waitResourceReady("securitygroup", fix.SGName("client-sg"))

		fix.CreatePodWithContainers(serverPodName, fix.serverSubnet, fix.serverNode,
			udpSinkContainer(policyUDPSinkContainer, policyUDPSinkPort), []string{"server-sg"})
		fix.CreatePodWithContainers(clientPodName, fix.clientSubnet, fix.clientNode,
			netshootClientContainer, []string{"client-sg"})
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		waitContainerLogLine(fix.namespace, serverPodName, policyUDPSinkContainer, policySinkReadyLine)

		clientIP := mustPodIP(fix.namespace, clientPodName)
		serverIP := mustPodIP(fix.namespace, serverPodName)
		mtu := podInterfaceMTU(fix.namespace, clientPodName)

		By("delivering a datagram that fits in one IP packet")
		fitting := mtu - policyUDPFitMargin
		sendUDPDatagram(fix.namespace, clientPodName, serverIP,
			policyUDPFittingSourcePort, policyUDPSinkPort, fitting)
		waitContainerLogLine(fix.namespace, serverPodName, policyUDPSinkContainer,
			sinkPacketRecord(clientIP, fitting))

		// Before the fragment map, a later fragment had no UDP
		// header, so the policy stage read its payload as ports and
		// no port rule matched.
		By("delivering a datagram the sender has to fragment")
		oversized := mtu + policyUDPOversizeMargin
		sendUDPDatagram(fix.namespace, clientPodName, serverIP,
			policyUDPOversizedSourcePort, policyUDPSinkPort, oversized)
		waitContainerLogLine(fix.namespace, serverPodName, policyUDPSinkContainer,
			sinkPacketRecord(clientIP, oversized))
	})
})

const (
	// sgEntriesPerDirection mirrors
	// juneauv1alpha1.SecurityGroupMaxEntriesPerDirection. The e2e
	// module does not depend on the controller module, so the number
	// is repeated here; the entry-count assertion is what ties the two
	// together.
	sgEntriesPerDirection = 8

	// sgSecondElsewhereCIDR is a second documentation-only prefix
	// (RFC 5737), so a rule can name two peers that match nothing.
	sgSecondElsewhereCIDR = "198.51.100.0/24"

	// A SG rule costs peers times ports, so naming this many peers and
	// this many ports lands a direction exactly on its budget.
	sgBudgetFillerPeers = 2
	sgBudgetFillerPorts = sgEntriesPerDirection / sgBudgetFillerPeers

	// sgFillerFirstPort starts well clear of the ports the fixtures
	// actually serve, so a filler can never admit real traffic.
	sgFillerFirstPort = 8100
)

// sgFillerPorts returns `count` port entries naming ports no listener
// in these fixtures binds. They cost their entries without changing any
// verdict, which is how a spec parks a direction at a chosen point in
// its budget.
func sgFillerPorts(count int) string {
	ports := make([]string, 0, count)
	for i := 0; i < count; i++ {
		ports = append(ports, fmt.Sprintf(`
        - port: %d`, sgFillerFirstPort+i))
	}
	return strings.Join(ports, "")
}

// --- helpers ---------------------------------------------------------

// sgFixture is policyFixture plus the Vpc-level enforcement switch this
// suite is the only user of.
type sgFixture struct {
	policyFixture

	enforceSG bool
}

func newSGFixture(base string) *sgFixture {
	return &sgFixture{policyFixture: *newPolicyFixture(base)}
}

func (f *sgFixture) CreateNetwork() {
	enforceLine := ""
	if f.enforceSG {
		enforceLine = "  enforceSecurityGroups: true\n"
	}
	f.createNetworkWithVpcSpec("spec:\n" + enforceLine)
}

// applyManifestCapturingStderr runs `kubectl apply -f -` with the given
// manifest, returning the kubectl stderr alongside the Go error so
// admission-rejection tests can grep for the rejection reason.
//
// runWithStdin pipes stderr to GinkgoWriter only and does not surface
// it in the returned error, which makes admission-failure test
// assertions impossible. This helper exists exclusively for cases
// where the rejection message itself is part of the contract.
func applyManifestCapturingStderr(manifest string) (string, error) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), fmt.Sprintf("KIND_CLUSTER=%s", clusterName))
	cmd.Stdin = strings.NewReader(manifest)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if stdout.Len() > 0 {
		_, _ = GinkgoWriter.Write(stdout.Bytes())
	}
	if stderr.Len() > 0 {
		_, _ = GinkgoWriter.Write(stderr.Bytes())
	}
	return stderr.String(), err
}

// assertPodConnectivityStops asserts a HTTP probe from clientPod to
// serverPod starts failing. It retries, unlike assertNoPodConnectivity:
// the caller has just taken a route away from a path that was working,
// and the daemon needs a moment to reprogram the data plane, so a
// single probe would race that update.
func assertPodConnectivityStops(namespace, clientPod, serverPod string) {
	serverIP, err := kubectlJSONPath(repoRoot, `{.status.podIP}`, "-n", namespace, "get", "pod", serverPod)
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(serverIP)).NotTo(BeEmpty())

	Eventually(func(g Gomega) {
		out, curlErr := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--",
			"curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s", strings.TrimSpace(serverIP)))
		g.Expect(curlErr).To(HaveOccurred(), "curl should fail once the route is withdrawn, got: %s", out)
	}).Should(Succeed())
}
