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
})

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
