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
})

// --- helpers ---------------------------------------------------------

type sgFixture struct {
	base             string
	namespace        string
	vpcName          string
	serverSubnet     string
	clientSubnet     string
	serverSubnetCIDR string
	clientSubnetCIDR string

	enforceSG bool

	serverNode string
	clientNode string

	createdSGs []string
}

func newSGFixture(base string) *sgFixture {
	return &sgFixture{
		base:             base,
		namespace:        "e2e-" + base,
		vpcName:          "vpc-" + base,
		serverSubnet:     "subnet-a-" + base,
		clientSubnet:     "subnet-b-" + base,
		serverSubnetCIDR: cidrForScenario(base, 0),
		clientSubnetCIDR: cidrForScenario(base, 1),
		serverNode:       workerNodes[0],
		clientNode:       workerNodes[0],
	}
}

func (f *sgFixture) CreateNetwork() {
	createNamespace(f.namespace)

	enforceLine := ""
	if f.enforceSG {
		enforceLine = "  enforceSecurityGroups: true\n"
	}

	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
%s---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, f.vpcName, enforceLine,
		f.serverSubnet, f.vpcName, f.serverSubnetCIDR,
		f.clientSubnet, f.vpcName, f.clientSubnetCIDR)
	Expect(applyManifest(manifest)).To(Succeed())
	waitSubnetReady(f.serverSubnet)
	waitSubnetReady(f.clientSubnet)
}

// SGName returns the cluster-scoped SG name for the given short label.
// SecurityGroups are cluster-scoped, so to keep parallel test specs from
// stepping on each other we suffix every name with the fixture's base
// (which is itself derived from the spec name).
func (f *sgFixture) SGName(short string) string {
	return short + "--" + f.base
}

// CreateSG creates a SecurityGroup whose body is rulesYAML (a YAML
// fragment placed under spec, e.g. "  ingress: [...]"). Pass empty
// string for "no rules" — that produces a SG with default-deny ingress
// and default-allow egress.
//
// `name` is the short, fixture-local name (e.g. "server-sg"); the
// fully-qualified cluster-scoped name is f.SGName(name).
func (f *sgFixture) CreateSG(name, rulesYAML string) {
	full := f.SGName(name)
	// Rewrite any "name: <short>" occurrences in rulesYAML (used by
	// securityGroupRef peers) to point at the fully-qualified name.
	body := rulesYAML
	for _, peer := range []string{"client-sg", "server-sg", "guard-sg"} {
		body = strings.ReplaceAll(body, "name: "+peer+"\n", "name: "+f.SGName(peer)+"\n")
		body = strings.ReplaceAll(body, "name: "+peer+"$", "name: "+f.SGName(peer))
	}
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: SecurityGroup
metadata:
  name: %s
spec:
  vpc: %s%s
`, full, f.vpcName, body)
	Expect(applyManifest(manifest)).To(Succeed())
	f.createdSGs = append(f.createdSGs, full)

	// Wait for GroupID to be allocated so the daemon's BPF projection
	// has a chance to fire before any traffic-checking spec body runs.
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot, `{.status.groupID}`, "get", "securitygroup", full)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).NotTo(BeEmpty())
		g.Expect(strings.TrimSpace(got)).NotTo(Equal("0"))
	}).Should(Succeed())
}

// CreatePod creates a server (nginx) or client (curl) Pod with optional
// SG annotation. `sgs` are the short fixture-local names; CreatePod
// expands them via SGName before applying. node defaults to fixture's
// serverNode/clientNode based on `server`.
func (f *sgFixture) CreatePod(name, subnet string, server bool, sgs []string) {
	node := f.clientNode
	if server {
		node = f.serverNode
	}
	expanded := make([]string, len(sgs))
	for i, s := range sgs {
		expanded[i] = f.SGName(s)
	}
	Expect(applyManifest(podManifestWithSG(f.namespace, name, node, subnet, server, expanded))).To(Succeed())
}

func (f *sgFixture) Cleanup() {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", f.namespace, "--ignore-not-found=true", "--timeout=60s")
	for _, sg := range f.createdSGs {
		runBestEffort(repoRoot, "kubectl", "delete", "securitygroup", sg, "--ignore-not-found=true")
	}
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", f.serverSubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", f.clientSubnet, "--ignore-not-found=true")
	// RouteTable is owned by Vpc and is GC'd cascadingly when the Vpc
	// is deleted; the webhook explicitly forbids manual deletion of a
	// Vpc's main RouteTable, so we just delete the Vpc here.
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", f.vpcName, "--ignore-not-found=true")
}

func podManifestWithSG(namespace, name, nodeName, subnet string, server bool, sgs []string) string {
	annotations := []string{}
	if subnet != "" {
		annotations = append(annotations, fmt.Sprintf("    juneau.loutres.me/subnet: %s", subnet))
	}
	if len(sgs) > 0 {
		annotations = append(annotations, fmt.Sprintf("    juneau.loutres.me/security-groups: %q", strings.Join(sgs, ",")))
	}
	annBlock := ""
	if len(annotations) > 0 {
		annBlock = "  annotations:\n" + strings.Join(annotations, "\n") + "\n"
	}

	container := `    - name: client
      image: curlimages/curl:8.12.1
      command: ["sleep", "3600"]`
	if server {
		container = `    - name: server
      image: nginx:1.27
      ports:
        - containerPort: 80`
	}

	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  labels:
    app: %s
%sspec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
%s
`, namespace, name, name, annBlock, nodeName, container)
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

// assertNoPodConnectivity asserts a HTTP probe from clientPod to serverPod
// fails. We use a short-timeout single-shot probe — success would
// actively contradict the assertion, so retrying only delays real
// regressions.
func assertNoPodConnectivity(namespace, clientPod, serverPod string) {
	serverIP, err := kubectlJSONPath(repoRoot, `{.status.podIP}`, "-n", namespace, "get", "pod", serverPod)
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(serverIP)).NotTo(BeEmpty())

	out, curlErr := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--",
		"curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s", strings.TrimSpace(serverIP)))
	Expect(curlErr).To(HaveOccurred(), "curl should fail per SG policy, got: %s", out)
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
