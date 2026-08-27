package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/gomega"
)

// policyFixture is the scaffolding the NetworkACL, SecurityGroup and
// policy-placement suites share: an isolated namespace, a Vpc with two
// Subnets, and the helpers that attach either policy layer to them.
//
// NetworkACL and SecurityGroup are cluster-scoped, so every name a
// fixture creates carries the spec-derived `base` suffix. That is what
// keeps the suites parallelizable under Ginkgo --procs.
type policyFixture struct {
	base             string
	namespace        string
	vpcName          string
	serverSubnet     string
	clientSubnet     string
	serverSubnetCIDR string
	clientSubnetCIDR string

	serverNode string
	clientNode string

	createdACLs []string
	createdSGs  []string
}

func newPolicyFixture(base string) *policyFixture {
	return &policyFixture{
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

// applyPlacement pins the server and client Pods per the requested
// placement. Fixtures default to a single Node, so specs that care
// about placement have to say so.
func (f *policyFixture) applyPlacement(mode placementMode) {
	nodes := chooseNodes(mode)
	f.serverNode = nodes[0]
	f.clientNode = nodes[1]
}

func (f *policyFixture) CreateNetwork() {
	f.createNetworkWithVpcSpec("spec: {}\n")
}

// createNetworkWithVpcSpec builds the namespace, the Vpc and both
// Subnets. vpcSpec is the whole `spec:` block of the Vpc, newline
// terminated, so a suite can opt into Vpc-level settings.
func (f *policyFixture) createNetworkWithVpcSpec(vpcSpec string) {
	createNamespace(f.namespace)

	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
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
`, f.vpcName, vpcSpec,
		f.serverSubnet, f.vpcName, f.serverSubnetCIDR,
		f.clientSubnet, f.vpcName, f.clientSubnetCIDR)
	Expect(applyManifest(manifest)).To(Succeed())
	waitSubnetReady(f.serverSubnet)
	waitSubnetReady(f.clientSubnet)
}

// SGName returns the cluster-scoped SecurityGroup name for a short,
// fixture-local label.
func (f *policyFixture) SGName(short string) string { return short + "--" + f.base }

// SGNames expands a list of short labels.
func (f *policyFixture) SGNames(shorts []string) []string {
	full := make([]string, len(shorts))
	for i, short := range shorts {
		full[i] = f.SGName(short)
	}
	return full
}

// ACLName returns the cluster-scoped NetworkACL name for a short,
// fixture-local label.
func (f *policyFixture) ACLName(short string) string { return short + "--" + f.base }

// policySGPeerLabels are the short labels a rule body may name through
// securityGroupRef. qualifySGRefs rewrites those to the fixture-scoped
// names so a spec references its own copy of the peer group.
var policySGPeerLabels = []string{"client-sg", "server-sg", "guard-sg"}

// qualifySGRefs rewrites the short peer labels a rule body names into
// the fixture-scoped SecurityGroup names.
func (f *policyFixture) qualifySGRefs(rulesYAML string) string {
	lines := strings.Split(rulesYAML, "\n")
	for i, line := range lines {
		for _, peer := range policySGPeerLabels {
			suffix := "name: " + peer
			if !strings.HasSuffix(line, suffix) {
				continue
			}
			lines[i] = strings.TrimSuffix(line, suffix) + "name: " + f.SGName(peer)
			break
		}
	}
	return strings.Join(lines, "\n")
}

// CreateSG creates a SecurityGroup whose body is rulesYAML (a YAML
// fragment placed under spec, e.g. "  ingress: [...]"). Pass empty
// string for "no rules" — that produces a SG with default-deny ingress
// and default-allow egress.
//
// `name` is the short, fixture-local name (e.g. "server-sg"); the
// fully-qualified cluster-scoped name is f.SGName(name).
func (f *policyFixture) CreateSG(name, rulesYAML string) {
	f.applySG(name, rulesYAML)
	f.createdSGs = append(f.createdSGs, f.SGName(name))

	// Wait for GroupID to be allocated so the daemon's BPF projection
	// has a chance to fire before any traffic-checking spec body runs.
	full := f.SGName(name)
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot, `{.status.groupID}`, "get", "securitygroup", full)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).NotTo(BeEmpty())
		g.Expect(strings.TrimSpace(got)).NotTo(Equal("0"))
	}).Should(Succeed())
}

// ReplaceSGRules rewrites the rules of a SecurityGroup the fixture
// already created and waits for the controller to observe the change.
func (f *policyFixture) ReplaceSGRules(name, rulesYAML string) {
	f.applySG(name, rulesYAML)
	waitObservedGeneration("securitygroup", f.SGName(name))
}

func (f *policyFixture) applySG(name, rulesYAML string) {
	full := f.SGName(name)
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: SecurityGroup
metadata:
  name: %s
spec:
  vpc: %s%s
`, full, f.vpcName, f.qualifySGRefs(rulesYAML))
	Expect(applyManifest(manifest)).To(Succeed())
}

// CreateACL creates a NetworkACL whose body is rulesYAML — a YAML
// fragment placed under spec, e.g. "  ingress: [...]" or
// "  egress: [...]". Pass an empty string for "no rules" (yields a
// minimal ACL whose both directions are nil = default-allow, useful
// only for negative-control tests).
func (f *policyFixture) CreateACL(name, rulesYAML string) {
	f.applyACL(name, rulesYAML)
	f.createdACLs = append(f.createdACLs, f.ACLName(name))

	// Wait for ACLID allocation so the daemon has a chance to project
	// the ruleset before traffic-checking specs run.
	full := f.ACLName(name)
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot, `{.status.aclID}`, "get", "networkacl", full)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).NotTo(BeEmpty())
		g.Expect(strings.TrimSpace(got)).NotTo(Equal("0"))
	}).Should(Succeed())
}

// ReplaceACLRules rewrites the rules of a NetworkACL the fixture
// already created and waits for the controller to observe the change.
func (f *policyFixture) ReplaceACLRules(name, rulesYAML string) {
	f.applyACL(name, rulesYAML)
	waitObservedGeneration("networkacl", f.ACLName(name))
}

func (f *policyFixture) applyACL(name, rulesYAML string) {
	full := f.ACLName(name)
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: NetworkACL
metadata:
  name: %s
spec:
  vpc: %s%s
`, full, f.vpcName, rulesYAML)
	Expect(applyManifest(manifest)).To(Succeed())
}

// AttachACL patches an existing Subnet to reference the named ACL.
// `name` is the short, fixture-local label.
func (f *policyFixture) AttachACL(subnet, name string) {
	full := f.ACLName(name)
	patch := fmt.Sprintf(`{"spec":{"networkACL":%q}}`, full)
	Expect(run(repoRoot, "kubectl", "patch", "subnet", subnet, "--type=merge", "-p", patch)).To(Succeed())

	// Wait until status mirrors the attachment so the daemon has
	// caught up.
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot, `{.status.networkACL.aclID}`, "get", "subnet", subnet)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).NotTo(BeEmpty())
		g.Expect(strings.TrimSpace(got)).NotTo(Equal("0"))
	}).Should(Succeed())
}

// DetachACL clears spec.networkACL on a Subnet, returning the Subnet
// to default-allow.
func (f *policyFixture) DetachACL(subnet string) {
	patch := `{"spec":{"networkACL":""}}`
	Expect(run(repoRoot, "kubectl", "patch", "subnet", subnet, "--type=merge", "-p", patch)).To(Succeed())
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot, `{.status.networkACL}`, "get", "subnet", subnet)
		g.Expect(err).NotTo(HaveOccurred())
		// status.networkACL is omitempty; once cleared the JSONPath
		// extraction returns an empty string.
		g.Expect(strings.TrimSpace(got)).To(BeEmpty())
	}).Should(Succeed())
}

// CreatePod creates a server (nginx) or client (curl) Pod on the node
// the fixture holds for that role. `sgs` are short, fixture-local
// SecurityGroup labels; CreatePod expands them via SGName.
func (f *policyFixture) CreatePod(name, subnet string, server bool, sgs []string) {
	node := f.clientNode
	if server {
		node = f.serverNode
	}
	Expect(applyManifest(podManifestWithSG(f.namespace, name, node, subnet, server, f.SGNames(sgs)))).To(Succeed())
}

// CreatePodWithContainers creates a Pod whose spec.containers block is
// `containers`, pinned to `node`. Specs that need something other than
// the nginx / curl pair use this.
func (f *policyFixture) CreatePodWithContainers(name, subnet, node, containers string, sgs []string) {
	Expect(applyManifest(policyPodManifest(f.namespace, name, node, subnet, f.SGNames(sgs), containers))).To(Succeed())
}

func (f *policyFixture) Cleanup() {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", f.namespace, "--ignore-not-found=true", "--timeout=60s")
	// Detach Subnets from the ACLs first so the webhook does not
	// reject the ACL deletion. Best-effort: the namespace is already
	// gone, so attached pods are not a concern.
	if len(f.createdACLs) > 0 {
		for _, subnet := range []string{f.serverSubnet, f.clientSubnet} {
			runBestEffort(repoRoot, "kubectl", "patch", "subnet", subnet, "--type=merge",
				"-p", `{"spec":{"networkACL":""}}`)
		}
	}
	for _, acl := range f.createdACLs {
		runBestEffort(repoRoot, "kubectl", "delete", "networkacl", acl, "--ignore-not-found=true")
	}
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

// waitObservedGeneration waits until the controller has reconciled the
// spec revision currently stored in the API server.
func waitObservedGeneration(resource, name string) {
	Eventually(func(g Gomega) {
		generation, err := kubectlJSONPath(repoRoot, `{.metadata.generation}`, "get", resource, name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(generation)).NotTo(BeEmpty())

		observed, err := kubectlJSONPath(repoRoot, `{.status.observedGeneration}`, "get", resource, name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(observed)).To(Equal(strings.TrimSpace(generation)))
	}).Should(Succeed())
}

// waitPolicyEntryCounts waits until the controller publishes the data
// plane cost of each direction of a NetworkACL or SecurityGroup.
//
// This is the status half of the capacity contract. The webhook budgets
// a spec against these numbers, so a spec that knows how many entries
// it means to use can check that the controller agrees before drawing
// any conclusion from the traffic it sees.
func waitPolicyEntryCounts(resource, name string, ingress, egress int) {
	want := entryCountText(ingress) + "/" + entryCountText(egress)
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot,
			`{.status.ingressEntryCount}/{.status.egressEntryCount}`, "get", resource, name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).To(Equal(want))
	}).Should(Succeed())
}

// entryCountText renders an expected entry count the way the status
// field reads back through jsonpath. Both counts are omitempty, so a
// direction that costs nothing leaves the field out and extracts as an
// empty string rather than "0".
func entryCountText(entries int) string {
	if entries == 0 {
		return ""
	}
	return strconv.Itoa(entries)
}

// --- Pod manifests ---------------------------------------------------

const (
	busyboxImage  = "busybox:1.37"
	netshootImage = "nicolaka/netshoot:v0.16"
)

const curlClientContainer = `    - name: client
      image: curlimages/curl:8.12.1
      command: ["sleep", "3600"]`

const nginxServerContainer = `    - name: server
      image: nginx:1.27
      ports:
        - containerPort: 80`

// The policy suites give one destination Pod a listener per outcome
// they need to tell apart, and let the rules decide which of them
// answer. Two ports cover "admitted" and "denied"; the third exists for
// the specs that have to separate an ingress verdict from an egress one
// in the same run.
const (
	// policyOpenPort is the destination port the placement scenarios
	// admit.
	policyOpenPort = 80
	// policyBlockedPort is the one those scenarios never name.
	policyBlockedPort = 8080
	// policyAltBody is what the policyBlockedPort listener answers
	// with, so a spec can tell it apart from nginx.
	policyAltBody = "policy-alt-port"

	policyThirdPort = 8081
	policyThirdBody = "policy-third-port"
)

// altPortServerContainer builds a busybox httpd listener answering
// `body` on `port`. Each container has its own filesystem, so several
// of them can serve their own document root from the same path.
func altPortServerContainer(name string, port int, body string) string {
	return fmt.Sprintf(`
    - name: %s
      image: %s
      command:
        - /bin/sh
        - -c
        - |
          mkdir -p /www
          echo %s > /www/index.html
          exec httpd -f -p %d -h /www
      ports:
        - containerPort: %d`, name, busyboxImage, body, port, port)
}

// dualPortServerContainers serves nginx on policyOpenPort and a static
// page on policyBlockedPort, so one destination Pod carries both the
// admitted and the denied case.
func dualPortServerContainers() string {
	return nginxServerContainer + altPortServerContainer("server-alt", policyBlockedPort, policyAltBody)
}

// triplePortServerContainers adds policyThirdPort to the pair above.
// A spec that has to see ingress and egress decide differently needs
// three outcomes at once: one port both directions admit, one only
// egress admits, and one only ingress admits.
func triplePortServerContainers() string {
	return dualPortServerContainers() + altPortServerContainer("server-third", policyThirdPort, policyThirdBody)
}

func podManifestWithSG(namespace, name, nodeName, subnet string, server bool, sgs []string) string {
	container := curlClientContainer
	if server {
		container = nginxServerContainer
	}
	return policyPodManifest(namespace, name, nodeName, subnet, sgs, container)
}

// policyPodManifest builds a Pod with the Juneau subnet and
// security-group annotations. `containers` is the whole
// spec.containers block: four-space indented, no trailing newline.
func policyPodManifest(namespace, name, nodeName, subnet string, sgs []string, containers string) string {
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
`, namespace, name, name, annBlock, nodeName, containers)
}

// --- packet probes ---------------------------------------------------

// The HTTP probes above cover everything curl can say. Three inputs of
// the policy stage need a sender that writes the packet itself: an IP
// protocol that carries no ports, an IPv4 datagram split into
// fragments, and a frame that is not IPv4 at all.
//
// Every probe pairs a sink container that records what arrived with a
// source container the spec execs into.

const (
	probeSinkContainerName   = "server"
	probeSourceContainerName = "client"

	// probeSinkLogPath is where a sink writes what it saw. One path
	// for all of them: a Pod never carries two sinks.
	probeSinkLogPath = "/tmp/probe.log"

	// probePackets is how many packets one probe sends. None of these
	// protocols has a handshake or a retransmission, so a single
	// packet cannot tell a policy drop from a packet lost on the way.
	probePackets = 3

	// probeQuietWindow is how long a "nothing arrives" assertion keeps
	// reading the sink after the packets have been sent.
	probeQuietWindow       = 5 * time.Second
	probeQuietPollInterval = time.Second

	// probeSinkReadyMarker is what a sink prints once it can observe
	// traffic. tcpdump prints it on its own; the UDP sink is written to
	// print the same words.
	probeSinkReadyMarker = "listening on"
)

// captureSinkContainer records every packet matching the pcap filter
// into a file the specs read back.
//
// tcpdump runs with -p because the "any" device cannot go promiscuous,
// so the container needs nothing beyond NET_RAW.
func captureSinkContainer(filter string) string {
	return fmt.Sprintf(`    - name: %s
      image: %s
      securityContext:
        capabilities:
          add: ["NET_RAW"]
      command: ["sh", "-c", "tcpdump -n -l -p -i any '%s' > %s 2>&1"]`,
		probeSinkContainerName, netshootImage, filter, probeSinkLogPath)
}

// probeSourceContainer idles until a spec asks it to send. The senders
// below open raw sockets, which is what NET_RAW is here for.
func probeSourceContainer() string {
	return fmt.Sprintf(`    - name: %s
      image: %s
      securityContext:
        capabilities:
          add: ["NET_RAW"]
      command: ["sleep", "3600"]`, probeSourceContainerName, netshootImage)
}

// probeSinkLog reads back everything the sink has recorded so far.
func probeSinkLog(namespace string, serverPod string) (string, error) {
	return kubectlOutput(repoRoot, "exec", "-n", namespace, serverPod, "-c", probeSinkContainerName,
		"--", "cat", probeSinkLogPath)
}

// waitProbeSinkReady blocks until the sink can observe traffic. Without
// it a "nothing arrives" assertion could pass because nothing was
// watching yet.
func waitProbeSinkReady(namespace string, serverPod string) {
	Eventually(func(g Gomega) {
		log, err := probeSinkLog(namespace, serverPod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(log).To(ContainSubstring(probeSinkReadyMarker))
	}).Should(Succeed())
}

// captureFrom is what tcpdump prints for an IPv4 packet sent by srcIP.
// Matching the whole source field keeps one Pod address from answering
// for another whose address merely starts the same way.
func captureFrom(srcIP string) string {
	return fmt.Sprintf("IP %s > ", srcIP)
}

// captureFromV6 is captureFrom for an IPv6 packet.
func captureFromV6(srcIP string) string {
	return fmt.Sprintf("IP6 %s > ", srcIP)
}

// runProbeSender runs one of the Python senders below inside the source
// container and returns its output so a caller can report what went
// wrong.
func runProbeSender(namespace string, clientPod string, script string, args ...string) (string, error) {
	full := append([]string{
		"exec", "-n", namespace, clientPod, "-c", probeSourceContainerName, "--",
		"python3", "-c", script,
	}, args...)
	return kubectlOutput(repoRoot, full...)
}

// --- GRE probes ------------------------------------------------------

// Both policy layers are supposed to evaluate every IP protocol, not
// only the three that used to reach the evaluator. GRE is what the
// specs probe that with: the kernel routes it like any other IP
// packet, it carries no ports, and nothing else in these fixtures
// sends it.
const (
	// greProtocolNumber is the IANA number for GRE. Specs write it into
	// rules both as this number and as the "gre" keyword.
	greProtocolNumber = 47
)

// greSinkContainer captures every GRE packet that reaches the Pod.
func greSinkContainer() string {
	return captureSinkContainer(fmt.Sprintf("ip proto %d", greProtocolNumber))
}

// greSendScript writes bare GRE headers to the address in its first
// argument, as many as its second argument asks for.
//
// A raw socket is the only way to put an arbitrary IP protocol on the
// wire from these containers: netshoot v0.16 carries no packet
// generator that reaches past TCP, UDP and ICMP.
const greSendScript = `import socket
import sys

target = sys.argv[1]
count = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE)
header = b"\x00\x00\x08\x00"
for _ in range(count):
    sock.sendto(header, (target, 0))
`

// sendPodGRE sends `count` GRE packets from clientPod to target and
// returns the sender's output so a caller can report what went wrong.
func sendPodGRE(namespace string, clientPod string, target string, count int) (string, error) {
	return runProbeSender(namespace, clientPod, greSendScript, target, strconv.Itoa(count))
}

// assertPodGREConnectivity requires the GRE packets clientPod sends to
// show up in serverPod's capture.
func assertPodGREConnectivity(namespace string, clientPod string, serverPod string) {
	clientIP := mustPodIP(namespace, clientPod)
	serverIP := mustPodIP(namespace, serverPod)
	waitProbeSinkReady(namespace, serverPod)

	Eventually(func(g Gomega) {
		out, err := sendPodGRE(namespace, clientPod, serverIP, probePackets)
		g.Expect(err).NotTo(HaveOccurred(), "sending GRE failed: %s", out)

		capture, err := probeSinkLog(namespace, serverPod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(capture).To(ContainSubstring(captureFrom(clientIP)), "GRE capture: %s", capture)
	}).Should(Succeed())
}

// assertNoPodGREConnectivity sends GRE and then requires serverPod's
// capture to stay empty. Unlike the positive assertion it cannot retry
// the send: a packet that arrives contradicts the claim, so watching
// the capture for a while is the whole check.
func assertNoPodGREConnectivity(namespace string, clientPod string, serverPod string) {
	clientIP := mustPodIP(namespace, clientPod)
	serverIP := mustPodIP(namespace, serverPod)
	waitProbeSinkReady(namespace, serverPod)

	out, err := sendPodGRE(namespace, clientPod, serverIP, probePackets)
	Expect(err).NotTo(HaveOccurred(), "sending GRE failed: %s", out)

	Consistently(func(g Gomega) {
		capture, err := probeSinkLog(namespace, serverPod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(capture).NotTo(ContainSubstring(captureFrom(clientIP)), "GRE capture: %s", capture)
	}, probeQuietWindow, probeQuietPollInterval).Should(Succeed())
}

// --- fragment probes -------------------------------------------------

// Only the first fragment of an IPv4 datagram carries the L4 header, so
// the policy stage cannot read the ports of any fragment after it. It
// recovers them from ipv4_frag_map instead. These probes are how the
// specs see whether that worked.

const (
	// fragUDPPort is where the UDP sink listens. Nothing else in these
	// fixtures binds it.
	fragUDPPort = 5001

	// fragDatagramSize is past the 1500-byte MTU a Pod NIC gets, so the
	// kernel always splits this datagram. Three fragments leave the
	// Pod and only the first one carries the UDP header.
	fragDatagramSize = 4000

	// fragWarmupSize fits in one packet. A spec sends it first when it
	// wants the flow established before the fragments start.
	fragWarmupSize = 32

	// fragEchoPayload is an ICMP payload past the same MTU.
	fragEchoPayload = 5000

	// laterFragmentFilter matches IPv4 packets that start past the
	// beginning of their datagram, which is exactly the set the policy
	// stage cannot read ports from.
	laterFragmentFilter = "(ip[6:2] & 0x1fff) != 0"
)

// udpSinkContainer receives UDP datagrams on `port` and records the
// size of every one the kernel handed it.
//
// The size is the point. A capture would show the fragments arriving,
// but only a socket read proves the kernel put the datagram back
// together: tcpdump cannot tell "every fragment arrived" from "the
// first one did".
func udpSinkContainer(port int) string {
	return fmt.Sprintf(`    - name: %s
      image: %s
      command:
        - /bin/sh
        - -c
        - |
          cat > /tmp/udp_sink.py <<'PY'
          import socket
          import sys

          port = int(sys.argv[1])
          sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          sock.bind(("0.0.0.0", port))
          print("listening on %%d" %% port, flush=True)
          while True:
              payload, peer = sock.recvfrom(65535)
              print("received %%d bytes from %%s" %% (len(payload), peer[0]), flush=True)
          PY
          exec python3 -u /tmp/udp_sink.py %d > %s 2>&1`,
		probeSinkContainerName, netshootImage, port, probeSinkLogPath)
}

// udpSendScript sends one datagram per size it is given, all from one
// socket so every one of them carries the same 5-tuple.
//
// The pause between them is what lets a spec establish a flow before
// the fragments start: the policy conntrack entry is written while the
// first datagram crosses the hooks, and veth hands the packet to the
// data plane asynchronously.
const udpSendScript = `import socket
import sys
import time

target = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((target, port))
for index, size in enumerate(sys.argv[3:]):
    if index > 0:
        time.sleep(0.5)
    sock.send(b"j" * int(size))
    print("sent %s bytes" % size)
`

// sendPodUDP sends one datagram per size from clientPod.
func sendPodUDP(namespace string, clientPod string, target string, port int, sizes []int) (string, error) {
	args := []string{target, strconv.Itoa(port)}
	for _, size := range sizes {
		args = append(args, strconv.Itoa(size))
	}
	return runProbeSender(namespace, clientPod, udpSendScript, args...)
}

// assertPodUDPDatagrams requires serverPod's sink to report every
// datagram at the size it was sent. The size is what separates a
// reassembled datagram from a first fragment that arrived alone: the
// rest of an incomplete datagram never reaches a socket read at all.
func assertPodUDPDatagrams(namespace string, clientPod string, serverPod string, sizes ...int) {
	clientIP := mustPodIP(namespace, clientPod)
	serverIP := mustPodIP(namespace, serverPod)
	waitProbeSinkReady(namespace, serverPod)

	Eventually(func(g Gomega) {
		out, err := sendPodUDP(namespace, clientPod, serverIP, fragUDPPort, sizes)
		g.Expect(err).NotTo(HaveOccurred(), "sending UDP failed: %s", out)

		log, err := probeSinkLog(namespace, serverPod)
		g.Expect(err).NotTo(HaveOccurred())
		for _, size := range sizes {
			g.Expect(log).To(ContainSubstring(udpSinkReceived(size, clientIP)), "UDP sink log: %s", log)
		}
	}).Should(Succeed())
}

// udpSinkReceived is the line udpSinkContainer prints for one datagram.
// The trailing newline is part of the match so a Pod address cannot
// answer for another whose address merely starts the same way.
func udpSinkReceived(size int, srcIP string) string {
	return fmt.Sprintf("received %d bytes from %s\n", size, srcIP)
}

// orphanFragmentScript sends IPv4 fragments whose first fragment never
// existed.
//
// This is the one case ipv4_frag_map cannot answer, and it is the only
// way a spec can hold the fail-closed path still: a datagram sent the
// ordinary way always puts its first fragment on the wire first, and
// the ports are then recovered whatever the policy says.
const orphanFragmentScript = `import socket
import struct
import sys

source = sys.argv[1]
target = sys.argv[2]
count = int(sys.argv[3])

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
payload = b"j" * 64
for index in range(count):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                         0x5300 + index, 185, 64, socket.IPPROTO_UDP, 0,
                         socket.inet_aton(source), socket.inet_aton(target))
    sock.sendto(header + payload, (target, 0))
print("sent %d orphan fragments" % count)
`

// sendPodOrphanFragments sends `count` fragments from clientPod that no
// first fragment ever preceded.
func sendPodOrphanFragments(namespace string, clientPod string, source string, target string, count int) (string, error) {
	return runProbeSender(namespace, clientPod, orphanFragmentScript, source, target, strconv.Itoa(count))
}

// assertPodOrphanFragment requires the fragments clientPod sends to
// reach serverPod.
func assertPodOrphanFragment(namespace string, clientPod string, serverPod string) {
	clientIP := mustPodIP(namespace, clientPod)
	serverIP := mustPodIP(namespace, serverPod)
	waitProbeSinkReady(namespace, serverPod)

	Eventually(func(g Gomega) {
		out, err := sendPodOrphanFragments(namespace, clientPod, clientIP, serverIP, probePackets)
		g.Expect(err).NotTo(HaveOccurred(), "sending fragments failed: %s", out)

		capture, err := probeSinkLog(namespace, serverPod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(capture).To(ContainSubstring(captureFrom(clientIP)), "fragment capture: %s", capture)
	}).Should(Succeed())
}

// assertNoPodOrphanFragment sends the same fragments and requires
// serverPod's capture to stay empty.
func assertNoPodOrphanFragment(namespace string, clientPod string, serverPod string) {
	clientIP := mustPodIP(namespace, clientPod)
	serverIP := mustPodIP(namespace, serverPod)
	waitProbeSinkReady(namespace, serverPod)

	out, err := sendPodOrphanFragments(namespace, clientPod, clientIP, serverIP, probePackets)
	Expect(err).NotTo(HaveOccurred(), "sending fragments failed: %s", out)

	Consistently(func(g Gomega) {
		capture, err := probeSinkLog(namespace, serverPod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(capture).NotTo(ContainSubstring(captureFrom(clientIP)), "fragment capture: %s", capture)
	}, probeQuietWindow, probeQuietPollInterval).Should(Succeed())
}

// --- non-IPv4 probes -------------------------------------------------

// A frame that is not IPv4 carries no address the policy stage could
// look a rule up by, so a policed Pod is not allowed to send one. IPv6
// is what the specs probe that with: juneau puts no IPv6 address on a
// Pod, so the frame has to be built by hand.

const (
	// ipv6ProbeSource and ipv6ProbeDest come from the documentation
	// prefix (RFC 3849). Nothing routes them; they only have to be
	// recognisable in a capture.
	ipv6ProbeSource = "2001:db8::1"
	ipv6ProbeDest   = "2001:db8::2"
)

// ipv6SinkContainer captures every IPv6 packet that reaches the Pod. A
// Pod emits link-local IPv6 of its own, so the specs match on
// ipv6ProbeSource rather than on the capture being empty.
func ipv6SinkContainer() string {
	return captureSinkContainer("ip6")
}

// ipv6SendScript builds an Ethernet frame carrying an IPv6 header and
// writes it straight to the NIC.
//
// AF_PACKET is what makes this possible without an address: the frame
// never goes near the IPv6 stack, which has nothing configured. The
// next header is 59 (no next header), so the packet carries nothing
// that could be mistaken for a port, and the six payload bytes bring
// the frame up to the 60-byte Ethernet minimum.
const ipv6SendScript = `import socket
import struct
import sys

iface = sys.argv[1]
dst_mac = sys.argv[2]
source = sys.argv[3]
dest = sys.argv[4]
count = int(sys.argv[5])

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind((iface, 0))
src_mac = sock.getsockname()[4]
dst = bytes(int(part, 16) for part in dst_mac.split(":"))

payload = b"juneau"
header = struct.pack("!IHBB", 6 << 28, len(payload), 59, 64)
header += socket.inet_pton(socket.AF_INET6, source)
header += socket.inet_pton(socket.AF_INET6, dest)
frame = dst + src_mac + struct.pack("!H", 0x86DD) + header + payload
for _ in range(count):
    sock.send(frame)
print("sent %d frames" % count)
`

// podMAC reads a Pod's own NIC address. The IPv6 frame is switched on
// the destination MAC, so the sender needs the receiver's.
func podMAC(namespace string, podName string, container string) string {
	out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "-c", container,
		"--", "cat", "/sys/class/net/"+podIfaceName+"/address")
	Expect(err).NotTo(HaveOccurred(), "reading the Pod MAC failed: %s", out)
	mac := strings.TrimSpace(out)
	Expect(mac).NotTo(BeEmpty())
	return mac
}

// sendPodIPv6Frame sends `count` IPv6 frames from clientPod to dstMAC.
func sendPodIPv6Frame(namespace string, clientPod string, dstMAC string, count int) (string, error) {
	return runProbeSender(namespace, clientPod, ipv6SendScript,
		podIfaceName, dstMAC, ipv6ProbeSource, ipv6ProbeDest, strconv.Itoa(count))
}

// assertPodIPv6Frame requires the frames clientPod sends to reach
// serverPod.
func assertPodIPv6Frame(namespace string, clientPod string, serverPod string) {
	waitProbeSinkReady(namespace, serverPod)
	serverMAC := podMAC(namespace, serverPod, probeSinkContainerName)

	Eventually(func(g Gomega) {
		out, err := sendPodIPv6Frame(namespace, clientPod, serverMAC, probePackets)
		g.Expect(err).NotTo(HaveOccurred(), "sending the IPv6 frame failed: %s", out)

		capture, err := probeSinkLog(namespace, serverPod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(capture).To(ContainSubstring(captureFromV6(ipv6ProbeSource)), "IPv6 capture: %s", capture)
	}).Should(Succeed())
}

// assertNoPodIPv6Frame sends the same frames and requires serverPod's
// capture never to name ipv6ProbeSource.
func assertNoPodIPv6Frame(namespace string, clientPod string, serverPod string) {
	waitProbeSinkReady(namespace, serverPod)
	serverMAC := podMAC(namespace, serverPod, probeSinkContainerName)

	out, err := sendPodIPv6Frame(namespace, clientPod, serverMAC, probePackets)
	Expect(err).NotTo(HaveOccurred(), "sending the IPv6 frame failed: %s", out)

	Consistently(func(g Gomega) {
		capture, err := probeSinkLog(namespace, serverPod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(capture).NotTo(ContainSubstring(captureFromV6(ipv6ProbeSource)), "IPv6 capture: %s", capture)
	}, probeQuietWindow, probeQuietPollInterval).Should(Succeed())
}
