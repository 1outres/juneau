package e2e

import (
	"fmt"
	"strconv"
	"strings"

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

const busyboxImage = "busybox:1.37"

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
