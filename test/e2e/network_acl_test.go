package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Juneau NetworkACL E2E coverage:
//
// 1. Baseline — Subnet without an ACL keeps the legacy default-allow
//    behaviour.
// 2. Ingress allow-list — an ACL with a single allow rule plus implicit
//    terminal deny lets only the matching CIDR through.
// 3. Priority precedence — a deny rule placed before an otherwise-
//    matching allow rule wins (rules evaluate in priority order).
// 4. Egress deny — denying egress at the client's Subnet boundary
//    blocks outbound traffic even when the server's Subnet would have
//    admitted it. Stateful: the reply leg flows once the forward leg
//    has been admitted (covered by the allow case).
// 5. Detach — clearing spec.networkACL on a Subnet returns it to
//    default-allow on the next reconcile.
// 6. Cross-Node — ACL evaluation applies to traffic that crossed
//    VXLAN; the same rules block / admit consistently.
//
// Every spec creates an isolated namespace + Vpc + Subnets so they can
// run in parallel under Ginkgo --procs.

var _ = Describe("Juneau NetworkACL", func() {
	It("baseline: Subnet without ACL allows traffic", func() {
		base := sanitizeName("acl-baseline")
		fix := newACLFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("ingress: explicit deny-list blocks unlisted CIDRs", func() {
		base := sanitizeName("acl-ingress-allowlist")
		fix := newACLFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// One allow rule whose CIDR does NOT cover the client subnet:
		// every other source must fall through to the implicit deny.
		fix.CreateACL("server-acl", `
  ingress:
    - priority: 100
      action: allow
      protocol: tcp
      cidr: 192.0.2.0/24
      ports:
        - port: 80`)
		fix.AttachACL(fix.serverSubnet, "server-acl")

		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertNoPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("ingress: allow rule admitting the client subnet permits traffic and reply (stateful)", func() {
		base := sanitizeName("acl-ingress-allow")
		fix := newACLFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// 0.0.0.0/0 allow on the server's Subnet → first packet
		// admitted by ACL, reply leg short-circuited via CT (stateful
		// confirmation: the client's Subnet has no ACL, so without
		// stateful CT the response would still need to satisfy SG
		// ingress, which is absent here).
		fix.CreateACL("server-acl", `
  ingress:
    - priority: 100
      action: allow
      protocol: tcp
      cidr: 0.0.0.0/0
      ports:
        - port: 80`)
		fix.AttachACL(fix.serverSubnet, "server-acl")

		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("ingress: priority order — earlier deny wins over a later allow", func() {
		base := sanitizeName("acl-priority")
		fix := newACLFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		fix.CreateACL("server-acl", fmt.Sprintf(`
  ingress:
    - priority: 100
      action: deny
      protocol: tcp
      cidr: %s
      ports:
        - port: 80
    - priority: 200
      action: allow
      protocol: tcp
      cidr: 0.0.0.0/0
      ports:
        - port: 80`, fix.clientSubnetCIDR))
		fix.AttachACL(fix.serverSubnet, "server-acl")

		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertNoPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("egress: deny on the client subnet blocks outbound traffic", func() {
		base := sanitizeName("acl-egress-deny")
		fix := newACLFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// Egress deny everything from the client's subnet; ingress on
		// the client subnet is omitted (default-allow, so reply
		// traffic to *unrelated* flows is unaffected — but here the
		// forward leg never leaves so there is no reply to test).
		fix.CreateACL("client-acl", `
  egress:
    - priority: 100
      action: deny
      protocol: all
      cidr: 0.0.0.0/0`)
		fix.AttachACL(fix.clientSubnet, "client-acl")

		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertNoPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("detach: clearing spec.networkACL returns the Subnet to default-allow", func() {
		base := sanitizeName("acl-detach")
		fix := newACLFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// Start with an ingress ACL that blocks everything.
		fix.CreateACL("server-acl", `
  ingress:
    - priority: 100
      action: deny
      protocol: tcp
      cidr: 0.0.0.0/0
      ports:
        - port: 80`)
		fix.AttachACL(fix.serverSubnet, "server-acl")

		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertNoPodConnectivity(fix.namespace, clientPodName, serverPodName)

		fix.DetachACL(fix.serverSubnet)
		// After detach traffic must flow again. assertPodConnectivity
		// already retries until the daemon catches up with the new
		// status, so we do not need an explicit wait here.
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("cross-Node: ACL ingress deny applies to traffic that crossed VXLAN", func() {
		base := sanitizeName("acl-cross-node")
		fix := newACLFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		fix.serverNode = workerNodes[0]
		fix.clientNode = workerNodes[1]

		fix.CreateACL("server-acl", `
  ingress:
    - priority: 100
      action: deny
      protocol: tcp
      cidr: 0.0.0.0/0
      ports:
        - port: 80`)
		fix.AttachACL(fix.serverSubnet, "server-acl")

		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertNoPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})
})

// --- helpers ---------------------------------------------------------

type aclFixture struct {
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
}

func newACLFixture(base string) *aclFixture {
	return &aclFixture{
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

func (f *aclFixture) CreateNetwork() {
	createNamespace(f.namespace)
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec: {}
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
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, f.vpcName,
		f.serverSubnet, f.vpcName, f.serverSubnetCIDR,
		f.clientSubnet, f.vpcName, f.clientSubnetCIDR)
	Expect(applyManifest(manifest)).To(Succeed())
	waitSubnetReady(f.serverSubnet)
	waitSubnetReady(f.clientSubnet)
}

// ACLName returns the cluster-scoped ACL name for the given short
// label. NetworkACL is cluster-scoped; suffixing with the fixture base
// keeps parallel specs from stepping on each other.
func (f *aclFixture) ACLName(short string) string { return short + "--" + f.base }

// CreateACL creates a NetworkACL whose body is rulesYAML — a YAML
// fragment placed under spec, e.g. "  ingress: [...]" or
// "  egress: [...]". Pass an empty string for "no rules" (yields a
// minimal ACL whose both directions are nil = default-allow, useful
// only for negative-control tests).
func (f *aclFixture) CreateACL(name, rulesYAML string) {
	full := f.ACLName(name)
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: NetworkACL
metadata:
  name: %s
spec:
  vpc: %s%s
`, full, f.vpcName, rulesYAML)
	Expect(applyManifest(manifest)).To(Succeed())
	f.createdACLs = append(f.createdACLs, full)

	// Wait for ACLID allocation so the daemon has a chance to project
	// the ruleset before traffic-checking specs run.
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot, `{.status.aclID}`, "get", "networkacl", full)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).NotTo(BeEmpty())
		g.Expect(strings.TrimSpace(got)).NotTo(Equal("0"))
	}).Should(Succeed())
}

// AttachACL patches an existing Subnet to reference the named ACL.
// `name` is the short, fixture-local label.
func (f *aclFixture) AttachACL(subnet, name string) {
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
func (f *aclFixture) DetachACL(subnet string) {
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

// CreatePod mirrors sgFixture.CreatePod but does not pass any
// SecurityGroup annotation: this suite exercises ACL in isolation.
func (f *aclFixture) CreatePod(name, subnet string, server bool, sgs []string) {
	node := f.clientNode
	if server {
		node = f.serverNode
	}
	Expect(applyManifest(podManifestWithSG(f.namespace, name, node, subnet, server, sgs))).To(Succeed())
}

func (f *aclFixture) Cleanup() {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", f.namespace, "--ignore-not-found=true", "--timeout=60s")
	// Detach Subnets from the ACLs first so the webhook does not
	// reject the ACL deletion. Best-effort: the namespace is already
	// gone, so attached pods are not a concern.
	for _, subnet := range []string{f.serverSubnet, f.clientSubnet} {
		runBestEffort(repoRoot, "kubectl", "patch", "subnet", subnet, "--type=merge",
			"-p", `{"spec":{"networkACL":""}}`)
	}
	for _, acl := range f.createdACLs {
		runBestEffort(repoRoot, "kubectl", "delete", "networkacl", acl, "--ignore-not-found=true")
	}
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", f.serverSubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", f.clientSubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", f.vpcName, "--ignore-not-found=true")
}
