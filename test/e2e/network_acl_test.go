package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
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
// 7. Enforcing sender — the destination ingress deny holds even when
//    the client Subnet also carries an ACL. See policy_placement_test
//    for the whole matrix; this one pairs with case (2).
// 8. Both directions (issue #52) — one ACL that sets ingress AND
//    egress enforces both, including when one of them sits at its
//    entry budget.
// 9. Ports — one rule admits every port it lists, and nothing else.
//
// Every spec creates an isolated namespace + Vpc + Subnets so they can
// run in parallel under Ginkgo --procs.

var _ = Describe("Juneau NetworkACL", func() {
	It("baseline: Subnet without ACL allows traffic", func() {
		base := sanitizeName("acl-baseline")
		fix := newPolicyFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("ingress: explicit deny-list blocks unlisted CIDRs", func() {
		base := sanitizeName("acl-ingress-allowlist")
		fix := newPolicyFixture(base)
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
		fix := newPolicyFixture(base)
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
		fix := newPolicyFixture(base)
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
		fix := newPolicyFixture(base)
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
		fix := newPolicyFixture(base)
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
		fix := newPolicyFixture(base)
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

	It("ingress: deny still applies when the client Subnet is enforcing too", func() {
		base := sanitizeName("acl-ingress-deny-enforcing-source")
		fix := newPolicyFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// Pair for "ingress: explicit deny-list blocks unlisted CIDRs".
		// That spec leaves the client Subnet without an ACL, so the
		// sender's egress hook enforces nothing and writes no policy
		// conntrack entry. Attaching an ACL to the client Subnet makes
		// it write one, which is the state issue #51 broke: on a single
		// Node the server's ingress hook used to find that entry and
		// skip its own rules.
		fix.CreateACL("client-acl", `
  egress:
    - priority: 100
      action: allow
      protocol: all
      cidr: 0.0.0.0/0`)
		fix.CreateACL("server-acl", `
  ingress:
    - priority: 100
      action: allow
      protocol: tcp
      cidr: 192.0.2.0/24
      ports:
        - port: 80`)
		fix.AttachACL(fix.clientSubnet, "client-acl")
		fix.AttachACL(fix.serverSubnet, "server-acl")

		fix.CreatePod(serverPodName, fix.serverSubnet, true, nil)
		fix.CreatePod(clientPodName, fix.clientSubnet, false, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)
		assertNoPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	It("ports: one rule admits every port it lists", func() {
		base := sanitizeName("acl-rule-ports")
		fix := newPolicyFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// One rule, two ports, and a third port it leaves out. The
		// listed ports are not adjacent, so a data plane that kept
		// only the first port of the rule, or that turned the list
		// into a range, gets a different answer than this spec wants.
		fix.CreateACL("server-acl", fmt.Sprintf(`
  ingress:
    - priority: 100
      action: allow
      protocol: tcp
      cidr: 0.0.0.0/0
      ports:
        - port: %d
        - port: %d`, policyOpenPort, policyThirdPort))
		fix.AttachACL(fix.serverSubnet, "server-acl")

		fix.CreatePodWithContainers(serverPodName, fix.serverSubnet, fix.serverNode, triplePortServerContainers(), nil)
		fix.CreatePodWithContainers(clientPodName, fix.clientSubnet, fix.clientNode, curlClientContainer, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)

		By("admitting the first port of the rule")
		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
		By("admitting the second port of the rule")
		assertPodPortConnectivity(fix.namespace, clientPodName, serverPodName, policyThirdPort, policyThirdBody)
		By("dropping the port the rule leaves out")
		assertNoPodPortConnectivity(fix.namespace, clientPodName, serverPodName, policyBlockedPort)
	})

	It("directions: one ACL enforces its ingress and its egress rules", func() {
		base := sanitizeName("acl-both-directions")
		fix := newPolicyFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		runACLBothDirections(fix, 0)
	})

	It("directions: a full ingress budget still leaves egress installed", func() {
		base := sanitizeName("acl-full-ingress-budget")
		fix := newPolicyFixture(base)
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// This is issue #52. Before each direction got its own window
		// in the rule array, ingress was written first and filled all
		// aclEntriesPerDirection slots, the egress entries fell off
		// the end, and the whole egress direction of the Subnet
		// blackholed while the ACL still reported Ready=True.
		runACLBothDirections(fix, aclEntriesPerDirection-aclBothDirectionsAllowEntries)
	})
})

const (
	// aclEntriesPerDirection mirrors
	// juneauv1alpha1.NetworkACLMaxEntriesPerDirection. The e2e module
	// does not depend on the controller module, so the number is
	// repeated here; the entry-count assertion below is what ties the
	// two together.
	aclEntriesPerDirection = 16

	// aclBothDirectionsAllowEntries is what each allow rule of
	// runACLBothDirections costs: one entry per port it lists.
	aclBothDirectionsAllowEntries = 2

	// The allow rule sits above every filler priority, so it is the
	// last thing a direction tries and the fillers cannot shadow it.
	aclFillerFirstPriority = 100
	aclAllowRulePriority   = 1000
)

// runACLBothDirections attaches one ACL, carrying rules in both
// directions, to both Subnets of the fixture, and checks that each
// direction decides on its own.
//
// The rules name three destination ports:
//
//	policyOpenPort    both directions admit it
//	policyBlockedPort only egress admits it, so ingress drops it
//	policyThirdPort   only ingress admits it, so egress drops it
//
// Every way a direction can go missing shows up in that trio. A
// direction installed empty drops policyOpenPort; a direction not
// installed at all admits the port it was supposed to drop.
//
// ingressFillers adds that many further ingress rules, one entry each,
// so a caller can park the ingress direction anywhere in its entry
// budget without changing what the spec observes.
//
// The ingress allow rule lists policyOpenPort last on purpose. Rules
// expand in port order and sort stably by priority, so with a full
// budget that port owns the very last slot of the window: reaching it
// is what says the scan walks its own window to the end.
func runACLBothDirections(fix *policyFixture, ingressFillers int) {
	fix.CreateACL("policy-acl", aclBothDirectionsRules(ingressFillers))
	fix.AttachACL(fix.serverSubnet, "policy-acl")
	fix.AttachACL(fix.clientSubnet, "policy-acl")

	aclName := fix.ACLName("policy-acl")
	By("publishing the entry cost the rules were written to have")
	waitPolicyEntryCounts("networkacl", aclName,
		ingressFillers+aclBothDirectionsAllowEntries, aclBothDirectionsAllowEntries)
	waitResourceReady("networkacl", aclName)

	fix.CreatePodWithContainers(serverPodName, fix.serverSubnet, fix.serverNode, triplePortServerContainers(), nil)
	fix.CreatePodWithContainers(clientPodName, fix.clientSubnet, fix.clientNode, curlClientContainer, nil)
	waitPodsReady(fix.namespace, serverPodName, clientPodName)

	By("admitting the port both directions name")
	assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
	By("dropping the port only egress names")
	assertNoPodPortConnectivity(fix.namespace, clientPodName, serverPodName, policyBlockedPort)
	By("dropping the port only ingress names")
	assertNoPodPortConnectivity(fix.namespace, clientPodName, serverPodName, policyThirdPort)
}

// aclBothDirectionsRules is the spec body runACLBothDirections applies.
func aclBothDirectionsRules(ingressFillers int) string {
	return fmt.Sprintf(`
  ingress:%s
    - priority: %d
      action: allow
      protocol: tcp
      cidr: 0.0.0.0/0
      ports:
        - port: %d
        - port: %d
  egress:
    - priority: %d
      action: allow
      protocol: tcp
      cidr: 0.0.0.0/0
      ports:
        - port: %d
        - port: %d`,
		aclFillerRules(aclFillerFirstPriority, ingressFillers),
		aclAllowRulePriority, policyThirdPort, policyOpenPort,
		aclAllowRulePriority, policyOpenPort, policyBlockedPort)
}

// aclFillerRules returns `count` deny rules starting at `firstPriority`
// that name single addresses out of the documentation range, so none of
// them can ever match a Pod. "all" with no ports costs exactly one data
// plane entry, which makes the rule count the entry count too: a spec
// uses them to park a direction at a chosen point in its budget.
func aclFillerRules(firstPriority, count int) string {
	rules := make([]string, 0, count)
	for i := 0; i < count; i++ {
		rules = append(rules, fmt.Sprintf(`
    - priority: %d
      action: deny
      protocol: all
      cidr: 192.0.2.%d/32`, firstPriority+i, i+1))
	}
	return strings.Join(rules, "")
}
