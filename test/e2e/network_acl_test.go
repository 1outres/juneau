package e2e

import (
	"fmt"

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
})
