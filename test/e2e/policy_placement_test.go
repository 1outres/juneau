package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
)

// Juneau policy placement E2E coverage (issue #51).
//
// The policy stage keeps a conntrack entry per enforcement point so an
// admission made at the sender's egress hook cannot stand in for one
// the destination's ingress hook never made. That distinction only
// shows up when the sender is itself enforcing and both Pods sit on the
// same Node: the sender's entry and the destination's lookup then land
// in the same map. Every spec here therefore attaches a policy layer to
// the sender as well, and runs the same rules on one Node and across
// two.
//
// The matrix walks three axes:
//
//   * layer      — NetworkACL only, SecurityGroup only, or both.
//   * placement  — both Pods on one Node, or one Node each.
//   * Subnet     — sender and destination in one Subnet, or in two.
//
// The destination Pod serves two ports. The policy admits
// policyOpenPort and never names policyBlockedPort, so a single Pod
// carries both the "admitted" and the "denied" case and the two only
// differ in what the rules say.

// policyLayer selects which policy layers a scenario attaches.
type policyLayer string

const (
	policyLayerACL  policyLayer = "acl"
	policyLayerSG   policyLayer = "sg"
	policyLayerBoth policyLayer = "acl-sg"
)

func (l policyLayer) usesACL() bool { return l == policyLayerACL || l == policyLayerBoth }
func (l policyLayer) usesSG() bool  { return l == policyLayerSG || l == policyLayerBoth }

// subnetRelation selects whether the sender shares the destination's
// Subnet.
type subnetRelation string

const (
	subnetsShared   subnetRelation = "same-subnet"
	subnetsDistinct subnetRelation = "diff-subnet"
)

type policyPlacementScenario struct {
	layer     policyLayer
	placement placementMode
	subnets   subnetRelation
}

func (s policyPlacementScenario) baseName(prefix string) string {
	return sanitizeName(fmt.Sprintf("%s-%s-%s-%s", prefix, s.layer, s.placement, s.subnets))
}

const (
	// policyOpenPort is the destination port every scenario admits.
	policyOpenPort = 80
	// policyBlockedPort is the one no rule ever names.
	policyBlockedPort = 8080
	// policyAltBody is what the second listener answers with, so the
	// baseline spec can tell it apart from nginx.
	policyAltBody = "policy-alt-port"
)

var _ = Describe("Juneau policy placement", func() {
	It("baseline: both destination ports answer while no policy is attached", func() {
		fix := newPolicyFixture(sanitizeName("policy-ports-baseline"))
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		fix.CreatePodWithContainers(serverPodName, fix.serverSubnet, fix.serverNode, dualPortServerContainers(), nil)
		fix.CreatePodWithContainers(clientPodName, fix.clientSubnet, fix.clientNode, curlClientContainer, nil)
		waitPodsReady(fix.namespace, serverPodName, clientPodName)

		assertPodConnectivity(fix.namespace, clientPodName, serverPodName)
		assertPodPortConnectivity(fix.namespace, clientPodName, serverPodName, policyBlockedPort, policyAltBody)
	})

	It("regression #51: a same-Node destination still evaluates its ingress SG", func() {
		fix := newPolicyFixture(sanitizeName("policy-issue-51"))
		DeferCleanup(fix.Cleanup)
		fix.applyPlacement(placementSameNode)
		fix.CreateNetwork()

		// The client's SG makes its egress hook write a policy
		// conntrack entry. The server's SG admits nobody the client
		// could be. On one Node those two facts used to cancel out.
		fix.CreateSG("client-sg", policySGEgressAllowAll)
		fix.CreateSG("server-sg", policySGIngressFromElsewhere(policyOpenPort))

		fix.CreatePod(serverPodName, fix.serverSubnet, true, []string{"server-sg"})
		fix.CreatePod(clientPodName, fix.clientSubnet, false, []string{"client-sg"})
		waitPodsReady(fix.namespace, serverPodName, clientPodName)

		assertNoPodConnectivity(fix.namespace, clientPodName, serverPodName)
	})

	DescribeTable("destination ingress rules decide the same way wherever the Pods sit",
		runPolicyIngressScenario,
		ingressEntry(policyLayerACL, placementSameNode, subnetsShared),
		ingressEntry(policyLayerACL, placementSameNode, subnetsDistinct),
		ingressEntry(policyLayerACL, placementDifferentNodes, subnetsShared),
		ingressEntry(policyLayerACL, placementDifferentNodes, subnetsDistinct),
		ingressEntry(policyLayerSG, placementSameNode, subnetsShared),
		ingressEntry(policyLayerSG, placementSameNode, subnetsDistinct),
		ingressEntry(policyLayerSG, placementDifferentNodes, subnetsShared),
		ingressEntry(policyLayerSG, placementDifferentNodes, subnetsDistinct),
		ingressEntry(policyLayerBoth, placementSameNode, subnetsShared),
		ingressEntry(policyLayerBoth, placementSameNode, subnetsDistinct),
		ingressEntry(policyLayerBoth, placementDifferentNodes, subnetsShared),
		ingressEntry(policyLayerBoth, placementDifferentNodes, subnetsDistinct),
	)

	DescribeTable("sender egress rules decide the same way wherever the Pods sit",
		runPolicyEgressScenario,
		egressEntry(policyLayerACL, placementSameNode),
		egressEntry(policyLayerACL, placementDifferentNodes),
		egressEntry(policyLayerSG, placementSameNode),
		egressEntry(policyLayerSG, placementDifferentNodes),
		egressEntry(policyLayerBoth, placementSameNode),
		egressEntry(policyLayerBoth, placementDifferentNodes),
	)
})

func ingressEntry(layer policyLayer, placement placementMode, subnets subnetRelation) TableEntry {
	return Entry(fmt.Sprintf("%s, %s, %s", layer, placement, subnets),
		policyPlacementScenario{layer: layer, placement: placement, subnets: subnets})
}

// egressEntry pins the sender to a Subnet of its own: an egress ACL on
// a shared Subnet would govern the destination as well, and the spec
// could no longer say which side dropped the packet.
func egressEntry(layer policyLayer, placement placementMode) TableEntry {
	return Entry(fmt.Sprintf("%s, %s", layer, placement),
		policyPlacementScenario{layer: layer, placement: placement, subnets: subnetsDistinct})
}

// runPolicyIngressScenario checks the two halves of an ingress ruleset
// at once: the port it names is reachable and answers, the port it does
// not name is dropped.
//
// The reply is the stateful half. Neither layer ever admits an
// ephemeral destination port back towards the sender, so the answer to
// the open port can only arrive through the conntrack entry the
// forward leg installed.
func runPolicyIngressScenario(s policyPlacementScenario) {
	fix := newPolicyFixture(s.baseName("pi"))
	DeferCleanup(fix.Cleanup)
	fix.applyPlacement(s.placement)
	fix.CreateNetwork()

	clientSubnet := fix.clientSubnet
	if s.subnets == subnetsShared {
		clientSubnet = fix.serverSubnet
	}

	var serverSGs, clientSGs []string
	if s.layer.usesSG() {
		fix.CreateSG("client-sg", policySGEgressAllowAll)
		fix.CreateSG("server-sg", policySGIngressPort(policyOpenPort))
		serverSGs = []string{"server-sg"}
		clientSGs = []string{"client-sg"}
	}
	if s.layer.usesACL() {
		// One ACL on both Subnets. Its egress half is what makes the
		// sender enforcing; its ingress half admits the open port and
		// nothing else, in either direction.
		fix.CreateACL("policy-acl", policyACLIngressPort(policyOpenPort))
		fix.AttachACL(fix.serverSubnet, "policy-acl")
		if clientSubnet != fix.serverSubnet {
			fix.AttachACL(clientSubnet, "policy-acl")
		}
	}

	fix.CreatePodWithContainers(serverPodName, fix.serverSubnet, fix.serverNode, dualPortServerContainers(), serverSGs)
	fix.CreatePodWithContainers(clientPodName, clientSubnet, fix.clientNode, curlClientContainer, clientSGs)
	waitPodsReady(fix.namespace, serverPodName, clientPodName)

	By("reaching the admitted port and getting the reply back")
	assertPodConnectivity(fix.namespace, clientPodName, serverPodName)

	By("being dropped on the port the destination never admits")
	assertNoPodPortConnectivity(fix.namespace, clientPodName, serverPodName, policyBlockedPort)
}

// runPolicyEgressScenario checks that a sender the rules do not let out
// stays in, whichever Node the destination is on. The destination
// admits the port, so the only thing that can drop the packet is the
// sender's own egress hook.
func runPolicyEgressScenario(s policyPlacementScenario) {
	fix := newPolicyFixture(s.baseName("pe"))
	DeferCleanup(fix.Cleanup)
	fix.applyPlacement(s.placement)
	fix.CreateNetwork()

	var serverSGs, clientSGs []string
	if s.layer.usesSG() {
		fix.CreateSG("server-sg", policySGIngressPort(policyOpenPort))
		fix.CreateSG("client-sg", policySGEgressToElsewhere)
		serverSGs = []string{"server-sg"}
		clientSGs = []string{"client-sg"}
	}
	if s.layer.usesACL() {
		fix.CreateACL("client-acl", policyACLEgressDeny)
		fix.AttachACL(fix.clientSubnet, "client-acl")
	}

	fix.CreatePod(serverPodName, fix.serverSubnet, true, serverSGs)
	fix.CreatePod(clientPodName, fix.clientSubnet, false, clientSGs)
	waitPodsReady(fix.namespace, serverPodName, clientPodName)

	assertNoPodConnectivity(fix.namespace, clientPodName, serverPodName)
}

// --- rule bodies -----------------------------------------------------

// policyElsewhereCIDR is a documentation-only prefix (RFC 5737) no Pod
// ever gets an address from. A rule that names it is a rule that
// matches nothing, which is how these specs write "has rules in this
// direction, admits nobody".
const policyElsewhereCIDR = "192.0.2.0/24"

// policyACLIngressPort admits `port` from anywhere and lets everything
// out. Attached to the sender's Subnet as well, the ingress half also
// denies the reply leg: a reply carries an ephemeral destination port,
// which no rule names.
func policyACLIngressPort(port int) string {
	return fmt.Sprintf(`
  ingress:
    - priority: 100
      action: allow
      protocol: tcp
      cidr: 0.0.0.0/0
      ports:
        - port: %d
  egress:
    - priority: 100
      action: allow
      protocol: all
      cidr: 0.0.0.0/0`, port)
}

// policyACLIngressDeny keeps egress open and stops admitting anything
// inbound.
const policyACLIngressDeny = `
  ingress:
    - priority: 100
      action: deny
      protocol: all
      cidr: 0.0.0.0/0
  egress:
    - priority: 100
      action: allow
      protocol: all
      cidr: 0.0.0.0/0`

// policyACLEgressDeny stops everything leaving the Subnet.
const policyACLEgressDeny = `
  egress:
    - priority: 100
      action: deny
      protocol: all
      cidr: 0.0.0.0/0`

// policySGEgressAllowAll makes the sender enforcing without changing
// which packets leave it. Declaring egress rules and no ingress rules
// also leaves ingress at the SecurityGroup default of deny, so the
// reply leg depends on conntrack.
const policySGEgressAllowAll = `
  egress:
    - to:
        - cidr: 0.0.0.0/0
      protocol: all`

// policySGEgressToElsewhere declares egress rules that no destination
// in the fixture matches.
const policySGEgressToElsewhere = `
  egress:
    - to:
        - cidr: ` + policyElsewhereCIDR + `
      protocol: all`

// policySGIngressPort admits `port` from any peer.
func policySGIngressPort(port int) string {
	return fmt.Sprintf(`
  ingress:
    - from:
        - cidr: 0.0.0.0/0
      protocol: tcp
      ports:
        - port: %d`, port)
}

// policySGIngressFromElsewhere declares ingress rules that no peer in
// the fixture matches.
func policySGIngressFromElsewhere(port int) string {
	return fmt.Sprintf(`
  ingress:
    - from:
        - cidr: %s
      protocol: tcp
      ports:
        - port: %d`, policyElsewhereCIDR, port)
}

// --- Pod containers --------------------------------------------------

// dualPortServerContainers serves nginx on policyOpenPort and a static
// page on policyBlockedPort, so one destination Pod carries both the
// admitted and the denied case.
func dualPortServerContainers() string {
	return nginxServerContainer + fmt.Sprintf(`
    - name: server-alt
      image: %s
      command:
        - /bin/sh
        - -c
        - |
          mkdir -p /www
          echo %s > /www/index.html
          exec httpd -f -p %d -h /www
      ports:
        - containerPort: %d`, busyboxImage, policyAltBody, policyBlockedPort, policyBlockedPort)
}
