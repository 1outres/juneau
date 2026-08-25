package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Juneau VpcPeering E2E coverage:
//
//  1. Two peered VPCs reach each other in both directions once both
//     main RouteTables name the peering.
//  2. A peering on its own carries no traffic: the side whose
//     RouteTable has no peering route cannot reach the other VPC, and
//     adding that route is what opens the path.
//
// The data plane forwards a peering route like a connected one — it
// targets the peer Subnet's VNI — so both specs pin the two sides to
// different nodes to exercise the VXLAN path.
var _ = Describe("Juneau VpcPeering", func() {
	It("connects Pods in two peered VPCs in both directions", func() {
		fix := newPeeringFixture(sanitizeName("peering-both-ways"))
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		By("waiting for the VpcPeering to become Ready")
		fix.WaitPeeringReady()

		By("naming the peering in both main RouteTables")
		fix.SetPeeringRoute(fix.vpcA, fix.cidrB)
		fix.SetPeeringRoute(fix.vpcB, fix.cidrA)

		By("checking each RouteTable resolved its route to the peer Subnet")
		fix.ExpectPeeringRoute(fix.vpcA, fix.cidrB, fix.subnetB)
		fix.ExpectPeeringRoute(fix.vpcB, fix.cidrA, fix.subnetA)

		By("placing a server and a client in each VPC, on different nodes")
		fix.CreatePod("server-a", fix.subnetA, workerNodes[0], true)
		fix.CreatePod("client-a", fix.subnetA, workerNodes[0], false)
		fix.CreatePod("server-b", fix.subnetB, workerNodes[1], true)
		fix.CreatePod("client-b", fix.subnetB, workerNodes[1], false)
		waitPodsReady(fix.namespace, "server-a", "client-a", "server-b", "client-b")

		By("checking traffic from the requester VPC to the accepter VPC")
		assertPodConnectivity(fix.namespace, "client-a", "server-b")

		By("checking traffic from the accepter VPC back to the requester VPC")
		assertPodConnectivity(fix.namespace, "client-b", "server-a")
	})

	It("carries traffic only in the direction a peering route was written", func() {
		fix := newPeeringFixture(sanitizeName("peering-needs-routes"))
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()
		fix.WaitPeeringReady()

		By("routing only the requester VPC towards the accepter VPC")
		fix.SetPeeringRoute(fix.vpcA, fix.cidrB)
		fix.ExpectPeeringRoute(fix.vpcA, fix.cidrB, fix.subnetB)

		fix.CreatePod("server-a", fix.subnetA, workerNodes[0], true)
		fix.CreatePod("server-b", fix.subnetB, workerNodes[1], true)
		fix.CreatePod("client-b", fix.subnetB, workerNodes[1], false)
		waitPodsReady(fix.namespace, "server-a", "server-b", "client-b")

		// Reach a server inside the client's own VPC first. Without this
		// the next assertion could pass simply because the client's data
		// plane was not programmed yet, rather than because the route is
		// missing.
		By("checking the client can reach its own VPC")
		assertPodConnectivity(fix.namespace, "client-b", "server-b")

		By("checking the accepter VPC cannot reach back without its own route")
		assertNoPodConnectivity(fix.namespace, "client-b", "server-a")

		By("adding the return route and checking the same path now works")
		fix.SetPeeringRoute(fix.vpcB, fix.cidrA)
		fix.ExpectPeeringRoute(fix.vpcB, fix.cidrA, fix.subnetA)
		assertPodConnectivity(fix.namespace, "client-b", "server-a")
	})
})

type peeringFixture struct {
	namespace string
	vpcA      string
	vpcB      string
	subnetA   string
	subnetB   string
	cidrA     string
	cidrB     string
	peering   string
}

func newPeeringFixture(base string) *peeringFixture {
	return &peeringFixture{
		namespace: "e2e-" + base,
		vpcA:      "vpc-a-" + base,
		vpcB:      "vpc-b-" + base,
		subnetA:   "subnet-a-" + base,
		subnetB:   "subnet-b-" + base,
		cidrA:     cidrForScenario(base, 0),
		cidrB:     cidrForScenario(base, 1),
		peering:   "peering-" + base,
	}
}

func (f *peeringFixture) CreateNetwork() {
	createNamespace(f.namespace)

	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
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
---
apiVersion: juneau.loutres.me/v1alpha1
kind: VpcPeering
metadata:
  name: %s
spec:
  requester:
    vpc: %s
  accepter:
    vpc: %s
`, f.vpcA, f.vpcB,
		f.subnetA, f.vpcA, f.cidrA,
		f.subnetB, f.vpcB, f.cidrB,
		f.peering, f.vpcA, f.vpcB)

	Expect(applyManifest(manifest)).To(Succeed())
	waitSubnetReady(f.subnetA)
	waitSubnetReady(f.subnetB)
}

func (f *peeringFixture) WaitPeeringReady() {
	waitResourceReady("vpcpeering", f.peering)
}

// SetPeeringRoute replaces the routes of a Vpc's main RouteTable with a
// single route towards the peer.
func (f *peeringFixture) SetPeeringRoute(vpc string, dst string) {
	setMainRouteTableRoutes(vpc, vpcPeeringRoute(dst, f.peering))
}

// ExpectPeeringRoute checks the controller published the route with the
// peer Subnet resolved: that name is what the data plane turns into the
// destination VNI.
func (f *peeringFixture) ExpectPeeringRoute(vpc string, dst string, peerSubnet string) {
	Eventually(func(g Gomega) {
		viaType, err := kubectlJSONPath(repoRoot,
			fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].via.type}`, dst),
			"get", "routetable", vpc)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(viaType)).To(Equal("vpcPeering"))

		subnet, err := kubectlJSONPath(repoRoot,
			fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].subnet}`, dst),
			"get", "routetable", vpc)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(subnet)).To(Equal(peerSubnet))
	}).Should(Succeed())
}

func (f *peeringFixture) CreatePod(name string, subnet string, node string, server bool) {
	Expect(applyManifest(podManifest(f.namespace, name, node, subnet, server))).To(Succeed())
}

func (f *peeringFixture) Cleanup() {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", f.namespace, "--ignore-not-found=true", "--timeout=60s")
	// Unwind in reference order: the VpcPeering delete guard refuses
	// while a RouteTable still names it, and the Vpc guard refuses
	// while a Subnet or a VpcPeering still names the Vpc.
	for _, vpc := range []string{f.vpcA, f.vpcB} {
		clearMainRouteTableRoutes(vpc)
	}
	runBestEffort(repoRoot, "kubectl", "delete", "vpcpeering", f.peering, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", f.subnetA, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", f.subnetB, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", f.vpcA, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", f.vpcB, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "routetable", f.vpcA, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "routetable", f.vpcB, "--ignore-not-found=true")
}
