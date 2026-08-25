package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Juneau TransitGateway E2E coverage:
//
//  1. A hub and two spokes attached to the same gateway and sharing one
//     transit route table reach each other, spoke to spoke included.
//  2. A static blackhole route drops the traffic for one destination
//     while the rest of the gateway keeps forwarding.
//  3. Giving the spokes their own association keeps them apart: their
//     table only carries the hub prefix, so a spoke destination never
//     resolves even though the Vpc RouteTable points at the gateway.
//  4. Deleting an attachment withdraws its prefixes: the destination
//     leaves the shared route table, the traffic that used it stops,
//     and the rest of the gateway keeps forwarding.
//
// The transit lookup ends in a normal Subnet VNI, so every spec puts the
// client and the servers on different nodes to exercise the VXLAN path.
var _ = Describe("Juneau TransitGateway", func() {
	It("connects the hub and both spokes through one transit route table", func() {
		fix := newTransitGatewayFixture(sanitizeName("tgw-shared"))
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		By("attaching every Vpc to the single default route table")
		fix.AttachAllToDefaultTable()

		By("checking every Vpc prefix was propagated into the default route table")
		fix.ExpectTransitGatewayRoute(fix.defaultTable, fix.hubCIDR, fix.hubSubnet, "propagated")
		fix.ExpectTransitGatewayRoute(fix.defaultTable, fix.spokeACIDR, fix.spokeASubnet, "propagated")
		fix.ExpectTransitGatewayRoute(fix.defaultTable, fix.spokeBCIDR, fix.spokeBSubnet, "propagated")

		By("pointing every Vpc RouteTable at the transit gateway")
		fix.RouteEveryVpcThroughTheGateway()

		By("checking each RouteTable resolved its association")
		fix.ExpectTransitRoute(fix.spokeAVpc, fix.spokeBCIDR, fix.defaultTable)
		fix.ExpectTransitRoute(fix.spokeBVpc, fix.spokeACIDR, fix.defaultTable)

		By("placing servers in the hub and in one spoke, and a client in the other spoke")
		fix.CreatePod("server-hub", fix.hubSubnet, workerNodes[1], true)
		fix.CreatePod("server-b", fix.spokeBSubnet, workerNodes[1], true)
		fix.CreatePod("client-a", fix.spokeASubnet, workerNodes[0], false)
		waitPodsReady(fix.namespace, "server-hub", "server-b", "client-a")

		By("checking traffic from a spoke to the hub")
		assertPodConnectivity(fix.namespace, "client-a", "server-hub")

		By("checking traffic from one spoke to the other")
		assertPodConnectivity(fix.namespace, "client-a", "server-b")
	})

	It("drops traffic for a destination with a blackhole route", func() {
		fix := newTransitGatewayFixture(sanitizeName("tgw-blackhole"))
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()
		fix.AttachAllToDefaultTable()

		// The blackhole goes in before the Pods exist so the data plane
		// never carries this destination. Flipping a working route to a
		// blackhole would race the daemon reprogramming the table.
		By("blackholing one spoke in the default route table")
		fix.SetBlackholeRoute(fix.defaultTable, fix.spokeBCIDR)
		fix.ExpectBlackholeRoute(fix.defaultTable, fix.spokeBCIDR)

		fix.RouteEveryVpcThroughTheGateway()
		fix.ExpectTransitRoute(fix.spokeAVpc, fix.spokeBCIDR, fix.defaultTable)

		fix.CreatePod("server-hub", fix.hubSubnet, workerNodes[1], true)
		fix.CreatePod("server-b", fix.spokeBSubnet, workerNodes[1], true)
		fix.CreatePod("client-a", fix.spokeASubnet, workerNodes[0], false)
		waitPodsReady(fix.namespace, "server-hub", "server-b", "client-a")

		// Reach the hub first. Without this the next assertion could pass
		// because the transit path was not programmed yet, rather than
		// because of the blackhole.
		By("checking the gateway still carries traffic to the hub")
		assertPodConnectivity(fix.namespace, "client-a", "server-hub")

		By("checking the blackholed spoke is unreachable")
		assertNoPodConnectivity(fix.namespace, "client-a", "server-b")
	})

	It("keeps the spokes apart when they associate with their own route table", func() {
		fix := newTransitGatewayFixture(sanitizeName("tgw-isolation"))
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()

		// The hub looks its traffic up in the default table and the
		// spokes fill that table, so the hub reaches both. The spokes
		// look their traffic up in a table only the hub propagates into,
		// so they reach the hub and nothing else.
		By("associating the hub with the default table and the spokes with their own")
		fix.Attach(fix.hubAttachment, fix.hubVpc, fix.defaultTable, fix.spokeTable)
		fix.Attach(fix.spokeAAttachment, fix.spokeAVpc, fix.spokeTable, fix.defaultTable)
		fix.Attach(fix.spokeBAttachment, fix.spokeBVpc, fix.spokeTable, fix.defaultTable)
		fix.WaitAttachmentsReady()

		By("checking the spoke table only learned the hub prefix")
		fix.ExpectTransitGatewayRoute(fix.spokeTable, fix.hubCIDR, fix.hubSubnet, "propagated")
		fix.ExpectNoTransitGatewayRoute(fix.spokeTable, fix.spokeBCIDR)
		fix.ExpectTransitGatewayRoute(fix.defaultTable, fix.spokeACIDR, fix.spokeASubnet, "propagated")

		fix.RouteEveryVpcThroughTheGateway()
		fix.ExpectTransitRoute(fix.spokeAVpc, fix.spokeBCIDR, fix.spokeTable)

		fix.CreatePod("server-hub", fix.hubSubnet, workerNodes[1], true)
		fix.CreatePod("server-b", fix.spokeBSubnet, workerNodes[1], true)
		fix.CreatePod("client-a", fix.spokeASubnet, workerNodes[0], false)
		waitPodsReady(fix.namespace, "server-hub", "server-b", "client-a")

		By("checking a spoke still reaches the hub")
		assertPodConnectivity(fix.namespace, "client-a", "server-hub")

		By("checking a spoke cannot reach the other spoke")
		assertNoPodConnectivity(fix.namespace, "client-a", "server-b")
	})

	It("withdraws the routes of a deleted attachment and stops its traffic", func() {
		fix := newTransitGatewayFixture(sanitizeName("tgw-detach"))
		DeferCleanup(fix.Cleanup)
		fix.CreateNetwork()
		fix.AttachAllToDefaultTable()
		fix.RouteEveryVpcThroughTheGateway()

		By("checking the spoke prefix is propagated into the default route table")
		fix.ExpectTransitGatewayRoute(fix.defaultTable, fix.spokeBCIDR, fix.spokeBSubnet, "propagated")
		fix.ExpectTransitRoute(fix.spokeAVpc, fix.spokeBCIDR, fix.defaultTable)

		fix.CreatePod("server-hub", fix.hubSubnet, workerNodes[1], true)
		fix.CreatePod("server-b", fix.spokeBSubnet, workerNodes[1], true)
		fix.CreatePod("client-a", fix.spokeASubnet, workerNodes[0], false)
		waitPodsReady(fix.namespace, "server-hub", "server-b", "client-a")

		// Open the path first. Without this the assertion after the delete
		// could pass because the transit path was never programmed, rather
		// than because the attachment took its prefix away.
		By("checking one spoke reaches the other while both are attached")
		assertPodConnectivity(fix.namespace, "client-a", "server-b")

		By("deleting the attachment of the destination spoke")
		fix.DeleteAttachment(fix.spokeBAttachment)

		By("checking the spoke prefix left the default route table")
		fix.ExpectTransitGatewayRouteWithdrawn(fix.defaultTable, fix.spokeBCIDR)

		By("checking traffic to the detached spoke stops")
		assertPodConnectivityStops(fix.namespace, "client-a", "server-b")

		By("checking the gateway still carries traffic to the hub")
		assertPodConnectivity(fix.namespace, "client-a", "server-hub")
	})
})

type transitGatewayFixture struct {
	namespace string

	gateway string
	// defaultTable is created and owned by the TransitGateway and carries
	// the gateway's own name. spokeTable is an extra table the specs use
	// to give the spokes an association of their own.
	defaultTable string
	spokeTable   string

	hubVpc    string
	hubSubnet string
	hubCIDR   string

	spokeAVpc    string
	spokeASubnet string
	spokeACIDR   string

	spokeBVpc    string
	spokeBSubnet string
	spokeBCIDR   string

	hubAttachment    string
	spokeAAttachment string
	spokeBAttachment string
}

func newTransitGatewayFixture(base string) *transitGatewayFixture {
	gateway := "tgw-" + base
	return &transitGatewayFixture{
		namespace:    "e2e-" + base,
		gateway:      gateway,
		defaultTable: gateway,
		spokeTable:   "tgwrt-spoke-" + base,

		hubVpc:    "vpc-hub-" + base,
		hubSubnet: "subnet-hub-" + base,
		hubCIDR:   cidrForScenario(base, 0),

		spokeAVpc:    "vpc-spoke-a-" + base,
		spokeASubnet: "subnet-spoke-a-" + base,
		spokeACIDR:   cidrForScenario(base, 1),

		spokeBVpc:    "vpc-spoke-b-" + base,
		spokeBSubnet: "subnet-spoke-b-" + base,
		spokeBCIDR:   cidrForScenario(base, 2),

		hubAttachment:    "attach-hub-" + base,
		spokeAAttachment: "attach-spoke-a-" + base,
		spokeBAttachment: "attach-spoke-b-" + base,
	}
}

func (f *transitGatewayFixture) CreateNetwork() {
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
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGateway
metadata:
  name: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGatewayRouteTable
metadata:
  name: %s
spec:
  transitGateway: %s
`, f.hubVpc, f.spokeAVpc, f.spokeBVpc,
		f.hubSubnet, f.hubVpc, f.hubCIDR,
		f.spokeASubnet, f.spokeAVpc, f.spokeACIDR,
		f.spokeBSubnet, f.spokeBVpc, f.spokeBCIDR,
		f.gateway,
		f.spokeTable, f.gateway)

	Expect(applyManifest(manifest)).To(Succeed())
	waitSubnetReady(f.hubSubnet)
	waitSubnetReady(f.spokeASubnet)
	waitSubnetReady(f.spokeBSubnet)

	By("waiting for the TransitGateway and both route tables to become Ready")
	waitResourceReady("transitgateway", f.gateway)
	waitResourceReady("transitgatewayroutetable", f.defaultTable)
	waitResourceReady("transitgatewayroutetable", f.spokeTable)
}

// Attach creates one TransitGatewayAttachment. Traffic arriving from the
// Vpc is looked up in association, and the Vpc's Subnets are advertised
// into every table in propagations.
func (f *transitGatewayFixture) Attach(name string, vpc string, association string, propagations ...string) {
	list := ""
	for _, table := range propagations {
		list += fmt.Sprintf("\n    - %s", table)
	}

	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGatewayAttachment
metadata:
  name: %s
spec:
  transitGateway: %s
  vpc: %s
  association: %s
  propagations:%s
`, name, f.gateway, vpc, association, list)

	Expect(applyManifest(manifest)).To(Succeed())
}

// AttachAllToDefaultTable puts every Vpc on the gateway's default table,
// which is the flat setup where every attachment can reach every other.
func (f *transitGatewayFixture) AttachAllToDefaultTable() {
	f.Attach(f.hubAttachment, f.hubVpc, f.defaultTable, f.defaultTable)
	f.Attach(f.spokeAAttachment, f.spokeAVpc, f.defaultTable, f.defaultTable)
	f.Attach(f.spokeBAttachment, f.spokeBVpc, f.defaultTable, f.defaultTable)
	f.WaitAttachmentsReady()
}

func (f *transitGatewayFixture) DeleteAttachment(name string) {
	Expect(run(repoRoot, "kubectl", "delete", "transitgatewayattachment", name)).To(Succeed())
}

func (f *transitGatewayFixture) WaitAttachmentsReady() {
	for _, name := range []string{f.hubAttachment, f.spokeAAttachment, f.spokeBAttachment} {
		waitResourceReady("transitgatewayattachment", name)
	}
}

// RouteEveryVpcThroughTheGateway sends each Vpc towards the two other
// Vpcs through the gateway. Return traffic needs the same route on the
// server side, so all three main RouteTables get one.
func (f *transitGatewayFixture) RouteEveryVpcThroughTheGateway() {
	f.SetTransitRoutes(f.hubVpc, f.spokeACIDR, f.spokeBCIDR)
	f.SetTransitRoutes(f.spokeAVpc, f.hubCIDR, f.spokeBCIDR)
	f.SetTransitRoutes(f.spokeBVpc, f.hubCIDR, f.spokeACIDR)
}

// SetTransitRoutes replaces the routes of a Vpc's main RouteTable with
// one transit route per destination.
func (f *transitGatewayFixture) SetTransitRoutes(vpc string, dsts ...string) {
	routes := make([]route, 0, len(dsts))
	for _, dst := range dsts {
		routes = append(routes, transitGatewayRoute(dst, f.gateway))
	}
	setMainRouteTableRoutes(vpc, routes...)
}

func (f *transitGatewayFixture) SetBlackholeRoute(table string, dst string) {
	patch := fmt.Sprintf(`{"spec":{"routes":[{"dst":%q,"blackhole":true}]}}`, dst)
	Expect(run(repoRoot, "kubectl", "patch", "transitgatewayroutetable", table, "--type=merge", "-p", patch)).To(Succeed())
}

func (f *transitGatewayFixture) CreatePod(name string, subnet string, node string, server bool) {
	Expect(applyManifest(podManifest(f.namespace, name, node, subnet, server))).To(Succeed())
}

// ExpectTransitRoute checks the controller resolved the Vpc's route to
// the route table the Vpc's attachment associates with: that table is
// where the data plane does its second lookup.
func (f *transitGatewayFixture) ExpectTransitRoute(vpc string, dst string, table string) {
	Eventually(func(g Gomega) {
		viaType, err := kubectlJSONPath(repoRoot,
			fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].via.type}`, dst),
			"get", "routetable", vpc)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(viaType)).To(Equal("transitGateway"))

		association, err := kubectlJSONPath(repoRoot,
			fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].transitGatewayRouteTable}`, dst),
			"get", "routetable", vpc)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(association)).To(Equal(table))
	}).Should(Succeed())
}

// ExpectTransitGatewayRoute checks the resolved transit table names the
// target Subnet: that name is what the data plane turns into a VNI.
func (f *transitGatewayFixture) ExpectTransitGatewayRoute(table string, dst string, subnet string, origin string) {
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot,
			fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].subnet}`, dst),
			"get", "transitgatewayroutetable", table)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).To(Equal(subnet))

		gotOrigin, err := kubectlJSONPath(repoRoot,
			fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].origin}`, dst),
			"get", "transitgatewayroutetable", table)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(gotOrigin)).To(Equal(origin))
	}).Should(Succeed())
}

func (f *transitGatewayFixture) ExpectBlackholeRoute(table string, dst string) {
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot,
			fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].blackhole}`, dst),
			"get", "transitgatewayroutetable", table)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).To(Equal("true"))
	}).Should(Succeed())
}

// ExpectNoTransitGatewayRoute checks a destination never appears in the
// table. The check is consistently, not eventually: an entry showing up
// late would still open a path the spec says must stay closed.
func (f *transitGatewayFixture) ExpectNoTransitGatewayRoute(table string, dst string) {
	Consistently(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot,
			fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].dst}`, dst),
			"get", "transitgatewayroutetable", table)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).To(BeEmpty())
	}, "5s", "1s").Should(Succeed())
}

// ExpectTransitGatewayRouteWithdrawn waits for a destination to leave
// the table. ExpectNoTransitGatewayRoute cannot be used here: the route
// is present when the caller starts waiting, so a consistently check
// would fail on its first poll.
func (f *transitGatewayFixture) ExpectTransitGatewayRouteWithdrawn(table string, dst string) {
	Eventually(func(g Gomega) {
		got, err := kubectlJSONPath(repoRoot,
			fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].dst}`, dst),
			"get", "transitgatewayroutetable", table)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(got)).To(BeEmpty())
	}).Should(Succeed())
}

func (f *transitGatewayFixture) Cleanup() {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", f.namespace, "--ignore-not-found=true", "--timeout=60s")
	// Unwind in reference order: the TransitGateway delete guard refuses
	// while a RouteTable or an attachment still names it, the route table
	// guard refuses while an attachment associates or propagates into it,
	// and the Vpc guard refuses while a Subnet or an attachment names the
	// Vpc.
	for _, vpc := range []string{f.hubVpc, f.spokeAVpc, f.spokeBVpc} {
		clearMainRouteTableRoutes(vpc)
	}
	for _, attachment := range []string{f.hubAttachment, f.spokeAAttachment, f.spokeBAttachment} {
		runBestEffort(repoRoot, "kubectl", "delete", "transitgatewayattachment", attachment, "--ignore-not-found=true")
	}
	runBestEffort(repoRoot, "kubectl", "delete", "transitgatewayroutetable", f.spokeTable, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "transitgateway", f.gateway, "--ignore-not-found=true")
	for _, subnet := range []string{f.hubSubnet, f.spokeASubnet, f.spokeBSubnet} {
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnet, "--ignore-not-found=true")
	}
	for _, vpc := range []string{f.hubVpc, f.spokeAVpc, f.spokeBVpc} {
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpc, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpc, "--ignore-not-found=true")
	}
}
