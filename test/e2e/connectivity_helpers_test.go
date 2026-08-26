package e2e

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	serverPodName = "server"
	clientPodName = "client"
)

type trafficTarget string

const (
	targetPodIP   trafficTarget = "podIP"
	targetService trafficTarget = "service"
)

type placementMode string

const (
	placementSameNode       placementMode = "same-node"
	placementDifferentNodes placementMode = "different-nodes"
)

type networkMode string

const (
	networkDefault                networkMode = "default"
	networkSameCustomSubnet       networkMode = "same-custom-subnet"
	networkDifferentCustomSubnets networkMode = "different-custom-subnets"
)

type connectivityScenario struct {
	name      string
	target    trafficTarget
	placement placementMode
	network   networkMode
}

type networkFixture struct {
	vpcName      string
	serverSubnet string
	clientSubnet string
}

func runConnectivityScenario(s connectivityScenario) {
	ctx := newCaseContext(s)
	currentCase = &ctx
	DeferCleanup(func() {
		currentCase = nil
	})

	By("creating an isolated namespace for the scenario")
	createNamespace(ctx.namespace)
	DeferCleanup(cleanupCaseResources, ctx)

	By("preparing the network fixture for the scenario")
	fixture := ensureNetworkFixture(ctx, s.network)
	nodes := chooseNodes(s.placement)

	By(fmt.Sprintf("creating the server pod on %s", nodes[0]))
	createServerPod(ctx, nodes[0], fixture.serverSubnet)
	if s.target == targetService {
		By("creating a service for the server pod")
		serviceVpc := ""
		if fixture.vpcName != defaultVpcName {
			serviceVpc = fixture.vpcName
		}
		createServerService(ctx, serviceVpc)
	}
	By(fmt.Sprintf("creating the client pod on %s", nodes[1]))
	createClientPod(ctx, nodes[1], fixture.clientSubnet)

	By("waiting for both pods to become Ready")
	waitPodsReady(ctx.namespace, serverPodName, clientPodName)
	By("verifying the pods landed on the expected nodes")
	assertPodPlacement(ctx.namespace, serverPodName, nodes[0])
	assertPodPlacement(ctx.namespace, clientPodName, nodes[1])
	By("verifying Juneau created runtime resources for the expected subnets")
	assertPodNetwork(ctx.namespace, serverPodName, expectedSubnetName(fixture.serverSubnet))
	assertPodNetwork(ctx.namespace, clientPodName, expectedSubnetName(fixture.clientSubnet))

	if s.target == targetService {
		By("waiting for the service to publish its backend endpoint")
		waitServiceEndpoints(ctx.namespace, serverPodName)
		By("checking connectivity from the client pod to the service")
		assertServiceConnectivity(ctx.namespace, clientPodName, serverPodName)
		return
	}

	By("checking direct pod-to-pod connectivity from the client pod to the server pod")
	assertPodConnectivity(ctx.namespace, clientPodName, serverPodName)
}

func newCaseContext(s connectivityScenario) caseContext {
	base := sanitizeName(s.name)
	return caseContext{
		namespace:    "e2e-" + base,
		vpcName:      "vpc-" + base,
		serverSubnet: "subnet-a-" + base,
		clientSubnet: "subnet-b-" + base,
		serverCIDR:   cidrForScenario(base, 0),
		clientCIDR:   cidrForScenario(base, 1),
		serviceName:  serverPodName,
		scenarioName: base,
	}
}

type caseContext struct {
	namespace    string
	vpcName      string
	serverSubnet string
	clientSubnet string
	serverCIDR   string
	clientCIDR   string
	serviceName  string
	scenarioName string
}

func sanitizeName(s string) string {
	s = strings.ToLower(s)
	replacer := strings.NewReplacer(" ", "-", "/", "-", ",", "", "_", "-")
	return replacer.Replace(s)
}

func cidrForScenario(base string, offset int) string {
	var sum int
	for _, r := range base {
		sum += int(r)
	}
	// 128–255 avoids both the kind Pod CIDR (10.16.0.0/16) and the
	// Service CIDR (10.96.0.0/12 = 10.96–111). Older spec names happened
	// not to hash into the Service range, so the bug stayed dormant.
	thirdOctet := 128 + ((sum + (offset * 37)) % 128)
	return fmt.Sprintf("10.%d.0.0/24", thirdOctet)
}

func chooseNodes(mode placementMode) [2]string {
	Expect(len(workerNodes)).To(BeNumerically(">=", 2), "cross-node tests need at least 2 worker nodes")
	if mode == placementDifferentNodes {
		return [2]string{workerNodes[0], workerNodes[1]}
	}
	return [2]string{workerNodes[0], workerNodes[0]}
}

func expectedSubnetName(subnet string) string {
	if subnet == "" {
		return defaultSubnetName
	}
	return subnet
}

func ensureNetworkFixture(ctx caseContext, mode networkMode) networkFixture {
	switch mode {
	case networkDefault:
		return networkFixture{vpcName: defaultVpcName}
	case networkSameCustomSubnet:
		createCustomNetwork(ctx, false, false)
		return networkFixture{vpcName: ctx.vpcName, serverSubnet: ctx.serverSubnet, clientSubnet: ctx.serverSubnet}
	case networkDifferentCustomSubnets:
		createCustomNetwork(ctx, true, false)
		return networkFixture{vpcName: ctx.vpcName, serverSubnet: ctx.serverSubnet, clientSubnet: ctx.clientSubnet}
	default:
		Fail(fmt.Sprintf("unknown network mode: %s", mode))
		return networkFixture{}
	}
}

func createCustomNetwork(ctx caseContext, createClientSubnet bool, enableService bool) {
	By("creating a dedicated VPC and subnet resources")
	serviceLine := ""
	if enableService {
		// Setting service.consume=true is the umbrella that turns on
		// Service routing in the VPC; provider-only configuration
		// would also work but is not what these tests care about.
		serviceLine = "\nspec:\n  service:\n    consume: true"
	}
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s%s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, ctx.vpcName, serviceLine, ctx.serverSubnet, ctx.vpcName, ctx.serverCIDR)

	if createClientSubnet {
		manifest += fmt.Sprintf(`---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, ctx.clientSubnet, ctx.vpcName, ctx.clientCIDR)
	}

	Expect(applyManifest(manifest)).To(Succeed())
	By(fmt.Sprintf("waiting for subnet %s to become Ready", ctx.serverSubnet))
	waitSubnetReady(ctx.serverSubnet)
	if createClientSubnet {
		By(fmt.Sprintf("waiting for subnet %s to become Ready", ctx.clientSubnet))
		waitSubnetReady(ctx.clientSubnet)
	}
}

func createNamespace(namespace string) {
	Expect(applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, namespace))).To(Succeed())
}

func createServerPod(ctx caseContext, nodeName string, subnet string) {
	Expect(applyManifest(podManifest(ctx.namespace, serverPodName, nodeName, subnet, true))).To(Succeed())
}

func createClientPod(ctx caseContext, nodeName string, subnet string) {
	Expect(applyManifest(podManifest(ctx.namespace, clientPodName, nodeName, subnet, false))).To(Succeed())
}

func podManifest(namespace string, name string, nodeName string, subnet string, server bool) string {
	annotation := ""
	if subnet != "" {
		annotation = fmt.Sprintf("  annotations:\n    juneau.loutres.me/subnet: %s\n", subnet)
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

	// terminationGracePeriodSeconds: 0 lets `kubectl delete namespace` (and
	// implicit pod GC) complete in seconds instead of waiting out nginx's
	// default 30s graceful shutdown — the dominant tail latency in the
	// connectivity matrix and similar specs.
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
`, namespace, name, name, annotation, nodeName, container)
}

// netshootPodManifest builds a Pod carrying the network tools some specs
// shell out to (dig, ping). The curl fixture image cannot run ping: it
// starts as a non-root user, so opening a raw ICMP socket fails.
func netshootPodManifest(namespace string, name string, nodeName string, subnet string) string {
	annotation := ""
	if subnet != "" {
		annotation = fmt.Sprintf("  annotations:\n    juneau.loutres.me/subnet: %s\n", subnet)
	}

	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
%sspec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: client
      image: %s
      command: ["sleep", "3600"]
`, namespace, name, annotation, nodeName, netshootImage)
}

func createServerService(ctx caseContext, vpcAnnotation string) {
	annotation := ""
	if vpcAnnotation != "" {
		annotation = fmt.Sprintf("  annotations:\n    juneau.loutres.me/vpc: %s\n", vpcAnnotation)
	}
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
%sspec:
  selector:
    app: %s
  ports:
    - port: 80
      targetPort: 80
`, ctx.namespace, ctx.serviceName, annotation, serverPodName)
	Expect(applyManifest(manifest)).To(Succeed())
}

func waitPodsReady(namespace string, pods ...string) {
	args := []string{"wait", "-n", namespace, "--for=condition=Ready"}
	for _, pod := range pods {
		args = append(args, "pod/"+pod)
	}
	args = append(args, "--timeout=60s")
	Eventually(func(g Gomega) {
		g.Expect(run(repoRoot, "kubectl", args...)).To(Succeed())
	}).Should(Succeed())
}

func waitSubnetReady(name string) {
	Eventually(func(g Gomega) {
		ready, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].status}`, "get", "subnet", name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(ready)).To(Equal("True"))

		gateway, err := kubectlJSONPath(repoRoot, `{.status.gateway}`, "get", "subnet", name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(gateway)).NotTo(BeEmpty())
	}).Should(Succeed())
}

// waitResourceReady waits for the Ready condition of any cluster-scoped
// Juneau resource.
func waitResourceReady(resource string, name string) {
	Eventually(func(g Gomega) {
		ready, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].status}`, "get", resource, name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(ready)).To(Equal("True"))
	}).Should(Succeed())
}

type routeViaType string

const (
	viaInternetGateway routeViaType = "internetGateway"
	viaNATGateway      routeViaType = "natGateway"
	viaVpcPeering      routeViaType = "vpcPeering"
	viaTransitGateway  routeViaType = "transitGateway"
)

type routeVia struct {
	Type           routeViaType `json:"type"`
	NATGateway     string       `json:"natGateway,omitempty"`
	VpcPeering     string       `json:"vpcPeering,omitempty"`
	TransitGateway string       `json:"transitGateway,omitempty"`
}

type route struct {
	Dst string   `json:"dst"`
	Via routeVia `json:"via"`
}

type routeTablePatch struct {
	Spec routeTablePatchSpec `json:"spec"`
}

type routeTablePatchSpec struct {
	Routes []route `json:"routes"`
}

func internetGatewayRoute(dst string) route {
	return route{Dst: dst, Via: routeVia{Type: viaInternetGateway}}
}

func natGatewayRoute(dst string, natGateway string) route {
	return route{Dst: dst, Via: routeVia{Type: viaNATGateway, NATGateway: natGateway}}
}

func vpcPeeringRoute(dst string, vpcPeering string) route {
	return route{Dst: dst, Via: routeVia{Type: viaVpcPeering, VpcPeering: vpcPeering}}
}

func transitGatewayRoute(dst string, transitGateway string) route {
	return route{Dst: dst, Via: routeVia{Type: viaTransitGateway, TransitGateway: transitGateway}}
}

// mainRouteTablePatch builds the merge patch that makes the given routes
// the whole spec.routes of a RouteTable.
func mainRouteTablePatch(routes ...route) (string, error) {
	patch := routeTablePatch{Spec: routeTablePatchSpec{Routes: make([]route, 0, len(routes))}}
	patch.Spec.Routes = append(patch.Spec.Routes, routes...)

	encoded, err := json.Marshal(patch)
	if err != nil {
		return "", fmt.Errorf("encode route table patch: %w", err)
	}
	return string(encoded), nil
}

func vpcManifest(vpc string) string {
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
`, vpc)
}

func mainRouteTableManifest(vpc string, routes ...route) (string, error) {
	encoded, err := json.Marshal(append(make([]route, 0, len(routes)), routes...))
	if err != nil {
		return "", fmt.Errorf("encode route table routes: %w", err)
	}
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: %s
spec:
  vpc: %s
  routes: %s
`, vpc, vpc, encoded), nil
}

func vpcWithMainRouteTableManifest(vpc string, routes ...route) (string, error) {
	routeTable, err := mainRouteTableManifest(vpc, routes...)
	if err != nil {
		return "", err
	}
	return vpcManifest(vpc) + "---\n" + routeTable, nil
}

// vpcMainRouteTable reads the name of the RouteTable the Vpc reconciler
// created for the Vpc.
func vpcMainRouteTable(vpc string) (string, error) {
	out, err := kubectlJSONPath(repoRoot, `{.status.mainRouteTable}`, "get", "vpc", vpc)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return "", fmt.Errorf("vpc %s has no main route table in status yet", vpc)
	}
	return name, nil
}

// waitVpcMainRouteTable waits until the Vpc names its main RouteTable.
// The reconciler owns that object, so a spec that creates it races the
// reconciler and one of the two loses with AlreadyExists. The Vpc writes
// status.mainRouteTable only after the object exists, so waiting for the
// field and then patching never races.
func waitVpcMainRouteTable(vpc string) string {
	var name string
	Eventually(func(g Gomega) {
		var err error
		name, err = vpcMainRouteTable(vpc)
		g.Expect(err).NotTo(HaveOccurred())
	}).Should(Succeed())
	return name
}

// setMainRouteTableRoutes replaces spec.routes of the Vpc's main
// RouteTable with the given routes.
func setMainRouteTableRoutes(vpc string, routes ...route) {
	name := waitVpcMainRouteTable(vpc)
	patch, err := mainRouteTablePatch(routes...)
	Expect(err).NotTo(HaveOccurred())
	Expect(run(repoRoot, "kubectl", "patch", "routetable", name, "--type=merge", "-p", patch)).To(Succeed())
}

// clearMainRouteTableRoutes empties spec.routes of the Vpc's main
// RouteTable. It is best-effort so teardown never fails a suite.
func clearMainRouteTableRoutes(vpc string) {
	name, err := vpcMainRouteTable(vpc)
	if err != nil {
		reportMainRouteTableClearFailure(vpc, err)
		return
	}
	patch, err := mainRouteTablePatch()
	if err != nil {
		reportMainRouteTableClearFailure(vpc, err)
		return
	}
	runBestEffort(repoRoot, "kubectl", "patch", "routetable", name, "--type=merge", "-p", patch)
}

func reportMainRouteTableClearFailure(vpc string, err error) {
	_, _ = fmt.Fprintf(GinkgoWriter, "best-effort clear of the main RouteTable of vpc %s failed: %v\n", vpc, err)
}

type routeTableObject struct {
	Metadata routeTableMeta   `json:"metadata"`
	Spec     routeTableSpec   `json:"spec"`
	Status   routeTableStatus `json:"status"`
}

type routeTableMeta struct {
	Name            string               `json:"name"`
	OwnerReferences []routeTableOwnerRef `json:"ownerReferences,omitempty"`
}

type routeTableOwnerRef struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller bool   `json:"controller,omitempty"`
}

type routeTableSpec struct {
	Vpc    string  `json:"vpc"`
	Routes []route `json:"routes,omitempty"`
}

type routeTableStatus struct {
	TableID    uint32                       `json:"tableID,omitempty"`
	Routes     []routeTableRoute            `json:"routes,omitempty"`
	Conditions []bgpNodeStateConditionEntry `json:"conditions,omitempty"`
}

type routeTableRoute struct {
	Dst string `json:"dst"`
	Via struct {
		Type       string `json:"type"`
		NATGateway string `json:"natGateway,omitempty"`
	} `json:"via"`
}

func getRouteTableObject(name string) (*routeTableObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "routetable", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var obj routeTableObject
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, fmt.Errorf("decode routetable/%s: %w", name, err)
	}
	return &obj, nil
}

func routeTableControllerRef(obj *routeTableObject) *routeTableOwnerRef {
	for i := range obj.Metadata.OwnerReferences {
		if obj.Metadata.OwnerReferences[i].Controller {
			return &obj.Metadata.OwnerReferences[i]
		}
	}
	return nil
}

func waitServiceEndpoints(namespace string, serviceName string) {
	Eventually(func(g Gomega) {
		addresses, err := kubectlJSONPath(repoRoot, `{.subsets[*].addresses[*].ip}`, "-n", namespace, "get", "endpoints", serviceName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(addresses)).NotTo(BeEmpty())
	}).Should(Succeed())
}

func assertPodPlacement(namespace string, podName string, expectedNode string) {
	nodeName, err := kubectlJSONPath(repoRoot, `{.spec.nodeName}`, "-n", namespace, "get", "pod", podName)
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(nodeName)).To(Equal(expectedNode))
}

func assertPodNetwork(namespace string, podName string, expectedSubnet string) {
	Eventually(func(g Gomega) {
		nwifaceSubnet, err := kubectlJSONPath(repoRoot, `{.spec.subnet}`, "-n", namespace, "get", "networkinterface", podName+".eth0")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(nwifaceSubnet)).To(Equal(expectedSubnet))

		nwepSubnet, err := kubectlJSONPath(repoRoot, `{.spec.subnet}`, "-n", namespace, "get", "networkendpoint", podName+".eth0")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(nwepSubnet)).To(Equal(expectedSubnet))
	}).Should(Succeed())
}

func podIPOf(namespace string, podName string) (string, error) {
	out, err := kubectlJSONPath(repoRoot, `{.status.podIP}`, "-n", namespace, "get", "pod", podName)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func assertPodConnectivity(namespace string, clientPod string, serverPod string) {
	serverIP := mustPodIP(namespace, serverPod)

	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--", "curl", "-sS", "--max-time", "5", fmt.Sprintf("http://%s", serverIP))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.ToLower(out)).To(ContainSubstring("welcome to nginx"))
	}).Should(Succeed())
}

// mustPodIP returns a Pod's address and fails the spec when it has
// none yet.
func mustPodIP(namespace string, podName string) string {
	ip, err := podIPOf(namespace, podName)
	Expect(err).NotTo(HaveOccurred())
	Expect(ip).NotTo(BeEmpty())
	return ip
}

// assertPodPortConnectivity requires a HTTP probe to serverPod on the
// given port to answer with wantBody.
func assertPodPortConnectivity(namespace string, clientPod string, serverPod string, port int, wantBody string) {
	address := fmt.Sprintf("%s:%d", mustPodIP(namespace, serverPod), port)

	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--", "curl", "-sS", "--max-time", "5", fmt.Sprintf("http://%s", address))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.ToLower(out)).To(ContainSubstring(wantBody))
	}).Should(Succeed())
}

// assertNoPodConnectivity asserts a HTTP probe from clientPod to serverPod
// fails. We use a short-timeout single-shot probe — success would
// actively contradict the assertion, so retrying only delays real
// regressions.
func assertNoPodConnectivity(namespace string, clientPod string, serverPod string) {
	assertNoPodHTTP(namespace, clientPod, mustPodIP(namespace, serverPod))
}

// assertNoPodPortConnectivity is assertNoPodConnectivity aimed at one
// destination port.
func assertNoPodPortConnectivity(namespace string, clientPod string, serverPod string, port int) {
	assertNoPodHTTP(namespace, clientPod, fmt.Sprintf("%s:%d", mustPodIP(namespace, serverPod), port))
}

func assertNoPodHTTP(namespace string, clientPod string, address string) {
	out, curlErr := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--",
		"curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s", address))
	Expect(curlErr).To(HaveOccurred(), "curl should fail per policy, got: %s", out)
}

// assertPodPing requires every echo request the Pod sends to be
// answered. Demanding zero loss (rather than a single reply) keeps the
// check honest for NAPT: the identifier allocated for the first request
// has to keep matching for the ones that follow.
func assertPodPing(namespace string, podName string, target string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
			"ping", "-c", "3", "-W", "2", target)
		g.Expect(err).NotTo(HaveOccurred(), "ping output: %s", out)
		g.Expect(out).To(ContainSubstring("0% packet loss"), "ping output: %s", out)
	}).Should(Succeed())
}

// assertPodTraceroute requires the first hop of a traceroute started
// inside the Pod to be the given router. Both modes are probed: a UDP
// traceroute quotes a UDP header inside the router's Time Exceeded
// message, an ICMP one quotes an Echo Request, and a NAT has to repair
// either kind.
func assertPodTraceroute(namespace string, podName string, target string, firstHop string) {
	for _, mode := range []struct {
		name string
		args []string
	}{
		{name: "UDP", args: []string{"traceroute", "-n", "-m", "2", "-q", "1", "-w", "2", target}},
		{name: "ICMP", args: []string{"traceroute", "-I", "-n", "-m", "2", "-q", "1", "-w", "2", target}},
	} {
		By(fmt.Sprintf("running a %s traceroute towards %s", mode.name, target))
		args := append([]string{"exec", "-n", namespace, podName, "--"}, mode.args...)
		Eventually(func(g Gomega) {
			out, _ := kubectlOutput(repoRoot, args...)
			g.Expect(out).To(ContainSubstring(firstHop),
				"expected %s as the first hop; traceroute output: %s", firstHop, out)
		}).Should(Succeed())
	}
}

// assertPodLearnsPathMTU sends an oversized DF-set echo and then requires
// the Pod's own route cache to hold the reduced MTU.
//
// The printed report is checked too, because the MTU sits in the outer
// ICMP header whose checksum has to absorb every byte a NAT changed
// inside the quoted packet. But it is not enough on its own: iputils
// matches the report by Echo Identifier, which a 1:1 NAT preserves, so
// the line prints even when the kernel filed the route exception under
// an address the Pod never sends from. Only the route cache shows that
// the quoted header reached the Pod naming the Pod itself.
func assertPodLearnsPathMTU(namespace string, podName string, target string, payload string, mtu int) {
	By(fmt.Sprintf("sending a %s-byte DF-set echo towards %s", payload, target))
	Eventually(func(g Gomega) {
		// A refused oversized ping exits non-zero by design, so the
		// output is the assertion, not the exit status.
		out, _ := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
			"ping", "-M", "do", "-s", payload, "-c", "2", "-W", "2", target)
		g.Expect(out).To(ContainSubstring("Frag needed"),
			"expected a Fragmentation Needed report; ping output: %s", out)
		g.Expect(out).To(ContainSubstring(fmt.Sprintf("mtu = %d", mtu)),
			"expected the router's next-hop MTU; ping output: %s", out)

		route, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
			"ip", "route", "get", target)
		g.Expect(err).NotTo(HaveOccurred(), "ip route get output: %s", route)
		g.Expect(route).To(ContainSubstring(fmt.Sprintf("mtu %d", mtu)),
			"expected the Pod route cache to hold the learned MTU; ip route get output: %s", route)
	}).Should(Succeed())
}

func assertServiceConnectivity(namespace string, clientPod string, serviceName string) {
	clusterIP, err := kubectlJSONPath(repoRoot, `{.spec.clusterIP}`, "-n", namespace, "get", "service", serviceName)
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(clusterIP)).NotTo(BeEmpty())

	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--", "curl", "-sS", "--max-time", "5", fmt.Sprintf("http://%s", strings.TrimSpace(clusterIP)))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.ToLower(out)).To(ContainSubstring("welcome to nginx"))
	}).Should(Succeed())
}

// greProtocol is the IP protocol number of GRE (RFC 2784) and
// icmpProtocol that of ICMP. The policy suites use GRE as the stand-in
// for every protocol outside tcp, udp and icmp.
const (
	greProtocol  = 47
	icmpProtocol = 1
)

// podInterfaceMTU reads the MTU the CNI gave a Pod's primary
// interface. A spec that needs a datagram the sender has to fragment
// sizes it from this rather than from a guess.
func podInterfaceMTU(namespace string, podName string) int {
	out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
		"cat", "/sys/class/net/eth0/mtu")
	Expect(err).NotTo(HaveOccurred(), "reading the Pod MTU: %s", out)
	mtu, err := strconv.Atoi(strings.TrimSpace(out))
	Expect(err).NotTo(HaveOccurred(), "unexpected MTU text: %s", out)
	return mtu
}

// sendGREPackets sends `count` GRE packets from clientPod to target.
// They go out over a raw socket because no ordinary tool speaks a
// protocol the kernel has no stack for, and they carry a real GRE
// header so nothing on the path can turn them away as malformed.
func sendGREPackets(namespace string, clientPod string, target string, count int) {
	script := fmt.Sprintf(`import socket, struct
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, %d)
packet = struct.pack("!HH", 0, 0x0800) + b"juneau-gre-probe"
for _ in range(%d):
    if sock.sendto(packet, ("%s", 0)) != len(packet):
        raise SystemExit("short send")
print("sent", %d)
`, greProtocol, count, target, count)

	out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--", "python3", "-c", script)
	Expect(err).NotTo(HaveOccurred(), "sending GRE packets: %s", out)
	Expect(out).To(ContainSubstring(fmt.Sprintf("sent %d", count)))
}

// sendUDPDatagram sends one UDP datagram of exactly `size` payload
// bytes from clientPod:sourcePort to target:destPort.
func sendUDPDatagram(namespace string, clientPod string, target string, sourcePort int, destPort int, size int) {
	script := fmt.Sprintf(`import socket
payload = b"j" * %d
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", %d))
if sock.sendto(payload, ("%s", %d)) != len(payload):
    raise SystemExit("short send")
print("sent", len(payload))
`, size, sourcePort, target, destPort)

	out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--", "python3", "-c", script)
	Expect(err).NotTo(HaveOccurred(), "sending a %d-byte datagram: %s", size, out)
	Expect(out).To(ContainSubstring(fmt.Sprintf("sent %d", size)))
}

// waitContainerLogLine waits until one container of a Pod has printed
// a line containing want.
func waitContainerLogLine(namespace string, podName string, container string, want string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "logs", "-n", namespace, podName, "-c", container)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring(want))
	}).Should(Succeed())
}

// containerLog returns everything one container of a Pod has printed.
func containerLog(namespace string, podName string, container string) string {
	out, err := kubectlOutput(repoRoot, "logs", "-n", namespace, podName, "-c", container)
	Expect(err).NotTo(HaveOccurred())
	return out
}

func cleanupCaseResources(ctx caseContext) {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", ctx.namespace, "--ignore-not-found=true", "--timeout=60s")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", ctx.serverSubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", ctx.clientSubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", ctx.vpcName, "--ignore-not-found=true")
}
