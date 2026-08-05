package e2e

import (
	"fmt"
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

func assertPodConnectivity(namespace string, clientPod string, serverPod string) {
	serverIP, err := kubectlJSONPath(repoRoot, `{.status.podIP}`, "-n", namespace, "get", "pod", serverPod)
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(serverIP)).NotTo(BeEmpty())

	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--", "curl", "-sS", "--max-time", "5", fmt.Sprintf("http://%s", strings.TrimSpace(serverIP)))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.ToLower(out)).To(ContainSubstring("welcome to nginx"))
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

func cleanupCaseResources(ctx caseContext) {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", ctx.namespace, "--ignore-not-found=true", "--timeout=60s")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", ctx.serverSubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", ctx.clientSubnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", ctx.vpcName, "--ignore-not-found=true")
}
