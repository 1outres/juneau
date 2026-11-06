package e2e

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A RouteTable route via an endpoint sends traffic through a workload
// that forwards it, such as a firewall. The route names the workload by
// its allocation identity, so it follows the workload when a new Pod
// replaces the old one, and it drops the traffic while no Pod of the
// workload is there.
//
// The client Subnet follows a RouteTable of its own. It sends the /32 of
// one server through the router Pod, which forwards it on through the
// main RouteTable of its own Subnet. The other server stays on the
// connected route, so it shows that the rest of the table keeps working.
var _ = Describe("RouteTable route via a workload endpoint", Ordered, func() {
	const (
		routerIdentity = "router"
		clientCIDR     = "10.190.0.0/24"
		routerCIDR     = "10.191.0.0/24"
		serverCIDR     = "10.192.0.0/24"
		routedServer   = "routed-server"
		bystander      = "bystander"
		firstRouter    = "router-a"
		secondRouter   = "router-b"
	)

	var (
		base         string
		namespace    string
		vpc          string
		routeTable   string
		clientSubnet string
		routerSubnet string
		serverSubnet string
		routedDst    string
	)

	BeforeAll(func() {
		base = sanitizeName(fmt.Sprintf("eproute-%d", GinkgoRandomSeed()))
		namespace = "e2e-" + base
		vpc = "vpc-" + base
		routeTable = "rt-client-" + base
		clientSubnet = "subnet-client-" + base
		routerSubnet = "subnet-router-" + base
		serverSubnet = "subnet-server-" + base
		Expect(len(workerNodes)).To(BeNumerically(">=", 2), "the router has to sit on another node than the client")

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", clientSubnet, routerSubnet, serverSubnet, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", routeTable, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpc, "--ignore-not-found=true")
		})

		By("creating a Vpc whose client Subnet follows a RouteTable of its own")
		createNamespace(namespace)
		Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %[1]s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: %[2]s
spec:
  vpc: %[1]s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %[3]s
spec:
  vpc: %[1]s
  cidr: %[4]s
  routeTable: %[2]s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %[5]s
spec:
  vpc: %[1]s
  cidr: %[6]s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %[7]s
spec:
  vpc: %[1]s
  cidr: %[8]s
`, vpc, routeTable, clientSubnet, clientCIDR, routerSubnet, routerCIDR, serverSubnet, serverCIDR))).To(Succeed())
		waitSubnetReady(clientSubnet)
		waitSubnetReady(routerSubnet)
		waitSubnetReady(serverSubnet)

		By("starting the client, the two servers and the first router Pod")
		Expect(applyManifest(podManifest(namespace, clientPodName, workerNodes[0], clientSubnet, false))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, routedServer, workerNodes[0], serverSubnet, true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, bystander, workerNodes[0], serverSubnet, true))).To(Succeed())
		Expect(applyManifest(routerPodManifest(namespace, firstRouter, workerNodes[1], routerSubnet, routerIdentity))).To(Succeed())
		waitPodsReady(namespace, clientPodName, routedServer, bystander, firstRouter)
		waitRouterForwards(namespace, firstRouter)

		By("routing the /32 of one server through the router workload")
		routedDst = mustPodIP(namespace, routedServer) + "/32"
		Expect(run(repoRoot, "kubectl", "patch", "routetable", routeTable, "--type=merge", "-p",
			endpointRoutePatch(routedDst, namespace, routerIdentity))).To(Succeed())
	})

	It("forwards the traffic for the route through the router Pod", func() {
		waitEndpointRoute(routeTable, routedDst, "Active", namespace, firstRouter+"."+podIfaceName)

		before := forwardedDatagrams(namespace, firstRouter)
		assertPodConnectivity(namespace, clientPodName, routedServer)
		Expect(forwardedDatagrams(namespace, firstRouter)).To(BeNumerically(">", before),
			"the router Pod forwarded nothing, so the traffic did not go through it")
	})

	It("drops the traffic for the route while the workload has no Pod, and keeps the other routes", func() {
		Expect(run(repoRoot, "kubectl", "delete", "pod", "-n", namespace, firstRouter, "--wait=true")).To(Succeed())

		waitEndpointRoute(routeTable, routedDst, "Blackhole", "", "")
		waitResourceReady("routetable", routeTable)
		assertPodConnectivityStops(namespace, clientPodName, routedServer)
		assertPodConnectivity(namespace, clientPodName, bystander)
	})

	It("moves the route to the next Pod of the workload", func() {
		Expect(applyManifest(routerPodManifest(namespace, secondRouter, workerNodes[1], routerSubnet, routerIdentity))).To(Succeed())
		waitPodsReady(namespace, secondRouter)
		waitRouterForwards(namespace, secondRouter)

		waitEndpointRoute(routeTable, routedDst, "Active", namespace, secondRouter+"."+podIfaceName)

		before := forwardedDatagrams(namespace, secondRouter)
		assertPodConnectivity(namespace, clientPodName, routedServer)
		Expect(forwardedDatagrams(namespace, secondRouter)).To(BeNumerically(">", before),
			"the new router Pod forwarded nothing, so the route did not move to it")
	})
})

// routerPodManifest builds a Pod of the router workload. It turns IP
// forwarding on in its own network namespace. It also stops sending ICMP
// redirects: the packets it forwards leave through the NIC they came in
// on, and a redirect would only tell the client to skip the router.
func routerPodManifest(namespace, name, nodeName, subnet, identity string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/subnet: %s
    juneau.loutres.me/allocation-identity: %s
spec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: router
      image: %s
      securityContext:
        privileged: true
      command:
        - sh
        - -c
        - |
          sysctl -wq net.ipv4.ip_forward=1
          sysctl -wq net.ipv4.conf.all.send_redirects=0
          sysctl -wq net.ipv4.conf.eth0.send_redirects=0
          exec sleep infinity
`, namespace, name, subnet, identity, nodeName, netshootImage)
}

func endpointRoutePatch(dst, namespace, identity string) string {
	return fmt.Sprintf(`{"spec":{"routes":[{"dst":%q,"via":{"type":"endpoint","endpoint":{"namespace":%q,"allocationIdentity":%q,"interface":%q}}}]}}`,
		dst, namespace, identity, podIfaceName)
}

// waitRouterForwards waits until the router Pod has turned forwarding on.
// The Pod reports Ready as soon as its container starts, which can be
// before the sysctl has run.
func waitRouterForwards(namespace, pod string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, pod, "--", "cat", "/proc/sys/net/ipv4/ip_forward")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(Equal("1"))
	}).Should(Succeed())
}

// waitEndpointRoute waits until the route to dst has the given state and,
// when name is set, has resolved to that NetworkEndpoint.
func waitEndpointRoute(routeTable, dst, state, namespace, name string) {
	Eventually(func(g Gomega) {
		route := func(field string) string {
			out, err := kubectlJSONPath(repoRoot, fmt.Sprintf(`{.status.routes[?(@.dst=="%s")].%s}`, dst, field), "get", "routetable", routeTable)
			g.Expect(err).NotTo(HaveOccurred())
			return strings.TrimSpace(out)
		}
		g.Expect(route("state")).To(Equal(state))
		g.Expect(route("networkEndpoint.namespace")).To(Equal(namespace))
		g.Expect(route("networkEndpoint.name")).To(Equal(name))
		if state == "Blackhole" {
			g.Expect(route("message")).NotTo(BeEmpty())
		}
	}).Should(Succeed())
}

// forwardedDatagrams reads how many IPv4 datagrams the Pod's network
// namespace has forwarded so far (ForwDatagrams in /proc/net/snmp).
func forwardedDatagrams(namespace, pod string) int {
	GinkgoHelper()
	out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, pod, "--", "cat", "/proc/net/snmp")
	Expect(err).NotTo(HaveOccurred())

	var header, values []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Ip:" {
			continue
		}
		if header == nil {
			header = fields
		} else {
			values = fields
			break
		}
	}
	Expect(values).To(HaveLen(len(header)), "unexpected Ip lines in /proc/net/snmp:\n%s", out)
	for i, name := range header {
		if name != "ForwDatagrams" {
			continue
		}
		count, err := strconv.Atoi(values[i])
		Expect(err).NotTo(HaveOccurred())
		return count
	}
	Fail(fmt.Sprintf("no ForwDatagrams in /proc/net/snmp:\n%s", out))
	return 0
}
