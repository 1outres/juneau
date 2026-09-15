package e2e

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	// These mirror api/v1alpha1/podelasticip.go. The e2e module is a
	// separate Go module and does not import the API.
	directElasticIPGateway      = "169.254.0.1"
	directElasticIPRulePriority = 100

	directServerContainer = "server"
	directClientContainer = "client"

	directServerBody = "welcome to nginx"
)

// directElasticIPPod is a Pod one of whose NICs carries an ElasticIP
// directly. On eth0 the Pod joins no Subnet at all. On any other NIC the
// Pod keeps its eth0 on the default Subnet and adds the NIC next to it.
//
// The Pod runs nginx, with a readiness probe, next to a netshoot container
// that the specs run their clients from. Both share the Pod's network
// namespace, so the client speaks from the addresses the server answers on.
type directElasticIPPod struct {
	namespace string
	name      string
	node      string
	nic       string
	elasticIP string
}

func (p directElasticIPPod) networkInterfaceName() string {
	return p.name + "." + p.nic
}

func (p directElasticIPPod) manifest() string {
	annotation := fmt.Sprintf("    juneau.loutres.me/elastic-ip: %s\n", p.elasticIP)
	if p.nic != podIfaceName {
		annotation = fmt.Sprintf("    juneau.loutres.me/networks: |\n      [{\"interface\": %q, \"elasticIP\": %q}]\n",
			p.nic, p.elasticIP)
	}

	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  labels:
    app: %s
  annotations:
%sspec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: %s
      image: nginx:1.27
      ports:
        - containerPort: 80
      readinessProbe:
        httpGet:
          path: /
          port: 80
        initialDelaySeconds: 1
        periodSeconds: 2
        failureThreshold: 1
    - name: %s
      image: %s
      command: ["sleep", "3600"]
`, p.namespace, p.name, p.name, annotation, p.node,
		directServerContainer, directClientContainer, netshootImage)
}

// create starts the Pod and waits until it is Ready and its NIC holds the
// ElasticIP. It returns the address the NIC carries.
func (p directElasticIPPod) create() string {
	GinkgoHelper()
	By(fmt.Sprintf("creating Pod %s/%s on %s with ElasticIP %s on %s", p.namespace, p.name, p.node, p.elasticIP, p.nic))
	Expect(applyManifest(p.manifest())).To(Succeed())
	waitPodsReady(p.namespace, p.name)
	assertPodPlacement(p.namespace, p.name, p.node)
	waitElasticIPCarriedBy(p.namespace, p.elasticIP, p.networkInterfaceName())
	return waitElasticIPAddress(p.namespace, p.elasticIP)
}

// clientExec runs a command in the netshoot container of the Pod.
func (p directElasticIPPod) clientExec(args ...string) (string, error) {
	return kubectlOutput(repoRoot, append([]string{"exec", "-n", p.namespace, p.name, "-c", directClientContainer, "--"}, args...)...)
}

// waitElasticIPCarriedBy waits until the ElasticIP names the
// NetworkInterface as what uses it.
func waitElasticIPCarriedBy(namespace, elasticIP, networkInterface string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := kubectlJSONPath(repoRoot, `{.status.phase} {.status.attachment.kind} {.status.attachment.name}`,
			"-n", namespace, "get", "elasticip", elasticIP)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.Fields(out)).To(Equal([]string{"Attached", "NetworkInterface", networkInterface}),
			"elasticip %s phase, attachment kind and name", elasticIP)
	}).Should(Succeed())
}

// assertDirectElasticIPInterface requires every layer to agree that the NIC
// carries the address itself: the NetworkInterface, the NetworkEndpoint the
// daemon wrote for it, and the interface inside the Pod.
func assertDirectElasticIPInterface(pod directElasticIPPod, address, externalNetwork string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := kubectlJSONPath(repoRoot, `{.spec.elasticIP} {.status.address} {.spec.subnet}{.spec.l2Network}`,
			"-n", pod.namespace, "get", "networkinterface", pod.networkInterfaceName())
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.Fields(out)).To(Equal([]string{pod.elasticIP, address + "/32"}),
			"networkinterface %s elasticIP, address, and no subnet or l2Network", pod.networkInterfaceName())

		out, err = kubectlJSONPath(repoRoot, `{.spec.externalNetwork} {.spec.address} {.spec.subnet}{.spec.l2Network}`,
			"-n", pod.namespace, "get", "networkendpoint", pod.networkInterfaceName())
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.Fields(out)).To(Equal([]string{externalNetwork, address + "/32"}),
			"networkendpoint %s externalNetwork, address, and no subnet or l2Network", pod.networkInterfaceName())

		out, err = pod.clientExec("ip", "-o", "-4", "addr", "show", "dev", pod.nic)
		g.Expect(err).NotTo(HaveOccurred(), "ip addr output: %s", out)
		g.Expect(out).To(ContainSubstring("inet "+address+"/32 "), "ip addr output: %s", out)
	}).Should(Succeed())
}

// assertDirectElasticIPRouting requires the routes a NIC on an ElasticIP
// gets. It holds only a /32, so its way out is an onlink default route to
// the gateway the node answers ARP for. eth0 keeps that route in the main
// table. Any other NIC keeps it in a table of its own and reaches it only
// from its own address, so a reply to that address leaves the NIC it came in
// on while everything else still leaves eth0.
func assertDirectElasticIPRouting(pod directElasticIPPod, address string) {
	GinkgoHelper()
	defaultRoute := fmt.Sprintf("default via %s dev %s onlink", directElasticIPGateway, pod.nic)

	if pod.nic == podIfaceName {
		Eventually(func(g Gomega) {
			out, err := pod.clientExec("ip", "-4", "route", "show", "default")
			g.Expect(err).NotTo(HaveOccurred(), "ip route output: %s", out)
			g.Expect(strings.TrimSpace(out)).To(Equal(defaultRoute), "ip route output: %s", out)
		}).Should(Succeed())
		return
	}

	table := directElasticIPRouteTable(address)
	Eventually(func(g Gomega) {
		out, err := pod.clientExec("ip", "-4", "rule", "show", "priority", strconv.Itoa(directElasticIPRulePriority))
		g.Expect(err).NotTo(HaveOccurred(), "ip rule output: %s", out)
		g.Expect(out).To(ContainSubstring(fmt.Sprintf("from %s lookup %d", address, table)), "ip rule output: %s", out)

		out, err = pod.clientExec("ip", "-4", "route", "show", "table", strconv.FormatUint(uint64(table), 10))
		g.Expect(err).NotTo(HaveOccurred(), "ip route output: %s", out)
		g.Expect(strings.TrimSpace(out)).To(Equal(defaultRoute), "ip route table %d output: %s", table, out)

		out, err = pod.clientExec("ip", "-4", "route", "show", "default")
		g.Expect(err).NotTo(HaveOccurred(), "ip route output: %s", out)
		g.Expect(out).To(ContainSubstring("dev "+podIfaceName), "the main table must keep eth0 as the way out: %s", out)
		g.Expect(out).NotTo(ContainSubstring("dev "+pod.nic), "the main table must not route through %s: %s", pod.nic, out)
	}).Should(Succeed())
}

// directElasticIPRouteTable mirrors v1alpha1.PodElasticIPRouteTable: the
// table number is the IPv4 address read as a big-endian number.
func directElasticIPRouteTable(address string) uint32 {
	GinkgoHelper()
	ip := net.ParseIP(address).To4()
	Expect(ip).NotTo(BeNil(), "%q is not an IPv4 address", address)
	return binary.BigEndian.Uint32(ip)
}

// assertPodCurlFrom requires a request the Pod sends from source to answer
// with want. Binding the source is what picks the NIC: the policy rule of
// an extra NIC matches on its address.
func assertPodCurlFrom(pod directElasticIPPod, source, url, want string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := pod.clientExec("curl", "-sS", "--max-time", "5", "--interface", source, url)
		g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
		g.Expect(strings.ToLower(out)).To(ContainSubstring(want), "curl body: %s", out)
	}).Should(Succeed())
}

// assertAnsweredFromNIC requires the NIC to send at least the body of the
// answer while request fetches it from outside. The route inside the Pod
// already says which NIC a reply should leave; the counter shows it did,
// since nothing else sends that many bytes on the NIC.
func assertAnsweredFromNIC(pod directElasticIPPod, request func() (string, error)) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		before := podInterfaceTxBytes(g, pod)
		out, err := request()
		g.Expect(err).NotTo(HaveOccurred(), "request output: %s", out)
		g.Expect(strings.ToLower(out)).To(ContainSubstring(directServerBody), "request body: %s", out)
		after := podInterfaceTxBytes(g, pod)
		g.Expect(after-before).To(BeNumerically(">=", len(out)),
			"%s sent %d bytes while answering a %d-byte body", pod.nic, after-before, len(out))
	}, "90s", "3s").Should(Succeed())
}

func podInterfaceTxBytes(g Gomega, pod directElasticIPPod) uint64 {
	out, err := pod.clientExec("cat", "/sys/class/net/"+pod.nic+"/statistics/tx_bytes")
	g.Expect(err).NotTo(HaveOccurred(), "tx_bytes output: %s", out)
	value, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	g.Expect(err).NotTo(HaveOccurred(), "tx_bytes output: %s", out)
	return value
}

// assertPodServerSaw requires the nginx access log of the Pod to hold a
// request from source. A NIC on an ElasticIP sits behind no NAT, so the
// server sees the address the client really sent from.
func assertPodServerSaw(namespace, podName, source string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "logs", "-n", namespace, podName, "-c", directServerContainer)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring(source+" - "), "nginx access log of %s should record a request from %s", podName, source)
	}).Should(Succeed())
}

// assertNodeRoutesToPod requires the node to route the address of an eth0
// on an ElasticIP straight to the host side of the Pod's veth. That route is
// how the kubelet reaches such a Pod.
func assertNodeRoutesToPod(node, address string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := dockerExecOutput(node, "ip", "-4", "route", "show", address+"/32")
		g.Expect(err).NotTo(HaveOccurred(), "ip route output: %s", out)
		g.Expect(out).To(MatchRegexp(`^`+regexpQuoteIPv4(address)+` dev `+podIfaceName+`\+\S+ scope link`),
			"node %s route to %s: %s", node, address, out)
	}).Should(Succeed())
}

const (
	// juneauVXLANIfaceName mirrors the device the daemon's bootstrap creates
	// on every node.
	juneauVXLANIfaceName = "juneau_vxlan"

	// tcpRequestMinPackets is what the client side of one HTTP request over
	// a fresh connection sends at least: SYN, the ACK of SYN-ACK, the
	// request, and the FIN.
	tcpRequestMinPackets = 4
)

// nodeVXLANTxPackets reads how many packets the node has sent into the
// overlay.
func nodeVXLANTxPackets(g Gomega, node string) uint64 {
	out, err := dockerExecOutput(node, "cat", "/sys/class/net/"+juneauVXLANIfaceName+"/statistics/tx_packets")
	g.Expect(err).NotTo(HaveOccurred(), "tx_packets output: %s", out)
	value, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	g.Expect(err).NotTo(HaveOccurred(), "tx_packets output: %s", out)
	return value
}

func regexpQuoteIPv4(address string) string {
	return strings.ReplaceAll(address, ".", `\.`)
}

func dumpElasticIPDirectDiagnostics(namespace string) {
	dumpResource("elasticips", "-A", "-o", "yaml")
	dumpResource("networkinterfaces.juneau.loutres.me", "-n", namespace, "-o", "yaml")
	dumpResource("networkendpoints.juneau.loutres.me", "-n", namespace, "-o", "yaml")
	dumpResource("externalnetworks", "-o", "yaml")
	dumpDescribe("pods", "-n", namespace)
}
