package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	l2NetworkMTU = 1400

	l2ClientPod = "l2-client"
	l2ServerPod = "l2-server"
	l2ExtraIf   = "eth1"

	// Addresses juneau knows nothing about. The pods put them on the
	// segment themselves, which is the whole point of an L2Network
	// without a CIDR.
	l2ClientAddress = "192.168.60.1"
	l2ServerAddress = "192.168.60.2"
	l2ClientV6      = "fd00:0:0:60::1"
	l2ServerV6      = "fd00:0:0:60::2"

	l2ServerNewMAC = "02:00:00:aa:bb:cc"

	l2Eth0Namespace   = "e2e-l2-eth0"
	l2Eth0Vpc         = "vpc-l2-eth0"
	l2Eth0Subnet      = "subnet-l2-eth0"
	l2Eth0SubnetCIDR  = "10.243.0.0/24"
	l2Eth0NetworkName = "l2net-eth0"
	l2Eth0NetworkCIDR = "10.244.0.0/24"
	l2Eth0Gateway     = "10.244.0.1"
	l2Eth0ClientPod   = "l2-eth0-client"
	l2Eth0ServerPod   = "l2-eth0-server"
)

var _ = Describe("Juneau L2Network", func() {
	BeforeEach(func() {
		Expect(len(workerNodes)).To(BeNumerically(">=", 2), "these specs need at least 2 worker nodes")
	})

	It("carries a segment the pods address themselves, across nodes", func() {
		f := newL2Fixture("l2-self-addressed")
		f.create()

		By("checking juneau built runtime resources naming the L2Network")
		assertPodNICL2Network(f.namespace, l2ClientPod, l2ExtraIf, f.network)
		assertPodNICL2Network(f.namespace, l2ServerPod, l2ExtraIf, f.network)

		By("checking the extra NIC came up without an address")
		assertPodInterfaceHasNoAddress(f.namespace, l2ClientPod, l2ExtraIf)

		By("checking the extra NIC took the MTU of the segment")
		assertPodInterfaceMTU(f.namespace, l2ClientPod, l2ExtraIf, l2NetworkMTU)
		assertPodInterfaceMTU(f.namespace, l2ServerPod, l2ExtraIf, l2NetworkMTU)

		By("checking eth0 kept the address and the MTU it always had")
		address := mustPodIP(f.namespace, l2ClientPod)
		Expect(addressInCIDR(f.subnetCIDR, address)).To(BeTrue(), "Pod IP %s should come from %s", address, f.subnetCIDR)
		assertPodInterfaceMTU(f.namespace, l2ClientPod, podIfaceName, 1500)

		By("addressing the segment from inside the pods")
		addPodAddress(f.namespace, l2ClientPod, l2ExtraIf, l2ClientAddress+"/24")
		addPodAddress(f.namespace, l2ServerPod, l2ExtraIf, l2ServerAddress+"/24")

		By("reaching the other node over the segment")
		assertPodPing(f.namespace, l2ClientPod, l2ServerAddress)
		assertPodPing(f.namespace, l2ServerPod, l2ClientAddress)
	})

	It("carries an EtherType a Subnet would not", func() {
		f := newL2Fixture("l2-ipv6")
		f.create()

		By("addressing the segment with IPv6 only")
		addPodAddress(f.namespace, l2ClientPod, l2ExtraIf, l2ClientV6+"/64")
		addPodAddress(f.namespace, l2ServerPod, l2ExtraIf, l2ServerV6+"/64")

		// Neighbor discovery rides on IPv6 multicast (33:33:*), which
		// the segment floods like any other BUM frame. juneau has no
		// IPv6 support of its own, so a reply here means the data plane
		// never looked at the ethertype.
		By("reaching the other node over IPv6")
		assertPodPing6(f.namespace, l2ClientPod, l2ServerV6)
	})

	It("follows a MAC that changes on the segment", func() {
		f := newL2Fixture("l2-mac-change")
		f.create()

		addPodAddress(f.namespace, l2ClientPod, l2ExtraIf, l2ClientAddress+"/24")
		addPodAddress(f.namespace, l2ServerPod, l2ExtraIf, l2ServerAddress+"/24")
		assertPodPing(f.namespace, l2ClientPod, l2ServerAddress)

		By("giving the server NIC a MAC juneau never handed out")
		setPodInterfaceMAC(f.namespace, l2ServerPod, l2ExtraIf, l2ServerNewMAC)
		flushPodNeighbours(f.namespace, l2ClientPod, l2ExtraIf)

		// Nothing in the API says the MAC changed. The segment learns
		// it from the first frame the server sends under it, which is
		// the ARP reply to the client.
		By("reaching the server again under its new MAC")
		assertPodPing(f.namespace, l2ClientPod, l2ServerAddress)
	})

	// A Pod whose eth0 sits on a segment with an address and a gateway
	// lives in the Vpc without a Subnet. The gateway is its only way to the
	// rest of the Vpc, and the cluster DNS Service cannot be reached from a
	// Vpc, so the Pod resolves names through the node.
	It("gives eth0 an address and a default route through the gateway of the segment", func() {
		By("creating a VPC with a Subnet and an L2Network that has a CIDR and a gateway")
		Expect(applyManifest(l2Eth0NetworkManifest())).To(Succeed())
		DeferCleanup(cleanupL2Eth0Resources)
		waitSubnetReady(l2Eth0Subnet)
		waitResourceReady("l2network", l2Eth0NetworkName)

		createNamespace(l2Eth0Namespace)

		By("creating a Pod with eth0 on the segment and a server on the Subnet of another node")
		Expect(applyManifest(l2Eth0ClientManifest(workerNodes[0]))).To(Succeed())
		Expect(applyManifest(podManifest(l2Eth0Namespace, l2Eth0ServerPod, workerNodes[1], l2Eth0Subnet, true))).To(Succeed())
		waitPodsReady(l2Eth0Namespace, l2Eth0ClientPod, l2Eth0ServerPod)

		By("checking eth0 joined the L2Network and took an address of its CIDR")
		assertPodNICL2Network(l2Eth0Namespace, l2Eth0ClientPod, podIfaceName, l2Eth0NetworkName)
		address := mustPodIP(l2Eth0Namespace, l2Eth0ClientPod)
		Expect(addressInCIDR(l2Eth0NetworkCIDR, address)).To(BeTrue(), "Pod IP %s should come from %s", address, l2Eth0NetworkCIDR)
		assertPodInterfaceAddress(l2Eth0Namespace, l2Eth0ClientPod, podIfaceName, address)

		By("checking the default route goes through the gateway")
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", l2Eth0Namespace, l2Eth0ClientPod, "--", "ip", "-4", "route", "show", "default")
			g.Expect(err).NotTo(HaveOccurred(), "ip route output: %s", out)
			g.Expect(strings.TrimSpace(out)).To(HavePrefix(fmt.Sprintf("default via %s dev %s", l2Eth0Gateway, podIfaceName)), "ip route output: %s", out)
		}).Should(Succeed())

		By("checking the Pod resolves names through the node")
		dnsPolicy, err := kubectlJSONPath(repoRoot, `{.spec.dnsPolicy}`, "-n", l2Eth0Namespace, "get", "pod", l2Eth0ClientPod)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(dnsPolicy)).To(Equal("Default"))

		By("reaching the server on the Subnet through the gateway")
		assertPodConnectivity(l2Eth0Namespace, l2Eth0ClientPod, l2Eth0ServerPod)
	})
})

// l2Fixture names the objects of one L2Network spec. Every spec gets its
// own set so specs can run in parallel.
type l2Fixture struct {
	namespace  string
	vpc        string
	subnet     string
	subnetCIDR string
	network    string
}

func newL2Fixture(name string) l2Fixture {
	base := sanitizeName(name)
	return l2Fixture{
		namespace:  "e2e-" + base,
		vpc:        "vpc-" + base,
		subnet:     "subnet-" + base,
		subnetCIDR: cidrForScenario(base, 0),
		network:    "l2net-" + base,
	}
}

// create builds the VPC, the subnet eth0 sits on, the L2Network, and one
// pod per worker node with a second NIC on the segment.
func (f l2Fixture) create() {
	GinkgoHelper()
	By("creating a VPC, a subnet for eth0 and an L2Network without a CIDR")
	Expect(applyManifest(f.networkManifest())).To(Succeed())
	DeferCleanup(f.cleanup)
	waitSubnetReady(f.subnet)
	waitResourceReady("l2network", f.network)

	createNamespace(f.namespace)

	By("creating two pods on different nodes with a second NIC on the segment")
	Expect(applyManifest(f.podManifest(l2ClientPod, workerNodes[0]))).To(Succeed())
	Expect(applyManifest(f.podManifest(l2ServerPod, workerNodes[1]))).To(Succeed())
	waitPodsReady(f.namespace, l2ClientPod, l2ServerPod)
}

// assertPodNICL2Network requires both runtime resources of one NIC to
// name the L2Network it joined.
func assertPodNICL2Network(namespace string, podName string, ifName string, expected string) {
	Eventually(func(g Gomega) {
		nwiface, err := kubectlJSONPath(repoRoot, `{.spec.l2Network}`, "-n", namespace, "get", "networkinterface", podName+"."+ifName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(nwiface)).To(Equal(expected))

		nwep, err := kubectlJSONPath(repoRoot, `{.spec.l2Network}`, "-n", namespace, "get", "networkendpoint", podName+"."+ifName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(nwep)).To(Equal(expected))
	}).Should(Succeed())
}

// assertPodInterfaceHasNoAddress requires the NIC to exist and carry no
// IPv4 address. An L2Network without a CIDR hands out none, and the
// sandbox has to come up anyway.
func assertPodInterfaceHasNoAddress(namespace string, podName string, ifName string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--", "ip", "-o", "-4", "addr", "show", ifName)
		g.Expect(err).NotTo(HaveOccurred(), "ip addr output: %s", out)
		g.Expect(strings.TrimSpace(out)).To(BeEmpty(), "ip addr output: %s", out)
	}).Should(Succeed())
}

func assertPodInterfaceMTU(namespace string, podName string, ifName string, mtu int) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
			"cat", "/sys/class/net/"+ifName+"/mtu")
		g.Expect(err).NotTo(HaveOccurred(), "mtu output: %s", out)
		g.Expect(strings.TrimSpace(out)).To(Equal(fmt.Sprintf("%d", mtu)))
	}).Should(Succeed())
}

func addPodAddress(namespace string, podName string, ifName string, address string) {
	GinkgoHelper()
	out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
		"ip", "addr", "add", address, "dev", ifName)
	Expect(err).NotTo(HaveOccurred(), "ip addr add output: %s", out)
}

func setPodInterfaceMAC(namespace string, podName string, ifName string, mac string) {
	GinkgoHelper()
	for _, args := range [][]string{
		{"ip", "link", "set", "dev", ifName, "down"},
		{"ip", "link", "set", "dev", ifName, "address", mac},
		{"ip", "link", "set", "dev", ifName, "up"},
	} {
		out, err := kubectlOutput(repoRoot, append([]string{"exec", "-n", namespace, podName, "--"}, args...)...)
		Expect(err).NotTo(HaveOccurred(), "%v output: %s", args, out)
	}
}

func flushPodNeighbours(namespace string, podName string, ifName string) {
	GinkgoHelper()
	out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
		"ip", "neigh", "flush", "dev", ifName)
	Expect(err).NotTo(HaveOccurred(), "ip neigh flush output: %s", out)
}

// assertPodPing6 is assertPodPing over IPv6. The whole run is retried
// because duplicate address detection has to finish before the first
// echo can leave.
func assertPodPing6(namespace string, podName string, target string) {
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, podName, "--",
			"ping", "-6", "-c", "3", "-W", "2", target)
		g.Expect(err).NotTo(HaveOccurred(), "ping output: %s", out)
		g.Expect(out).To(ContainSubstring("0% packet loss"), "ping output: %s", out)
	}).Should(Succeed())
}

func (f l2Fixture) networkManifest() string {
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
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
kind: L2Network
metadata:
  name: %s
spec:
  vpc: %s
  mtu: %d
`, f.vpc, f.subnet, f.vpc, f.subnetCIDR, f.network, f.vpc, l2NetworkMTU)
}

func (f l2Fixture) podManifest(podName string, nodeName string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/subnet: %s
    juneau.loutres.me/networks: |
      [{"interface": "%s", "l2Network": "%s"}]
spec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: shell
      image: %s
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add: ["NET_ADMIN"]
`, f.namespace, podName, f.subnet, l2ExtraIf, f.network, nodeName, netshootImage)
}

func l2Eth0NetworkManifest() string {
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
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
kind: L2Network
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
  gateway:
    address: %s
`, l2Eth0Vpc, l2Eth0Subnet, l2Eth0Vpc, l2Eth0SubnetCIDR, l2Eth0NetworkName, l2Eth0Vpc, l2Eth0NetworkCIDR, l2Eth0Gateway)
}

func l2Eth0ClientManifest(nodeName string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/networks: |
      [{"interface": "%s", "l2Network": "%s"}]
spec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: client
      image: %s
      command: ["sleep", "3600"]
`, l2Eth0Namespace, l2Eth0ClientPod, podIfaceName, l2Eth0NetworkName, nodeName, netshootImage)
}

func cleanupL2Eth0Resources() {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", l2Eth0Namespace, "--ignore-not-found=true", "--timeout=60s")
	runBestEffort(repoRoot, "kubectl", "delete", "l2network", l2Eth0NetworkName, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", l2Eth0Subnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", l2Eth0Vpc, "--ignore-not-found=true")
}

func (f l2Fixture) cleanup() {
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", f.namespace, "--ignore-not-found=true", "--timeout=60s")
	runBestEffort(repoRoot, "kubectl", "delete", "l2network", f.network, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", f.subnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", f.vpc, "--ignore-not-found=true")
}
