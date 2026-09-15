package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The pools here are cluster-scoped and live next to the pools of every
// other spec that runs in parallel, so each spec writes addresses no other
// fixture uses. The AddressPool webhook would reject them otherwise.
const (
	admissionOverlapCIDR       = "203.0.113.192/28"
	admissionOverlapARPRange   = "203.0.113.200-203.0.113.203"
	admissionSharedCIDR        = "203.0.113.208/28"
	elasticIPUseCIDR           = "203.0.113.224/28"
	elasticIPUseNamespace      = "e2e-eip-use"
	elasticIPUseAddressPool    = "e2e-eip-use-pool"
	elasticIPUseExtNetwork     = "e2e-eip-use-extnet"
	elasticIPUseNATEIPName     = "eip-nat"
	elasticIPUseDirectEIPName  = "eip-direct"
	elasticIPUseNATTargetPod   = "nat-target"
	elasticIPUseNATAttachment  = "eip-att-nat"
	elasticIPUseRejectedAttach = "eip-att-direct"
)

var _ = Describe("Juneau address ownership admission", func() {
	// Two AddressPools holding one address could hand it out twice, and
	// the data plane could not tell which ExternalNetwork a packet to it
	// belongs to. The two advertise modes write addresses differently, so
	// the check has to compare a CIDR with a range.
	It("rejects an AddressPool that overlaps another one, across advertise modes", func() {
		base := sanitizeName("pool-overlap")
		holder := "e2e-" + base + "-bgp"
		overlapping := "e2e-" + base + "-arp"
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "addresspool", overlapping, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "addresspool", holder, "--ignore-not-found=true")
		})

		Expect(applyAddressPool(holder, []string{admissionOverlapCIDR})).To(Succeed())

		stderr, err := applyManifestCapturingStderr(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: AddressPool
metadata:
  name: %s
spec:
  advertiseMode: arp
  addresses:
    - %s
`, overlapping, admissionOverlapARPRange))
		Expect(err).To(HaveOccurred(), "an overlapping AddressPool must be rejected; stderr: %s", stderr)
		Expect(stderr).To(ContainSubstring(fmt.Sprintf("overlaps with AddressPool %q", holder)))
		assertResourceAbsent("addresspool", overlapping)
	})

	It("rejects an ExternalNetwork that names an AddressPool another ExternalNetwork holds", func() {
		base := sanitizeName("pool-shared")
		pool := "e2e-" + base
		holder := "e2e-" + base + "-first"
		second := "e2e-" + base + "-second"
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", second, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", holder, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "addresspool", pool, "--ignore-not-found=true")
		})

		Expect(applyAddressPool(pool, []string{admissionSharedCIDR})).To(Succeed())
		Expect(applyExternalNetwork(holder, []string{pool})).To(Succeed())

		stderr, err := applyManifestCapturingStderr(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: ExternalNetwork
metadata:
  name: %s
spec:
  type: bgp
  addressPools:
    - %s
`, second, pool))
		Expect(err).To(HaveOccurred(), "a second ExternalNetwork on the pool must be rejected; stderr: %s", stderr)
		Expect(stderr).To(ContainSubstring(fmt.Sprintf("AddressPool %q is already referenced by ExternalNetwork %q", pool, holder)))
		assertResourceAbsent("externalnetwork", second)
	})
})

// An ElasticIP reserves one address for one use: NAT through an
// ElasticIPAttachment, or a Pod NIC that carries it. These specs need the
// address to exist but not to be reachable, so the ExternalNetwork has no
// BGP peer or advertisement and the specs run in parallel with the rest.
var _ = Describe("Juneau ElasticIP used for NAT or carried by a Pod", Ordered, func() {
	var (
		directPod     directElasticIPPod
		directAddress string
	)

	BeforeAll(func() {
		By("creating an ExternalNetwork with two ElasticIPs")
		Expect(applyAddressPool(elasticIPUseAddressPool, []string{elasticIPUseCIDR})).To(Succeed())
		Expect(applyExternalNetwork(elasticIPUseExtNetwork, []string{elasticIPUseAddressPool})).To(Succeed())
		createNamespace(elasticIPUseNamespace)
		Expect(applyElasticIP(elasticIPUseNamespace, elasticIPUseNATEIPName, elasticIPUseExtNetwork)).To(Succeed())
		Expect(applyElasticIP(elasticIPUseNamespace, elasticIPUseDirectEIPName, elasticIPUseExtNetwork)).To(Succeed())
		waitElasticIPAddress(elasticIPUseNamespace, elasticIPUseNATEIPName)

		By("using the first ElasticIP for NAT to a Subnet Pod")
		Expect(applyManifest(podManifest(elasticIPUseNamespace, elasticIPUseNATTargetPod, workerNodes[0], defaultSubnetName, true))).To(Succeed())
		waitPodsReady(elasticIPUseNamespace, elasticIPUseNATTargetPod)
		Expect(applyElasticIPAttachment(elasticIPUseNamespace, elasticIPUseNATAttachment, elasticIPUseNATEIPName,
			elasticIPUseNATTargetPod+"."+podIfaceName)).To(Succeed())

		By("carrying the second ElasticIP on the eth0 of another Pod")
		directPod = directElasticIPPod{namespace: elasticIPUseNamespace, name: "direct", node: workerNodes[0], nic: podIfaceName, elasticIP: elasticIPUseDirectEIPName}
		directAddress = directPod.create()
	})

	AfterAll(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "elasticipattachment", "-n", elasticIPUseNamespace, elasticIPUseNATAttachment, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", elasticIPUseNamespace, "--ignore-not-found=true", "--timeout=120s")
		runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", elasticIPUseExtNetwork, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "addresspool", elasticIPUseAddressPool, "--ignore-not-found=true")
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		dumpResource("elasticipattachments", "-n", elasticIPUseNamespace, "-o", "yaml")
		dumpResource("allocationclaims.juneau.loutres.me", "-o", "yaml")
		dumpElasticIPDirectDiagnostics(elasticIPUseNamespace)
	})

	It("rejects a Pod that names an ElasticIP an ElasticIPAttachment uses", func() {
		rejected := directElasticIPPod{namespace: elasticIPUseNamespace, name: "wants-nat-eip", node: workerNodes[0], nic: podIfaceName, elasticIP: elasticIPUseNATEIPName}
		stderr, err := applyManifestCapturingStderr(rejected.manifest())
		Expect(err).To(HaveOccurred(), "the Pod must be rejected; stderr: %s", stderr)
		Expect(stderr).To(ContainSubstring(fmt.Sprintf("ElasticIP %q is used by ElasticIPAttachment %q", elasticIPUseNATEIPName, elasticIPUseNATAttachment)))
		assertResourceAbsent("pod", rejected.name, "-n", elasticIPUseNamespace)
	})

	It("rejects an ElasticIPAttachment for an ElasticIP a Pod carries", func() {
		stderr, err := applyManifestCapturingStderr(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: ElasticIPAttachment
metadata:
  namespace: %s
  name: %s
spec:
  elasticIPRef:
    name: %s
  targetRef:
    networkInterfaceName: %s
`, elasticIPUseNamespace, elasticIPUseRejectedAttach, elasticIPUseDirectEIPName, elasticIPUseNATTargetPod+"."+podIfaceName))
		Expect(err).To(HaveOccurred(), "the ElasticIPAttachment must be rejected; stderr: %s", stderr)
		Expect(stderr).To(ContainSubstring(fmt.Sprintf("ElasticIP is used directly by NetworkInterface %q", directPod.networkInterfaceName())))
		assertResourceAbsent("elasticipattachment", elasticIPUseRejectedAttach, "-n", elasticIPUseNamespace)
	})

	// Releasing the address while a NIC still holds it would let another
	// ElasticIP take an address that is live on a Pod. So the ElasticIP
	// waits, says why, and keeps its AllocationClaim until the Pod is gone.
	It("keeps a deleted ElasticIP and its address while a Pod carries it, and finishes once the Pod is gone", func() {
		claim := elasticIPAllocationClaimName(elasticIPUseNamespace, elasticIPUseDirectEIPName)

		By(fmt.Sprintf("deleting ElasticIP %s while %s carries it", elasticIPUseDirectEIPName, directPod.networkInterfaceName()))
		Expect(run(repoRoot, "kubectl", "delete", "elasticip", "-n", elasticIPUseNamespace, elasticIPUseDirectEIPName, "--wait=false")).To(Succeed())

		Eventually(func(g Gomega) {
			out, err := kubectlJSONPath(repoRoot,
				`{.status.conditions[?(@.type=="Allocated")].reason}`,
				"-n", elasticIPUseNamespace, "get", "elasticip", elasticIPUseDirectEIPName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("WaitingForNetworkInterfaces"))
		}).Should(Succeed())

		Consistently(func(g Gomega) {
			out, err := kubectlJSONPath(repoRoot,
				`{.metadata.deletionTimestamp} {.status.address} {.status.conditions[?(@.type=="Allocated")].message}`,
				"-n", elasticIPUseNamespace, "get", "elasticip", elasticIPUseDirectEIPName)
			g.Expect(err).NotTo(HaveOccurred(), "the ElasticIP must still exist while a Pod carries it")
			fields := strings.Fields(out)
			g.Expect(len(fields)).To(BeNumerically(">=", 2), "elasticip output: %s", out)
			g.Expect(fields[1]).To(Equal(directAddress), "the ElasticIP must keep its address")
			g.Expect(out).To(ContainSubstring(directPod.networkInterfaceName()), "the condition must name the NetworkInterface it waits for")

			claimIP, err := kubectlJSONPath(repoRoot, `{.status.value.ip}`, "get", "allocationclaim", claim)
			g.Expect(err).NotTo(HaveOccurred(), "the AllocationClaim must stay while a Pod carries the address")
			g.Expect(strings.TrimSpace(claimIP)).To(Equal(directAddress))

			carried, err := kubectlJSONPath(repoRoot, `{.status.address}`, "-n", elasticIPUseNamespace, "get", "networkinterface", directPod.networkInterfaceName())
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(carried)).To(Equal(directAddress + "/32"))
		}, "20s", "4s").Should(Succeed())

		By(fmt.Sprintf("deleting Pod %s", directPod.name))
		Expect(run(repoRoot, "kubectl", "delete", "pod", "-n", elasticIPUseNamespace, directPod.name, "--wait=true", "--timeout=120s")).To(Succeed())

		assertResourceGone("elasticip", elasticIPUseDirectEIPName, "-n", elasticIPUseNamespace)
		assertResourceGone("allocationclaim", claim)
	})
})

// elasticIPAllocationClaimName mirrors elasticIPClaimName in the controller:
// pool "elasticip", kind, namespace, name and attribute joined by "--".
func elasticIPAllocationClaimName(namespace, name string) string {
	return strings.Join([]string{"elasticip", "elasticip", namespace, name, "status-address"}, "--")
}

// assertResourceAbsent requires a rejected object not to exist. A single
// read is enough: the request that would have created it already failed.
func assertResourceAbsent(resource, name string, args ...string) {
	GinkgoHelper()
	out, err := kubectlOutput(repoRoot, append([]string{"get", resource, name, "--ignore-not-found=true", "-o", "name"}, args...)...)
	Expect(err).NotTo(HaveOccurred())
	Expect(out).To(BeEmpty(), "%s %s should not exist", resource, name)
}

func assertResourceGone(resource, name string, args ...string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, append([]string{"get", resource, name, "--ignore-not-found=true", "-o", "name"}, args...)...)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(BeEmpty(), "%s %s should be gone", resource, name)
	}).Should(Succeed())
}
