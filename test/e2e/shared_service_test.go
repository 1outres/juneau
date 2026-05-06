package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Cross-Vpc shared Service end-to-end tests. The data plane path under
// test is:
//
//   - pod_egress.handle_service_shared on the caller's Node (forward
//     SNAT+DNAT, CT install)
//   - pod_egress.apply_conntrack_svc_shared_in on the *backend's* Node
//     when the same Node hosts both legs (same-Node reply leg)
//   - vxlan_ingress's SVC_SHARED_IN leg when the legs sit on different
//     Nodes (cross-Node reply leg)
//
// The "shared Service" feature now factors into three orthogonal
// capabilities exercised by the cases below:
//
//   - Provider role: the owner Vpc has spec.service.provider.natSourceSubnet
//     configured, which tells the controller to fan out per-Node SNAT
//     IPs from that Subnet's pool.
//   - Consume role: the caller Vpc has spec.service.consume=true, which
//     gates whether its Pods can reach shared Services in other Vpcs.
//   - Per-Service ACL: the optional
//     juneau.loutres.me/shared-service-allowed-consumer-vpcs annotation
//     restricts which caller Vpcs may reach a particular Service.
//
// The forward-direction tests (S-dp-1, S-dp-2) use the default Vpc as
// the provider. The reverse-direction tests (S-dp-5, S-dp-6) flip the
// roles so the provider is a tenant Vpc and the caller is the default
// Vpc — the symmetric path that the per-(Node, Vpc) ServiceNATAttachment
// fan-out enables.

type sharedSvcPlacement string

const (
	sharedSvcSameNode sharedSvcPlacement = "same-node"
	sharedSvcDiffNode sharedSvcPlacement = "diff-node"
)

type sharedSvcScenario struct {
	name      string
	placement sharedSvcPlacement
}

var _ = Describe("Juneau shared Service", func() {
	DescribeTable("dataplane: caller Vpc reaches default-Vpc backend through SVC_SHARED",
		func(s sharedSvcScenario) {
			runSharedServiceForwardScenario(s)
		},
		Entry("S-dp-1: caller and backend on same node",
			sharedSvcScenario{name: "shared-svc-same-node", placement: sharedSvcSameNode}),
		Entry("S-dp-2: caller and backend on different nodes",
			sharedSvcScenario{name: "shared-svc-diff-node", placement: sharedSvcDiffNode}),
	)

	DescribeTable("dataplane: default Vpc reaches tenant-Vpc backend through SVC_SHARED",
		func(s sharedSvcScenario) {
			runSharedServiceReverseScenario(s)
		},
		Entry("S-dp-5: caller (default Vpc) and backend (tenant Vpc) on same node",
			sharedSvcScenario{name: "shared-svc-rev-same-node", placement: sharedSvcSameNode}),
		Entry("S-dp-6: caller (default Vpc) and backend (tenant Vpc) on different nodes",
			sharedSvcScenario{name: "shared-svc-rev-diff-node", placement: sharedSvcDiffNode}),
	)

	It("S-dp-7: a Service ACL whitelist admits listed Vpcs and rejects others", func() {
		runSharedServiceACLScenario()
	})
})

func runSharedServiceForwardScenario(s sharedSvcScenario) {
	Expect(len(workerNodes)).To(BeNumerically(">=", 2),
		"shared Service matrix needs at least 2 worker nodes")

	base := sanitizeName(s.name)
	namespace := "e2e-" + base
	callerVpcName := "vpc-" + base
	callerSubnetName := "subnet-" + base
	callerSubnetCIDR := cidrForScenario(base, 0)

	backendNode := workerNodes[0]
	callerNode := workerNodes[0]
	if s.placement == sharedSvcDiffNode {
		callerNode = workerNodes[1]
	}

	DeferCleanup(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
			"--ignore-not-found=true", "--timeout=60s")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", callerSubnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", callerVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", callerVpcName, "--ignore-not-found=true")
	})

	By(fmt.Sprintf("creating caller Vpc %s (service.consume=true) and Subnet %s",
		callerVpcName, callerSubnetName))
	Expect(applyManifest(consumerVpcSubnetManifest(callerVpcName, callerSubnetName, callerSubnetCIDR))).To(Succeed())
	waitSubnetReady(callerSubnetName)

	createNamespace(namespace)

	By(fmt.Sprintf("creating backend Pod (default Vpc) on %s and a shared Service", backendNode))
	Expect(applyManifest(podManifest(namespace, serverPodName, backendNode, "", true))).To(Succeed())
	Expect(applyManifest(sharedServiceManifest(namespace, serverPodName, serverPodName, defaultVpcProviderForTests(), nil))).To(Succeed())

	By(fmt.Sprintf("creating caller Pod on %s in %s", callerNode, callerSubnetName))
	Expect(applyManifest(podManifest(namespace, clientPodName, callerNode, callerSubnetName, false))).To(Succeed())

	waitPodsReady(namespace, serverPodName, clientPodName)
	waitServiceEndpoints(namespace, serverPodName)

	// Caller Node's SNAT IP for the default-Vpc provider role.
	By(fmt.Sprintf("waiting for ServiceNATAttachment %s to be Ready",
		serviceNATAttachmentName(callerNode, defaultVpcProviderForTests())))
	callerSNATIP := waitServiceNATAttachmentReady(callerNode, defaultVpcProviderForTests())

	By("issuing curl from caller Pod to the shared ClusterIP")
	assertServiceConnectivity(namespace, clientPodName, serverPodName)

	By(fmt.Sprintf("S-dp-3: nginx access log must record src=%s (caller Node SNAT IP)", callerSNATIP))
	assertNginxLogContains(namespace, serverPodName, callerSNATIP)
}

// runSharedServiceReverseScenario exercises the symmetric direction
// the new (Node × provider Vpc) ServiceNATAttachment fan-out unlocks:
// the *tenant* Vpc owns the Service and acts as the provider, and
// callers reach it from the default Vpc. Asserts both connectivity
// and SNAT-source-IP semantics.
func runSharedServiceReverseScenario(s sharedSvcScenario) {
	Expect(len(workerNodes)).To(BeNumerically(">=", 2),
		"reverse-direction shared Service matrix needs at least 2 worker nodes")

	base := sanitizeName(s.name)
	namespace := "e2e-" + base
	providerVpcName := "vpc-" + base
	providerSubnetName := "subnet-" + base
	providerSubnetCIDR := cidrForScenario(base, 0)

	callerNode := workerNodes[0]
	backendNode := workerNodes[0]
	if s.placement == sharedSvcDiffNode {
		backendNode = workerNodes[1]
	}

	DeferCleanup(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
			"--ignore-not-found=true", "--timeout=60s")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", providerSubnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", providerVpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", providerVpcName, "--ignore-not-found=true")
	})

	By(fmt.Sprintf("creating provider Vpc %s with provider.natSourceSubnet=%s",
		providerVpcName, providerSubnetName))
	Expect(applyManifest(providerVpcSubnetManifest(providerVpcName, providerSubnetName, providerSubnetCIDR))).To(Succeed())
	waitSubnetReady(providerSubnetName)

	createNamespace(namespace)

	By(fmt.Sprintf("creating backend Pod (Vpc=%s) on %s and a shared Service",
		providerVpcName, backendNode))
	Expect(applyManifest(podManifest(namespace, serverPodName, backendNode, providerSubnetName, true))).To(Succeed())
	Expect(applyManifest(sharedServiceManifest(namespace, serverPodName, serverPodName, providerVpcName, nil))).To(Succeed())

	By(fmt.Sprintf("creating caller Pod (default Vpc) on %s", callerNode))
	Expect(applyManifest(podManifest(namespace, clientPodName, callerNode, "", false))).To(Succeed())

	waitPodsReady(namespace, serverPodName, clientPodName)
	waitServiceEndpoints(namespace, serverPodName)

	// Caller Node's SNAT IP is allocated from the *provider* Vpc's
	// natSourceSubnet, not from the caller Vpc, because the SNAT
	// source must live on the provider's fabric so backend replies
	// route home.
	By(fmt.Sprintf("waiting for ServiceNATAttachment %s to be Ready",
		serviceNATAttachmentName(callerNode, providerVpcName)))
	callerSNATIP := waitServiceNATAttachmentReady(callerNode, providerVpcName)

	By("issuing curl from default-Vpc caller Pod to the shared ClusterIP")
	assertServiceConnectivity(namespace, clientPodName, serverPodName)

	By(fmt.Sprintf("nginx access log must record src=%s (caller Node SNAT IP from %s)",
		callerSNATIP, providerVpcName))
	assertNginxLogContains(namespace, serverPodName, callerSNATIP)
}

// runSharedServiceACLScenario validates the per-Service consumer
// ACL: when the
// juneau.loutres.me/shared-service-allowed-consumer-vpcs annotation
// is set to a whitelist, only listed caller Vpcs reach the Service.
// The test creates two consumer Vpcs (one allowed, one not) calling
// a tenant-provider Service and asserts allow + deny in the same
// run. Same-Vpc traffic always passes regardless of the ACL.
func runSharedServiceACLScenario() {
	Expect(len(workerNodes)).To(BeNumerically(">=", 1))

	base := sanitizeName("shared-svc-acl")
	namespace := "e2e-" + base
	providerVpc := "vpc-prov-" + base
	providerSubnet := "subnet-prov-" + base
	allowedVpc := "vpc-allow-" + base
	allowedSubnet := "subnet-allow-" + base
	deniedVpc := "vpc-deny-" + base
	deniedSubnet := "subnet-deny-" + base

	providerCIDR := cidrForScenario(base, 0)
	allowedCIDR := cidrForScenario(base, 1)
	deniedCIDR := cidrForScenario(base, 2)

	DeferCleanup(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
			"--ignore-not-found=true", "--timeout=60s")
		for _, sn := range []string{providerSubnet, allowedSubnet, deniedSubnet} {
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", sn, "--ignore-not-found=true")
		}
		for _, vpc := range []string{providerVpc, allowedVpc, deniedVpc} {
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpc, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpc, "--ignore-not-found=true")
		}
	})

	manifest := providerVpcSubnetManifest(providerVpc, providerSubnet, providerCIDR) + "---\n" +
		consumerVpcSubnetManifest(allowedVpc, allowedSubnet, allowedCIDR) + "---\n" +
		consumerVpcSubnetManifest(deniedVpc, deniedSubnet, deniedCIDR)
	Expect(applyManifest(manifest)).To(Succeed())
	waitSubnetReady(providerSubnet)
	waitSubnetReady(allowedSubnet)
	waitSubnetReady(deniedSubnet)

	createNamespace(namespace)

	allowedPod := clientPodName + "-allow"
	deniedPod := clientPodName + "-deny"

	Expect(applyManifest(podManifest(namespace, serverPodName, workerNodes[0], providerSubnet, true))).To(Succeed())
	Expect(applyManifest(sharedServiceManifest(namespace, serverPodName, serverPodName, providerVpc,
		[]string{allowedVpc}))).To(Succeed())
	Expect(applyManifest(podManifest(namespace, allowedPod, workerNodes[0], allowedSubnet, false))).To(Succeed())
	Expect(applyManifest(podManifest(namespace, deniedPod, workerNodes[0], deniedSubnet, false))).To(Succeed())

	waitPodsReady(namespace, serverPodName, allowedPod, deniedPod)
	waitServiceEndpoints(namespace, serverPodName)
	waitServiceNATAttachmentReady(workerNodes[0], providerVpc)

	clusterIP, err := kubectlJSONPath(repoRoot, `{.spec.clusterIP}`,
		"-n", namespace, "get", "service", serverPodName)
	Expect(err).NotTo(HaveOccurred())
	clusterIP = strings.TrimSpace(clusterIP)
	Expect(clusterIP).NotTo(BeEmpty())

	By("the allowed-Vpc Pod reaches the ACL-protected Service")
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, allowedPod, "--",
			"curl", "-sS", "--max-time", "5", "-w", "%{http_code}", "-o", "/dev/null",
			fmt.Sprintf("http://%s", clusterIP))
		g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
		g.Expect(strings.TrimSpace(out)).To(Equal("200"))
	}).Should(Succeed())

	By("the denied-Vpc Pod cannot reach the ACL-protected Service")
	out, curlErr := kubectlOutput(repoRoot, "exec", "-n", namespace, deniedPod, "--",
		"curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s", clusterIP))
	Expect(curlErr).To(HaveOccurred(), "curl from denied Vpc should fail; got: %s", out)
}

// consumerVpcSubnetManifest creates a Vpc that only consumes shared
// Services (no provider role). Used for caller-side fixtures.
func consumerVpcSubnetManifest(vpcName, subnetName, subnetCIDR string) string {
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  service:
    consume: true
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, vpcName, subnetName, vpcName, subnetCIDR)
}

// providerVpcSubnetManifest creates a Vpc that acts as a Service
// provider, with the supplied Subnet doubling as the SNAT source.
// Used for owner-side fixtures in reverse-direction and ACL tests.
func providerVpcSubnetManifest(vpcName, subnetName, subnetCIDR string) string {
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  service:
    consume: true
    provider:
      natSourceSubnet: %s
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, vpcName, subnetName, subnetName, vpcName, subnetCIDR)
}

// sharedServiceManifest builds a Service annotated for cross-Vpc
// sharing. ownerVpc selects the owner Vpc (empty string ↔ default Vpc
// — the annotation is omitted in that case so the controller defaults
// to "default" via the absent-annotation rule). When allowedConsumerVpcs
// is non-empty the per-Service ACL annotation is included.
func sharedServiceManifest(namespace, name, selector, ownerVpc string, allowedConsumerVpcs []string) string {
	annotations := []string{`juneau.loutres.me/shared-service: "true"`}
	if ownerVpc != "" && ownerVpc != defaultVpcName {
		annotations = append(annotations, fmt.Sprintf("juneau.loutres.me/vpc: %s", ownerVpc))
	}
	if len(allowedConsumerVpcs) > 0 {
		annotations = append(annotations,
			fmt.Sprintf(`juneau.loutres.me/shared-service-allowed-consumer-vpcs: "%s"`,
				strings.Join(allowedConsumerVpcs, ",")))
	}
	annLines := ""
	for _, a := range annotations {
		annLines += "    " + a + "\n"
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
  annotations:
%sspec:
  selector:
    app: %s
  ports:
    - port: 80
      targetPort: 80
`, namespace, name, annLines, selector)
}

// serviceNATAttachmentName mirrors the controller-side helper of the
// same name; the deterministic concatenation lets tests look up the
// per-(Node, provider Vpc) attachment without listing.
func serviceNATAttachmentName(nodeName, vpcName string) string {
	return nodeName + "." + vpcName
}

// defaultVpcProviderForTests is the provider Vpc the forward-direction
// shared-Service tests assume; the e2e environment bootstraps the
// default Vpc with provider.natSourceSubnet=default.
func defaultVpcProviderForTests() string {
	return defaultVpcName
}

func waitServiceNATAttachmentReady(nodeName, providerVpc string) string {
	name := serviceNATAttachmentName(nodeName, providerVpc)
	var assignedIP string
	Eventually(func(g Gomega) {
		ip, err := kubectlJSONPath(repoRoot, "{.status.assignedIP}",
			"get", "servicenatattachment", name)
		g.Expect(err).NotTo(HaveOccurred())
		ip = strings.TrimSpace(ip)
		g.Expect(ip).NotTo(BeEmpty(),
			"ServiceNATAttachment %s missing assignedIP", name)

		ready, err := kubectlJSONPath(repoRoot,
			`{.status.conditions[?(@.type=="Ready")].status}`,
			"get", "servicenatattachment", name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(ready)).To(Equal("True"),
			"ServiceNATAttachment %s not Ready", name)

		assignedIP = ip
	}).Should(Succeed())
	return assignedIP
}

func assertNginxLogContains(namespace, serverPod, expectedSrc string) {
	Eventually(func(g Gomega) {
		logs, err := kubectlOutput(repoRoot, "logs", "-n", namespace, serverPod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(logs).To(ContainSubstring(expectedSrc),
			"expected nginx access log to contain caller-Node SNAT IP %s; got logs:\n%s",
			expectedSrc, logs)
	}).Should(Succeed())
}
