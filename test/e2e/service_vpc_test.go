package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The three specs below carry the contracts the connectivity matrix
// never actually verified:
// (a) Service creation is webhook-gated on Vpc.spec.service being set,
// (b) Services are isolated per VPC at runtime, and
// (c) ClusterIP traffic crosses subnets within the same VPC.
var _ = Describe("Juneau Service VPC scoping", func() {
	It("rejects creating a Service in a VPC where service routing is disabled", func() {
		ctx := newCaseContext(connectivityScenario{name: "svc-vpc-disabled"})
		currentCase = &ctx
		DeferCleanup(func() { currentCase = nil })

		By("creating an isolated namespace and a VPC with no service config")
		createNamespace(ctx.namespace)
		DeferCleanup(cleanupCaseResources, ctx)
		createCustomNetwork(ctx, false, false)

		By("expecting the Service webhook to reject the apply")
		manifest := serviceManifestWithVpc(ctx.namespace, ctx.serviceName, serverPodName, ctx.vpcName)
		Expect(applyManifest(manifest)).To(HaveOccurred(), "Service apply should be rejected by webhook")

		_, err := kubectlJSONPath(repoRoot, "{.metadata.name}", "-n", ctx.namespace, "get", "service", ctx.serviceName)
		Expect(err).To(HaveOccurred(), "Service should not have been created")
	})

	It("isolates Services across VPCs", func() {
		base := sanitizeName("svc-vpc-isolation")
		namespace := "e2e-" + base
		vpcA := "vpc-a-" + base
		vpcB := "vpc-b-" + base
		subnetA := "subnet-a-" + base
		subnetB := "subnet-b-" + base
		cidrA := "10.210.0.0/24"
		cidrB := "10.211.0.0/24"

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetA, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetB, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpcA, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpcB, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcA, "--ignore-not-found=true")
			runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcB, "--ignore-not-found=true")
		})

		By("creating two VPCs (both with service.consume=true) with one subnet each")
		manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  service:
    consume: true
---
apiVersion: juneau.loutres.me/v1alpha1
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
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, vpcA, vpcB, subnetA, vpcA, cidrA, subnetB, vpcB, cidrB)
		Expect(applyManifest(manifest)).To(Succeed())
		waitSubnetReady(subnetA)
		waitSubnetReady(subnetB)

		createNamespace(namespace)

		By("placing the server + Service in vpc-a and the client in vpc-b")
		Expect(applyManifest(podManifest(namespace, serverPodName, workerNodes[0], subnetA, true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientPodName, workerNodes[0], subnetB, false))).To(Succeed())
		Expect(applyManifest(serviceManifestWithVpc(namespace, serverPodName, serverPodName, vpcA))).To(Succeed())

		waitPodsReady(namespace, serverPodName, clientPodName)
		waitServiceEndpoints(namespace, serverPodName)

		clusterIP, err := kubectlJSONPath(repoRoot, `{.spec.clusterIP}`, "-n", namespace, "get", "service", serverPodName)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(clusterIP)).NotTo(BeEmpty())

		By("verifying the client in vpc-b cannot reach the Service in vpc-a")
		// A single short-timeout probe is sufficient: success would
		// actively contradict the assertion, so retrying only delays
		// real regressions.
		out, curlErr := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPodName, "--",
			"curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s", strings.TrimSpace(clusterIP)))
		Expect(curlErr).To(HaveOccurred(), "curl should fail across VPCs, got: %s", out)
	})

	It("routes ClusterIP across subnets within a VPC", func() {
		ctx := newCaseContext(connectivityScenario{name: "svc-cross-subnet"})
		currentCase = &ctx
		DeferCleanup(func() { currentCase = nil })

		createNamespace(ctx.namespace)
		DeferCleanup(cleanupCaseResources, ctx)
		createCustomNetwork(ctx, true, true)

		By("placing server in subnet-a and client in subnet-b within the same VPC")
		Expect(applyManifest(podManifest(ctx.namespace, serverPodName, workerNodes[0], ctx.serverSubnet, true))).To(Succeed())
		Expect(applyManifest(podManifest(ctx.namespace, clientPodName, workerNodes[0], ctx.clientSubnet, false))).To(Succeed())
		createServerService(ctx, ctx.vpcName)

		waitPodsReady(ctx.namespace, serverPodName, clientPodName)
		waitServiceEndpoints(ctx.namespace, serverPodName)
		assertServiceConnectivity(ctx.namespace, clientPodName, serverPodName)
	})
})

func serviceManifestWithVpc(namespace, name, selector, vpc string) string {
	annotation := ""
	if vpc != "" {
		annotation = fmt.Sprintf("  annotations:\n    juneau.loutres.me/vpc: %s\n", vpc)
	}
	return fmt.Sprintf(`apiVersion: v1
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
`, namespace, name, annotation, selector)
}
