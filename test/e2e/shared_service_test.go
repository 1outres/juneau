package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// 07954a7 で導入された shared Service 経路 (per-Node ServiceNATAttachment +
// pod_egress.handle_service_shared / vxlan_ingress の SVC_SHARED_IN /
// pod_egress の apply_conntrack_svc_shared_in) を end-to-end で踏ませる。
//
// caller は別 Vpc (enableService=true) に居る Pod、backend は default Vpc /
// default Subnet の Pod。caller→backend が
//
//   - 同じ Node なら pod_egress 経由の同 Node 返り leg
//     (apply_conntrack_svc_shared_in) を、
//   - 別 Node なら vxlan 経由の SVC_SHARED_IN leg を
//
// それぞれ踏む。両ケースとも nginx の access log で "source IP = caller
// Node の ServiceNATAttachment.status.assignedIP" を確認することで SNAT が
// 効いていることを立証 (S-dp-3)。
//
// matrix entry はそれぞれ独立した namespace / Vpc / Subnet を持つので
// Ginkgo --procs=N で安全に並列分配される。

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
	DescribeTable("dataplane: cross-Vpc ClusterIP through SVC_SHARED",
		func(s sharedSvcScenario) {
			runSharedServiceScenario(s)
		},
		Entry("S-dp-1: caller and backend on same node",
			sharedSvcScenario{name: "shared-svc-same-node", placement: sharedSvcSameNode}),
		Entry("S-dp-2: caller and backend on different nodes",
			sharedSvcScenario{name: "shared-svc-diff-node", placement: sharedSvcDiffNode}),
	)

	It("S-dp-4: a Pod in a non-default Vpc reaches the kubernetes Service implicitly as shared", func() {
		runSharedKubernetesServiceScenario()
	})
})

func runSharedServiceScenario(s sharedSvcScenario) {
	Expect(len(workerNodes)).To(BeNumerically(">=", 2),
		"shared Service matrix needs at least 2 worker nodes")

	base := sanitizeName(s.name)
	namespace := "e2e-" + base
	vpcName := "vpc-" + base
	subnetName := "subnet-" + base
	subnetCIDR := cidrForScenario(base, 0)

	backendNode := workerNodes[0]
	callerNode := workerNodes[0]
	if s.placement == sharedSvcDiffNode {
		callerNode = workerNodes[1]
	}

	DeferCleanup(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
			"--ignore-not-found=true", "--timeout=60s")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcName, "--ignore-not-found=true")
	})

	By(fmt.Sprintf("creating caller Vpc %s (enableService=true) and Subnet %s", vpcName, subnetName))
	Expect(applyManifest(callerVpcSubnetManifest(vpcName, subnetName, subnetCIDR))).To(Succeed())
	waitSubnetReady(subnetName)

	createNamespace(namespace)

	By(fmt.Sprintf("creating backend Pod (default Vpc) on %s and a shared Service", backendNode))
	Expect(applyManifest(podManifest(namespace, serverPodName, backendNode, "", true))).To(Succeed())
	Expect(applyManifest(sharedServiceManifest(namespace, serverPodName, serverPodName))).To(Succeed())

	By(fmt.Sprintf("creating caller Pod on %s in %s", callerNode, subnetName))
	Expect(applyManifest(podManifest(namespace, clientPodName, callerNode, subnetName, false))).To(Succeed())

	waitPodsReady(namespace, serverPodName, clientPodName)
	waitServiceEndpoints(namespace, serverPodName)

	By(fmt.Sprintf("waiting for ServiceNATAttachment for caller Node %s to be Ready", callerNode))
	callerSNATIP := waitServiceNATAttachmentReady(callerNode)

	By("issuing curl from caller Pod to the shared ClusterIP")
	assertServiceConnectivity(namespace, clientPodName, serverPodName)

	By(fmt.Sprintf("S-dp-3: nginx access log must record src=%s (caller Node SNAT IP)", callerSNATIP))
	// nginx のアクセスログは "<remote_addr> - - [date] \"GET / HTTP/1.1\" ..."
	// で始まる。caller Node の assignedIP がそのまま source として現れる
	// 必要がある。違うアドレスが見えた場合 SVC_SHARED_OUT の SNAT 書換 or
	// ServiceNATAttachment の管理に regression が出ている。
	Eventually(func(g Gomega) {
		logs, err := kubectlOutput(repoRoot, "logs", "-n", namespace, serverPodName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(logs).To(ContainSubstring(callerSNATIP),
			"expected nginx access log to contain caller-Node SNAT IP %s; got logs:\n%s",
			callerSNATIP, logs)
	}).Should(Succeed())
}

func runSharedKubernetesServiceScenario() {
	Expect(workerNodes).NotTo(BeEmpty())

	base := sanitizeName("shared-kubernetes-svc")
	namespace := "e2e-" + base
	vpcName := "vpc-" + base
	subnetName := "subnet-" + base
	subnetCIDR := cidrForScenario(base, 0)

	DeferCleanup(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
			"--ignore-not-found=true", "--timeout=60s")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "routetable", vpcName, "--ignore-not-found=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcName, "--ignore-not-found=true")
	})

	Expect(applyManifest(callerVpcSubnetManifest(vpcName, subnetName, subnetCIDR))).To(Succeed())
	waitSubnetReady(subnetName)

	createNamespace(namespace)
	Expect(applyManifest(podManifest(namespace, clientPodName, workerNodes[0], subnetName, false))).To(Succeed())
	waitPodsReady(namespace, clientPodName)
	waitServiceNATAttachmentReady(workerNodes[0])

	clusterIP, err := kubectlJSONPath(repoRoot, "{.spec.clusterIP}",
		"-n", "default", "get", "service", "kubernetes")
	Expect(err).NotTo(HaveOccurred())
	clusterIP = strings.TrimSpace(clusterIP)
	Expect(clusterIP).NotTo(BeEmpty())

	// kubernetes Service は annotation 無しでも暗黙的に shared 扱い
	// される。/livez は anonymous-OK の kind デフォルト構成なので 200 を
	// 期待できる。
	Eventually(func(g Gomega) {
		out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPodName, "--",
			"curl", "-skS", "--max-time", "5", "-w", "%{http_code}", "-o", "/dev/null",
			fmt.Sprintf("https://%s/livez", clusterIP))
		g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
		g.Expect(strings.TrimSpace(out)).To(Equal("200"))
	}).Should(Succeed())
}

func callerVpcSubnetManifest(vpcName, subnetName, subnetCIDR string) string {
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  enableService: true
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

func sharedServiceManifest(namespace, name, selector string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/shared-service: "true"
spec:
  selector:
    app: %s
  ports:
    - port: 80
      targetPort: 80
`, namespace, name, selector)
}

func waitServiceNATAttachmentReady(nodeName string) string {
	var assignedIP string
	Eventually(func(g Gomega) {
		ip, err := kubectlJSONPath(repoRoot, "{.status.assignedIP}",
			"get", "servicenatattachment", nodeName)
		g.Expect(err).NotTo(HaveOccurred())
		ip = strings.TrimSpace(ip)
		g.Expect(ip).NotTo(BeEmpty(),
			"ServiceNATAttachment for node %s missing assignedIP", nodeName)

		ready, err := kubectlJSONPath(repoRoot,
			`{.status.conditions[?(@.type=="Ready")].status}`,
			"get", "servicenatattachment", nodeName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(ready)).To(Equal("True"),
			"ServiceNATAttachment for node %s not Ready", nodeName)

		assignedIP = ip
	}).Should(Succeed())
	return assignedIP
}
