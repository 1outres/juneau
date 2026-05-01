package e2e

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// 484063f により juneau_node が NetworkEndpoint(Kind=Node) として
// default Subnet に参加した。これによって host network namespace から
// overlay 上の Pod / default Vpc Service / host-network backend Service
// (kubernetes Service) への到達が成立する。本ファイルはその経路を
// 明示的にマトリクス化する。
//
// kubernetes Service エントリ (A6/A7) は既存リソースに対する curl のみで
// 何もリソースを作成しないため最も軽い。Pod/Service を作るエントリも
// シナリオ名から派生させた一意の namespace を使うため、Ginkgo --procs=N
// で安全に並列分配される (cf. e2e_test.go の connectivity matrix と同方針)。

type nodeFromTarget string

const (
	nodeFromTargetSameNodePod  nodeFromTarget = "same-node-pod"
	nodeFromTargetDiffNodePod  nodeFromTarget = "diff-node-pod"
	nodeFromTargetSameNodeSvc  nodeFromTarget = "same-node-svc"
	nodeFromTargetDiffNodeSvc  nodeFromTarget = "diff-node-svc"
	nodeFromTargetCPApiSvc     nodeFromTarget = "cp-apiserver-svc"
	nodeFromTargetWorkerApiSvc nodeFromTarget = "worker-apiserver-svc"
)

type nodeFromScenario struct {
	name   string
	target nodeFromTarget
}

var _ = Describe("Juneau node host-network connectivity", func() {
	DescribeTable("from host network namespace",
		func(s nodeFromScenario) {
			runNodeFromScenario(s)
		},
		Entry("A1: worker host -> same-node Pod (default Subnet)",
			nodeFromScenario{name: "host-to-pod-same-node", target: nodeFromTargetSameNodePod}),
		Entry("A2: worker host -> diff-node Pod (default Subnet)",
			nodeFromScenario{name: "host-to-pod-diff-node", target: nodeFromTargetDiffNodePod}),
		Entry("A4: worker host -> same-node default Vpc Service",
			nodeFromScenario{name: "host-to-svc-same-node", target: nodeFromTargetSameNodeSvc}),
		Entry("A5: worker host -> diff-node default Vpc Service",
			nodeFromScenario{name: "host-to-svc-diff-node", target: nodeFromTargetDiffNodeSvc}),
		Entry("A6: control-plane host -> kubernetes Service (HOST_LOCAL backend)",
			nodeFromScenario{name: "host-cp-to-kubernetes", target: nodeFromTargetCPApiSvc}),
		Entry("A7: worker host -> kubernetes Service (host-net backend, diff-node)",
			nodeFromScenario{name: "host-worker-to-kubernetes", target: nodeFromTargetWorkerApiSvc}),
	)
})

func runNodeFromScenario(s nodeFromScenario) {
	switch s.target {
	case nodeFromTargetCPApiSvc:
		// kube-apiserver は control-plane Node の host network 上に居る。
		// その上から ClusterIP に出るルートが kube-proxy の iptables に
		// よって作られているはずで、Juneau の SVC_NAPT 経路は通らない
		// (host->host のローカル DNAT)。返答が 200 になることだけを確認。
		assertHostCurlOK(clusterName+"-control-plane", kubernetesServiceURL(), "200")
		return
	case nodeFromTargetWorkerApiSvc:
		Expect(workerNodes).NotTo(BeEmpty())
		assertHostCurlOK(workerNodes[0], kubernetesServiceURL(), "200")
		return
	}

	Expect(len(workerNodes)).To(BeNumerically(">=", 2),
		"node host-network matrix needs at least 2 worker nodes")

	base := sanitizeName(s.name)
	namespace := "e2e-nh-" + base
	createNamespace(namespace)
	DeferCleanup(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace,
			"--ignore-not-found=true", "--timeout=60s")
	})

	srvNode := workerNodes[0]
	dialNode := srvNode
	if s.target == nodeFromTargetDiffNodePod || s.target == nodeFromTargetDiffNodeSvc {
		dialNode = workerNodes[1]
	}

	By(fmt.Sprintf("creating server Pod on %s in default Subnet", srvNode))
	Expect(applyManifest(podManifest(namespace, serverPodName, srvNode, "", true))).To(Succeed())

	wantsService := s.target == nodeFromTargetSameNodeSvc || s.target == nodeFromTargetDiffNodeSvc
	if wantsService {
		Expect(applyManifest(serviceManifestWithVpc(namespace, serverPodName, serverPodName, ""))).To(Succeed())
	}

	waitPodsReady(namespace, serverPodName)

	var url string
	switch s.target {
	case nodeFromTargetSameNodePod, nodeFromTargetDiffNodePod:
		ip, err := kubectlJSONPath(repoRoot, `{.status.podIP}`, "-n", namespace, "get", "pod", serverPodName)
		Expect(err).NotTo(HaveOccurred())
		ip = strings.TrimSpace(ip)
		Expect(ip).NotTo(BeEmpty())
		url = "http://" + ip
	case nodeFromTargetSameNodeSvc, nodeFromTargetDiffNodeSvc:
		waitServiceEndpoints(namespace, serverPodName)
		ip, err := kubectlJSONPath(repoRoot, `{.spec.clusterIP}`, "-n", namespace, "get", "service", serverPodName)
		Expect(err).NotTo(HaveOccurred())
		ip = strings.TrimSpace(ip)
		Expect(ip).NotTo(BeEmpty())
		url = "http://" + ip
	default:
		Fail(fmt.Sprintf("unhandled target %s", s.target))
	}

	By(fmt.Sprintf("curl %s from host network of %s", url, dialNode))
	assertHostCurlContains(dialNode, url, "welcome to nginx")
}

func kubernetesServiceURL() string {
	clusterIP, err := kubectlJSONPath(repoRoot, "{.spec.clusterIP}", "-n", "default", "get", "service", "kubernetes")
	Expect(err).NotTo(HaveOccurred())
	clusterIP = strings.TrimSpace(clusterIP)
	Expect(clusterIP).NotTo(BeEmpty())
	return fmt.Sprintf("https://%s/livez", clusterIP)
}

func assertHostCurlOK(node, url, expectStatus string) {
	Eventually(func(g Gomega) {
		out, err := dockerExecOutput(node, "curl", "-skS", "--max-time", "5",
			"-w", "%{http_code}", "-o", "/dev/null", url)
		g.Expect(err).NotTo(HaveOccurred(), "docker exec curl: %s", out)
		g.Expect(strings.TrimSpace(out)).To(Equal(expectStatus))
	}).Should(Succeed())
}

func assertHostCurlContains(node, url, want string) {
	Eventually(func(g Gomega) {
		out, err := dockerExecOutput(node, "curl", "-sS", "--max-time", "5", url)
		g.Expect(err).NotTo(HaveOccurred(), "docker exec curl: %s", out)
		g.Expect(strings.ToLower(out)).To(ContainSubstring(want))
	}).Should(Succeed())
}

func dockerExecOutput(container string, args ...string) (string, error) {
	full := append([]string{"exec", container}, args...)
	cmd := exec.Command("docker", full...)
	cmd.Dir = repoRoot

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_, _ = fmt.Fprintf(GinkgoWriter, "running: docker %s\n", strings.Join(full, " "))
	err := cmd.Run()
	if stderr.Len() > 0 {
		_, _ = GinkgoWriter.Write(stderr.Bytes())
	}
	if err != nil {
		return strings.TrimSpace(stdout.String()),
			fmt.Errorf("docker %s failed: %w", strings.Join(full, " "), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}
