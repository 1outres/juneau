package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	hostNetTestNamespace = "e2e-host-net"
	hostNetClientPod     = "curl"
)

// Phase 4b-6 added the SVC_NAPT_OUT/IN path so that ClusterIP traffic
// can reach Service backends running in the host network namespace
// (kube-apiserver, etc.). Before that change the kubernetes Service was
// unreachable from Pods, which kept coredns stuck NotReady. These specs
// pin the regression: Pod → kubernetes Service must work, and Pod-side
// DNS resolution (which depends on both the host-net path and a Ready
// coredns) must answer cluster names.
var _ = Describe("Juneau host-network Service backends", Ordered, func() {
	BeforeAll(func() {
		// coredns reaching Ready depends on the very feature this suite
		// covers (Pod → kubernetes Service via the host-net backend),
		// so it is asserted here rather than in SynchronizedBeforeSuite
		// to avoid a flaky cluster bring-up from skipping every spec.
		Eventually(func(g Gomega) {
			g.Expect(run(repoRoot, "kubectl", "rollout", "status", "deployment/coredns", "-n", "kube-system", "--timeout=30s")).To(Succeed())
		}).Should(Succeed())

		createNamespace(hostNetTestNamespace)
		manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  labels:
    app: %s
spec:
  nodeName: %s
  containers:
    - name: curl
      image: curlimages/curl:8.12.1
      command: ["sleep", "3600"]
`, hostNetTestNamespace, hostNetClientPod, hostNetClientPod, workerNodes[0])
		Expect(applyManifest(manifest)).To(Succeed())
		waitPodsReady(hostNetTestNamespace, hostNetClientPod)
	})

	AfterAll(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", hostNetTestNamespace, "--ignore-not-found=true", "--timeout=60s")
	})

	It("H1: a Pod can reach the kubernetes Service (host-network apiserver)", func() {
		clusterIP, err := kubectlJSONPath(repoRoot, "{.spec.clusterIP}", "-n", "default", "get", "service", "kubernetes")
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(clusterIP)).NotTo(BeEmpty())

		// /livez is anonymous-OK on a default kind cluster, so a 200
		// response proves the full path: Pod → ClusterIP → SVC_NAPT_OUT
		// → host-net apiserver → reply on the SVC_NAPT_IN return path.
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", hostNetTestNamespace, hostNetClientPod, "--",
				"curl", "-skS", "--max-time", "5", "-w", "%{http_code}", "-o", "/dev/null",
				fmt.Sprintf("https://%s/livez", strings.TrimSpace(clusterIP)))
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(strings.TrimSpace(out)).To(Equal("200"))
		}).Should(Succeed())
	})

	It("H2: kube-dns resolves cluster Service names from a Pod", func() {
		// Hitting the apiserver by FQDN exercises kube-dns end-to-end:
		// the lookup goes Pod → kube-dns ClusterIP → coredns Pod, the
		// answer comes back, and then the curl itself goes Pod →
		// kubernetes Service → host-net apiserver. A 200 here proves
		// both Pod-backed and host-backed Service paths simultaneously.
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", hostNetTestNamespace, hostNetClientPod, "--",
				"curl", "-skS", "--max-time", "5", "-w", "%{http_code}", "-o", "/dev/null",
				"https://kubernetes.default.svc.cluster.local/livez")
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(strings.TrimSpace(out)).To(Equal("200"))
		}).Should(Succeed())
	})
})
