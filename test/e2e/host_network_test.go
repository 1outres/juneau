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
	// hostNetClientPodCP exercises the BACKEND_KIND_HOST_LOCAL path: a
	// Pod co-located on the control plane (where kube-apiserver runs)
	// must reach the kubernetes Service. The previous shape pinned
	// every test Pod to a worker, which silently masked this case
	// because remote backends took the SVC_NAPT_OUT/_IN underlay path.
	hostNetClientPodCP = "curl-cp"
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
  terminationGracePeriodSeconds: 0
  containers:
    - name: curl
      image: curlimages/curl:8.12.1
      command: ["sleep", "3600"]
---
apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  labels:
    app: %s
spec:
  nodeName: %s-control-plane
  tolerations:
    - operator: Exists
  containers:
    - name: curl
      image: curlimages/curl:8.12.1
      command: ["sleep", "3600"]
`,
			hostNetTestNamespace, hostNetClientPod, hostNetClientPod, workerNodes[0],
			hostNetTestNamespace, hostNetClientPodCP, hostNetClientPodCP, clusterName)
		Expect(applyManifest(manifest)).To(Succeed())
		waitPodsReady(hostNetTestNamespace, hostNetClientPod, hostNetClientPodCP)
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

	It("H3: a Pod on the control-plane node can reach the kubernetes Service (HOST_LOCAL backend)", func() {
		// kube-apiserver lives on the control-plane node. A Pod
		// co-located there exercises BACKEND_KIND_HOST_LOCAL: the
		// pod_egress path must DNAT (without SNAT) and hand the packet
		// to kernel local input, while the reply through
		// juneau_node_h → juneau_node must hit the SVC_NAPT_IN reverse
		// rewrite. Before the kind-aware redesign, FIB lookup on the
		// rewritten dst (the node's own underlay IP) returned
		// NOT_FWDED and the data plane SHOT-ed the packet.
		clusterIP, err := kubectlJSONPath(repoRoot, "{.spec.clusterIP}", "-n", "default", "get", "service", "kubernetes")
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(clusterIP)).NotTo(BeEmpty())

		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", hostNetTestNamespace, hostNetClientPodCP, "--",
				"curl", "-skS", "--max-time", "5", "-w", "%{http_code}", "-o", "/dev/null",
				fmt.Sprintf("https://%s/livez", strings.TrimSpace(clusterIP)))
			g.Expect(err).NotTo(HaveOccurred(), "curl output: %s", out)
			g.Expect(strings.TrimSpace(out)).To(Equal("200"))
		}).Should(Succeed())
	})

	It("H2: kube-dns resolves cluster Service names from a Pod", func() {
		// Test the DNS path in isolation: Pod → kube-dns ClusterIP →
		// coredns Pod → answer. Combining DNS with an HTTPS request
		// (as the previous version did) made this spec flaky on
		// GitHub-hosted runners because a cold daemon Service reconcile
		// race delayed the kube-dns backend rewrite past the curl
		// timeout. nslookup lets the inner DNS retry on its own and
		// keeps the assertion narrowly about DNS resolution.
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", hostNetTestNamespace, hostNetClientPod, "--",
				"nslookup", "kubernetes.default.svc.cluster.local")
			g.Expect(err).NotTo(HaveOccurred(), "nslookup output: %s", out)
			// The kubernetes Service ClusterIP lives in the cluster
			// Service CIDR (10.96.0.0/12 on a default kind cluster).
			g.Expect(out).To(ContainSubstring("10.96.0."), "expected an answer in the Service CIDR; got: %s", out)
		}).Should(Succeed())
	})
})
