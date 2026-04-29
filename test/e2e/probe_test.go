package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const probeNamespace = "e2e-kubelet-probe"

// Phase 4b-4 wired the host-side juneau_node iface so that kubelet
// (running in the host network namespace) can reach Pod IPs in juneau's
// overlay. Readiness probes are the most direct end-user signal that
// this path works: a Pod that never becomes Ready means kubelet cannot
// hit it. We assert both directions:
//
//	J1α — a passing probe drives Ready=True (the path is reachable).
//	J1β — a deliberately failing probe keeps Ready=False AND emits a
//	      "Readiness probe failed" event (the kubelet *did* probe; the
//	      result was just a 404). A purely static failure would never
//	      surface that event.
var _ = Describe("Juneau kubelet readiness probe", Ordered, func() {
	BeforeAll(func() {
		createNamespace(probeNamespace)
	})

	AfterAll(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", probeNamespace, "--ignore-not-found=true", "--timeout=60s")
	})

	It("J1α: a Pod with a passing readinessProbe reaches Ready=True", func() {
		podName := "probe-ok"
		Expect(applyManifest(probePodManifest(probeNamespace, podName, workerNodes[0], "/"))).To(Succeed())
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "pod", podName, "-n", probeNamespace, "--ignore-not-found=true", "--timeout=60s")
		})
		waitPodsReady(probeNamespace, podName)
	})

	It("J1β: a Pod with a failing readinessProbe stays Ready=False and emits probe-failure events", func() {
		podName := "probe-broken"
		Expect(applyManifest(probePodManifest(probeNamespace, podName, workerNodes[0], "/this-path-does-not-exist"))).To(Succeed())
		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "pod", podName, "-n", probeNamespace, "--ignore-not-found=true", "--timeout=60s")
		})

		// Wait for the container itself to be Running before asserting
		// readiness — otherwise we might race the scheduler.
		Eventually(func(g Gomega) {
			phase, err := kubectlJSONPath(repoRoot, "{.status.phase}", "-n", probeNamespace, "get", "pod", podName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(phase)).To(Equal("Running"))
		}).Should(Succeed())

		// kubelet must reach the Pod and observe a 404, leaving it
		// NotReady. Consistently confirms it stays that way past several
		// probe intervals (so the failure isn't a transient race).
		Consistently(func(g Gomega) {
			ready, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].status}`, "-n", probeNamespace, "get", "pod", podName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(ready)).NotTo(Equal("True"), "pod should not become Ready while readinessProbe fails")
		}, "30s", "5s").Should(Succeed())

		// The kubelet event proves the probe was actually executed
		// (i.e. the host stack → Pod path is alive).
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "get", "events", "-n", probeNamespace,
				"--field-selector", fmt.Sprintf("involvedObject.name=%s", podName),
				"-o", "jsonpath={.items[*].message}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.ToLower(out)).To(ContainSubstring("readiness probe failed"))
		}).Should(Succeed())
	})
})

func probePodManifest(namespace, name, nodeName, probePath string) string {
	return fmt.Sprintf(`apiVersion: v1
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
    - name: server
      image: nginx:1.27
      ports:
        - containerPort: 80
      readinessProbe:
        httpGet:
          path: %s
          port: 80
        initialDelaySeconds: 1
        periodSeconds: 2
        failureThreshold: 1
`, namespace, name, name, nodeName, probePath)
}
