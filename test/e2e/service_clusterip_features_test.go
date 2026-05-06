package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// These specs cover ClusterIP behaviours that the basic
// service_vpc_test.go connectivity matrix does not exercise:
// sessionAffinity=ClientIP must keep the same caller IP pinned to a
// single backend, and internalTrafficPolicy=Local must restrict
// dispatch to backends on the caller's Node (and drop traffic when no
// such backend exists).
//
// The setup uses two nginx pods on different nodes, each with a
// distinct index.html written post-start, so the response body
// identifies which backend served the request. This avoids pulling
// in heavier images like agnhost while still giving us per-request
// backend attribution.
var _ = Describe("Juneau Service ClusterIP features", func() {
	It("sessionAffinity=ClientIP pins a caller to a single backend", func() {
		base := sanitizeName("svc-affinity-clientip")
		namespace := "e2e-" + base
		svcName := "affinity"
		serverA := "server-a"
		serverB := "server-b"
		clientA := "client-a"
		clientB := "client-b"

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
		})

		Expect(len(workerNodes)).To(BeNumerically(">=", 2), "session-affinity test needs two worker nodes")
		createNamespace(namespace)

		By("placing two server pods on different nodes and two client pods (distinct caller IPs)")
		// Two distinct client IPs are the canonical fixture for
		// ClientIP affinity: each client provides one independent
		// stickiness assertion, and we don't depend on natural
		// distribution from ephemeral source ports.
		Expect(applyManifest(podManifest(namespace, serverA, workerNodes[0], "", true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, serverB, workerNodes[1], "", true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientA, workerNodes[0], "", false))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientB, workerNodes[1], "", false))).To(Succeed())
		waitPodsReady(namespace, serverA, serverB, clientA, clientB)

		By("seeding distinct response bodies on each backend so we can attribute requests")
		stampBackend(namespace, serverA, "BACKEND-A")
		stampBackend(namespace, serverB, "BACKEND-B")

		By("creating a Service with sessionAffinity=ClientIP")
		Expect(applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
spec:
  selector:
    app: server
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 120
  ports:
    - port: 80
      targetPort: 80
`, namespace, svcName))).To(Succeed())
		labelPodApp(namespace, serverA, "server")
		labelPodApp(namespace, serverB, "server")
		waitServiceTwoEndpoints(namespace, svcName)

		By("verifying each client lands on exactly one backend across 20 sequential requests")
		// Eventually because the data plane has to converge on the
		// service_val.flags / affinity_sec write before the sticky
		// behaviour kicks in for the very first packet.
		Eventually(func(g Gomega) {
			respA := collectResponses(namespace, clientA, svcName, 20)
			g.Expect(distinctCount(respA)).To(Equal(1),
				"client-a should pin to a single backend; got %v", respA)

			respB := collectResponses(namespace, clientB, svcName, 20)
			g.Expect(distinctCount(respB)).To(Equal(1),
				"client-b should pin to a single backend; got %v", respB)
		}).Should(Succeed())
	})

	It("internalTrafficPolicy=Local routes to local-node backends only", func() {
		base := sanitizeName("svc-itp-local")
		namespace := "e2e-" + base
		svcName := "itp"
		serverA := "server-a"
		serverB := "server-b"
		clientLocal := "client-local"
		clientRemote := "client-remote"

		DeferCleanup(func() {
			runBestEffort(repoRoot, "kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--timeout=60s")
		})

		Expect(len(workerNodes)).To(BeNumerically(">=", 2), "iTP=Local test needs two worker nodes")
		createNamespace(namespace)

		By("placing one server on each node and a client on each node")
		Expect(applyManifest(podManifest(namespace, serverA, workerNodes[0], "", true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, serverB, workerNodes[1], "", true))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientLocal, workerNodes[0], "", false))).To(Succeed())
		Expect(applyManifest(podManifest(namespace, clientRemote, workerNodes[1], "", false))).To(Succeed())
		waitPodsReady(namespace, serverA, serverB, clientLocal, clientRemote)

		By("seeding distinct response bodies on each backend")
		stampBackend(namespace, serverA, "BACKEND-A")
		stampBackend(namespace, serverB, "BACKEND-B")

		By("creating the Service with internalTrafficPolicy=Local")
		Expect(applyManifest(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
spec:
  selector:
    app: server
  internalTrafficPolicy: Local
  ports:
    - port: 80
      targetPort: 80
`, namespace, svcName))).To(Succeed())
		labelPodApp(namespace, serverA, "server")
		labelPodApp(namespace, serverB, "server")
		waitServiceTwoEndpoints(namespace, svcName)

		By("verifying each client only ever sees the backend on its own node")
		Eventually(func(g Gomega) {
			localOut := collectResponses(namespace, clientLocal, svcName, 10)
			g.Expect(distinctSet(localOut)).To(Equal(map[string]struct{}{"BACKEND-A": {}}),
				"client on workerNodes[0] should only see BACKEND-A; got %v", localOut)

			remoteOut := collectResponses(namespace, clientRemote, svcName, 10)
			g.Expect(distinctSet(remoteOut)).To(Equal(map[string]struct{}{"BACKEND-B": {}}),
				"client on workerNodes[1] should only see BACKEND-B; got %v", remoteOut)
		}).Should(Succeed())

		By("removing the local backend on workerNodes[1] and verifying that client now fails")
		runBestEffort(repoRoot, "kubectl", "delete", "pod", "-n", namespace, serverB, "--grace-period=0", "--force")
		Eventually(func(g Gomega) {
			out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientRemote, "--",
				"curl", "-sS", "--max-time", "2", "http://"+svcName)
			// curl exits non-zero on connection failure / timeout.
			g.Expect(err).To(HaveOccurred(), "remote-node client should lose service reachability after local backend deletion; got: %s", out)
		}).Should(Succeed())

		By("confirming the client on workerNodes[0] still reaches its local backend")
		Consistently(func(g Gomega) {
			out := collectResponses(namespace, clientLocal, svcName, 5)
			g.Expect(distinctSet(out)).To(Equal(map[string]struct{}{"BACKEND-A": {}}))
		}).Should(Succeed())
	})
})

// stampBackend overwrites the nginx default index.html on the given
// pod with body so subsequent curl requests can attribute the
// response to the originating backend.
func stampBackend(namespace, podName, body string) {
	Expect(run(repoRoot, "kubectl", "exec", "-n", namespace, podName, "--",
		"sh", "-c", fmt.Sprintf("printf '%%s' '%s' > /usr/share/nginx/html/index.html", body))).To(Succeed())
}

// labelPodApp re-labels a pod's app key to share a Service selector
// across multiple distinctly-named pods. Used because podManifest
// hard-codes app=<podName>.
func labelPodApp(namespace, podName, appLabel string) {
	Expect(run(repoRoot, "kubectl", "label", "pod", "-n", namespace, podName,
		"app="+appLabel, "--overwrite")).To(Succeed())
}

// waitServiceTwoEndpoints waits until the EndpointSlice publishes at
// least two backend addresses for the Service. Affinity / iTP tests
// need both backends present before they assert distribution.
func waitServiceTwoEndpoints(namespace, svcName string) {
	Eventually(func(g Gomega) {
		out, err := kubectlJSONPath(repoRoot, `{.subsets[*].addresses[*].ip}`, "-n", namespace, "get", "endpoints", svcName)
		g.Expect(err).NotTo(HaveOccurred())
		fields := strings.Fields(strings.TrimSpace(out))
		g.Expect(len(fields)).To(BeNumerically(">=", 2), "want 2 endpoints, got %v", fields)
	}).Should(Succeed())
}

// collectResponses runs n curl requests sequentially from clientPod
// against the named Service and returns the response bodies (one per
// request). Failures are surfaced as empty strings so callers can
// notice them without aborting the whole batch.
func collectResponses(namespace, clientPod, svcName string, n int) []string {
	cmd := fmt.Sprintf("for i in $(seq 1 %d); do curl -sS --max-time 3 http://%s/ ; printf '\\n'; done", n, svcName)
	out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, clientPod, "--", "sh", "-c", cmd)
	Expect(err).NotTo(HaveOccurred())
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	return lines
}

func distinctSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		out[s] = struct{}{}
	}
	return out
}

func distinctCount(in []string) int { return len(distinctSet(in)) }
