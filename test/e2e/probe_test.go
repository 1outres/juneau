package e2e

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const probeNamespace = "e2e-kubelet-probe"

const overlapProbeNamespace = "e2e-kubelet-probe-overlap"

// Readiness probes are the most direct end-user signal that kubelet can
// check a Juneau Pod. Default-VPC Pods use the native host-to-Pod path.
// We assert both success and application-level failure:
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

var _ = Describe("Juneau overlapping-address probe compatibility", Ordered, func() {
	const (
		vpcA    = "probe-overlap-vpc-a"
		vpcB    = "probe-overlap-vpc-b"
		subnetA = "probe-overlap-subnet-a"
		subnetB = "probe-overlap-subnet-b"
		podA    = "probe-overlap-http"
		podB    = "probe-overlap-tcp"
	)

	BeforeAll(func() {
		createNamespace(overlapProbeNamespace)
		Expect(applyManifest(overlapProbeNetworkManifest(vpcA, vpcB, subnetA, subnetB))).To(Succeed())
		waitSubnetReady(subnetA)
		waitSubnetReady(subnetB)
	})

	AfterAll(func() {
		runBestEffort(repoRoot, "kubectl", "delete", "namespace", overlapProbeNamespace, "--ignore-not-found=true", "--timeout=60s")
		runBestEffort(repoRoot, "kubectl", "delete", "subnet", subnetA, subnetB, "--ignore-not-found=true", "--wait=true")
		runBestEffort(repoRoot, "kubectl", "delete", "vpc", vpcA, vpcB, "--ignore-not-found=true", "--wait=true")
	})

	It("keeps HTTP and TCP probes ready for duplicate Pod IPs on one node", func() {
		Expect(applyManifest(overlapProbePodManifest(overlapProbeNamespace, podA, workerNodes[0], subnetA, "http"))).To(Succeed())
		Expect(applyManifest(overlapProbePodManifest(overlapProbeNamespace, podB, workerNodes[0], subnetB, "tcp"))).To(Succeed())
		waitPodsReady(overlapProbeNamespace, podA, podB)

		ipA, err := kubectlJSONPath(repoRoot, "{.status.podIP}", "-n", overlapProbeNamespace, "get", "pod", podA)
		Expect(err).NotTo(HaveOccurred())
		ipB, err := kubectlJSONPath(repoRoot, "{.status.podIP}", "-n", overlapProbeNamespace, "get", "pod", podB)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(ipA)).To(Equal(strings.TrimSpace(ipB)))

		for _, podName := range []string{podA, podB} {
			version, err := kubectlJSONPath(repoRoot,
				`{.metadata.annotations.juneau\.loutres\.me/probe-rewrite-version}`,
				"-n", overlapProbeNamespace, "get", "pod", podName)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(version)).To(Equal("v1"))

			host, err := kubectlJSONPath(repoRoot,
				`{.spec.containers[0].readinessProbe.httpGet.host}`,
				"-n", overlapProbeNamespace, "get", "pod", podName)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(host)).To(Equal("127.0.0.1"))

			execCommand, err := kubectlJSONPath(repoRoot,
				`{.spec.containers[0].readinessProbe.exec.command}`,
				"-n", overlapProbeNamespace, "get", "pod", podName)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(execCommand)).To(BeEmpty())
		}
	})

	It("recovers probe registrations after the node daemon restarts", func() {
		pods, err := kubectlOutput(repoRoot, "get", "pods", "-n", "kube-system",
			"--field-selector", fmt.Sprintf("spec.nodeName=%s", workerNodes[0]),
			"-o", "name")
		Expect(err).NotTo(HaveOccurred())

		var daemonPod string
		for _, pod := range strings.Fields(pods) {
			if strings.Contains(pod, "juneau-cni-daemon-") {
				daemonPod = pod
				break
			}
		}
		Expect(daemonPod).NotTo(BeEmpty())
		Expect(run(repoRoot, "kubectl", "delete", "-n", "kube-system", daemonPod, "--wait=true", "--timeout=60s")).To(Succeed())
		Expect(run(repoRoot, "kubectl", "rollout", "status", "daemonset/juneau-cni-daemon", "-n", "kube-system", "--timeout=90s")).To(Succeed())

		waitPodsReady(overlapProbeNamespace, podA, podB)
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

func overlapProbeNetworkManifest(vpcA, vpcB, subnetA, subnetB string) string {
	return fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec: {}
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec: {}
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: 10.250.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: 10.250.0.0/24
`, vpcA, vpcB, subnetA, vpcA, subnetB, vpcB)
}

func overlapProbePodManifest(namespace, name, nodeName, subnet, probeType string) string {
	probe := `httpGet:
          path: /
          port: 80`
	if probeType == "tcp" {
		probe = `tcpSocket:
          port: 80`
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/subnet: %s
spec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: server
      image: nginx:1.27
      readinessProbe:
        %s
        initialDelaySeconds: 1
        periodSeconds: 2
        failureThreshold: 1
`, namespace, name, subnet, nodeName, probe)
}
