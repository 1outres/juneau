package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	clusterName         = "juneau-e2e"
	kindNodeImage       = "kindest/node:v1.33.1"
	controllerImage     = "example.com/controller:v0.0.1"
	webhookCertJobImage = "example.com/webhookcertjob:v0.0.1"
	daemonImage         = "daemon:latest"
	bgpSpeakerImage     = "bgp-speaker:latest"
	controllerNamespace = "juneau-system"
	daemonNamespace     = "kube-system"
	bgpSpeakerNamespace = "kube-system"
	defaultVpcName      = "default"
	defaultSubnetName   = "default"
	kindKubectlTimeout  = 5 * time.Minute
	defaultPollInterval = 2 * time.Second
)

var repoRoot string
var workerNodes []string
var currentCase *caseContext

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	SetDefaultEventuallyTimeout(kindKubectlTimeout)
	SetDefaultEventuallyPollingInterval(defaultPollInterval)
	RunSpecs(t, "Juneau Cluster E2E Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	root, err := findRepoRoot()
	Expect(err).NotTo(HaveOccurred())
	repoRoot = root

	runBestEffort(root, "kind", "delete", "cluster", "--name", clusterName)

	configFile, err := writeKindConfig(root)
	Expect(err).NotTo(HaveOccurred())

	mustRun(root, "kind", "create", "cluster", "--name", clusterName, "--config", configFile)
	mustRun(root, "make", "image-controller", fmt.Sprintf("CONTROLLER_IMAGE=%s", controllerImage))
	mustRun(root, "make", "image-webhookcertjob", fmt.Sprintf("WEBHOOKCERTJOB_IMAGE=%s", webhookCertJobImage))
	mustRun(root, "make", "image-daemon", fmt.Sprintf("DAEMON_IMAGE=%s", daemonImage))
	mustRun(root, "make", "image-bgp-speaker", fmt.Sprintf("BGP_SPEAKER_IMAGE=%s", bgpSpeakerImage))

	for _, image := range []string{controllerImage, webhookCertJobImage, daemonImage, bgpSpeakerImage} {
		mustRun(root, "kind", "load", "docker-image", image, "--name", clusterName)
	}

	mustRun(filepath.Join(root, "controller"), "make", "install")
	mustRun(filepath.Join(root, "controller"), "make", "deploy", fmt.Sprintf("IMG=%s", controllerImage))
	mustRun(root, "kubectl", "label", "--overwrite", "namespace", controllerNamespace, "pod-security.kubernetes.io/enforce=privileged")
	mustRun(root, "kubectl", "label", "--overwrite", "namespace", daemonNamespace, "pod-security.kubernetes.io/enforce=privileged")
	// The daemon installs the CNI binary on each node; without it, nodes
	// stay NotReady and the webhook-cert bootstrap job cannot schedule,
	// which in turn blocks the controller deployment. Apply it first.
	mustRun(root, "kubectl", "apply", "-k", filepath.Join(root, "daemon", "config", "default"))
	runBestEffort(root, "kubectl", "taint", "nodes", "--all", "node-role.kubernetes.io/control-plane-")

	Eventually(func(g Gomega) {
		g.Expect(run(root, "kubectl", "rollout", "status", "deployment/juneau-controller-manager", "-n", controllerNamespace, "--timeout=30s")).To(Succeed())
	}).Should(Succeed())

	Eventually(func(g Gomega) {
		g.Expect(run(root, "kubectl", "rollout", "status", "daemonset/juneau-cni-daemon", "-n", daemonNamespace, "--timeout=30s")).To(Succeed())
	}).Should(Succeed())

	Eventually(func(g Gomega) {
		status, err := kubectlJSONPath(root, "{.metadata.name}", "-n", controllerNamespace, "get", "secret", "webhook-certs")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(status)).To(Equal("webhook-certs"))
	}).Should(Succeed())

	Eventually(func(g Gomega) {
		g.Expect(run(root, "kubectl", "wait", "--for=condition=Ready", "node", "--all", "--timeout=30s")).To(Succeed())
	}).Should(Succeed())

	Eventually(func(g Gomega) {
		ready, err := kubectlJSONPath(root, `{.status.conditions[?(@.type=="Ready")].status}`, "get", "subnet", defaultSubnetName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(ready)).To(Equal("True"))
	}).Should(Succeed())

	// bgp-speaker is applied after the cluster has stabilized so its
	// DaemonSet pods don't compete with the CNI daemon during bootstrap.
	mustRun(root, "kubectl", "apply", "-k", filepath.Join(root, "bgp-speaker", "config", "default"))

	Eventually(func(g Gomega) {
		g.Expect(run(root, "kubectl", "rollout", "status", "daemonset/juneau-bgp-speaker", "-n", bgpSpeakerNamespace, "--timeout=30s")).To(Succeed())
	}).Should(Succeed())

	nodes, err := discoverWorkerNodes(root)
	Expect(err).NotTo(HaveOccurred())
	Expect(nodes).To(HaveLen(2))
	workerNodes = nodes

	return []byte(root)
}, func(data []byte) {
	repoRoot = string(data)
	nodes, err := discoverWorkerNodes(repoRoot)
	Expect(err).NotTo(HaveOccurred())
	workerNodes = nodes
})

var _ = SynchronizedAfterSuite(func() {
	if strings.EqualFold(os.Getenv("E2E_KEEP_CLUSTER"), "true") {
		return
	}
	teardownBGPRouter()
	Expect(run(repoRoot, "kind", "delete", "cluster", "--name", clusterName)).To(Succeed())
}, func() {})

var _ = AfterEach(func() {
	if !CurrentSpecReport().Failed() {
		return
	}

	dumpResource("pods", "-A", "-o", "wide")
	dumpResource("networkinterfaces.juneau.loutres.me", "-A")
	dumpResource("networkendpoints.juneau.loutres.me", "-A")
	dumpResource("ipleases.juneau.loutres.me")
	dumpResource("subnets.juneau.loutres.me")
	dumpResource("vpcs.juneau.loutres.me")
	dumpResource("routetables.juneau.loutres.me")
	dumpResource("services", "-A", "-o", "wide")
	dumpResource("endpoints", "-A")
	dumpResource("endpointslices.discovery.k8s.io", "-A")
	dumpDescribe("nodes")
	dumpEvents()
	if currentCase != nil {
		dumpDescribe("pods", "-n", currentCase.namespace)
		dumpDescribe("services", "-n", currentCase.namespace)
		dumpDescribe("endpoints", "-n", currentCase.namespace)
	}
	dumpLogs(controllerNamespace, "deployment/juneau-controller-manager")
	dumpLogs(daemonNamespace, "daemonset/juneau-cni-daemon")
	dumpLogs(bgpSpeakerNamespace, "daemonset/juneau-bgp-speaker")
	dumpNodeRuntime()
	dumpNodeState()
})

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(wd, "..", "..")), nil
}

func writeKindConfig(root string) (string, error) {
	config := `kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "10.16.0.0/16"
nodes:
  - role: control-plane
    image: ` + kindNodeImage + `
  - role: worker
    image: ` + kindNodeImage + `
  - role: worker
    image: ` + kindNodeImage + `
`

	path := filepath.Join(root, "test", "e2e", ".kind-config.yaml")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func discoverWorkerNodes(dir string) ([]string, error) {
	out, err := kubectlOutput(dir, "get", "nodes", "-l", "!node-role.kubernetes.io/control-plane", "-o", `jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}`)
	if err != nil {
		return nil, err
	}

	var nodes []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		nodes = append(nodes, line)
	}
	return nodes, nil
}

func run(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GO111MODULE=on", fmt.Sprintf("KIND_CLUSTER=%s", clusterName))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_, _ = fmt.Fprintf(GinkgoWriter, "running: (cd %s && %s %s)\n", dir, name, strings.Join(args, " "))
	err := cmd.Run()
	if stdout.Len() > 0 {
		_, _ = GinkgoWriter.Write(stdout.Bytes())
	}
	if stderr.Len() > 0 {
		_, _ = GinkgoWriter.Write(stderr.Bytes())
	}
	if err != nil {
		return fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func runBestEffort(dir string, name string, args ...string) {
	if err := run(dir, name, args...); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "best-effort command failed: %v\n", err)
	}
}

func mustRun(dir string, name string, args ...string) {
	Expect(run(dir, name, args...)).To(Succeed())
}

func kubectlOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), fmt.Sprintf("KIND_CLUSTER=%s", clusterName))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_, _ = fmt.Fprintf(GinkgoWriter, "running: (cd %s && kubectl %s)\n", dir, strings.Join(args, " "))
	err := cmd.Run()
	if stderr.Len() > 0 {
		_, _ = GinkgoWriter.Write(stderr.Bytes())
	}
	if err != nil {
		return strings.TrimSpace(stdout.String()), fmt.Errorf("kubectl %s failed: %w", strings.Join(args, " "), err)
	}
	if stdout.Len() > 0 {
		_, _ = GinkgoWriter.Write(stdout.Bytes())
	}
	return strings.TrimSpace(stdout.String()), nil
}

func kubectlJSONPath(dir string, jsonPath string, args ...string) (string, error) {
	fullArgs := append(args, "-o", "jsonpath="+jsonPath)
	return kubectlOutput(dir, fullArgs...)
}

func dumpResource(resource string, args ...string) {
	out, err := kubectlOutput(repoRoot, append([]string{"get", resource}, args...)...)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "failed to dump %s: %v\n", resource, err)
		return
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "\n%s\n", out)
}

func dumpLogs(namespace string, target string) {
	out, err := kubectlOutput(repoRoot, "logs", "-n", namespace, target, "--all-containers=true")
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "failed to dump logs for %s/%s: %v\n", namespace, target, err)
		return
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "\nlogs %s/%s\n%s\n", namespace, target, out)
}

func dumpDescribe(resource string, args ...string) {
	out, err := kubectlOutput(repoRoot, append([]string{"describe", resource}, args...)...)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "failed to describe %s: %v\n", resource, err)
		return
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "\ndescribe %s\n%s\n", resource, out)
}

func dumpEvents() {
	out, err := kubectlOutput(repoRoot, "get", "events", "-A", "--sort-by=.lastTimestamp")
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "failed to dump events: %v\n", err)
		return
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "\nevents\n%s\n", out)
}

func dumpNodeState() {
	nodes := append([]string{clusterName + "-control-plane"}, workerNodes...)
	for _, node := range nodes {
		if node == "" {
			continue
		}
		dumpDockerExec(node, "sh", "-lc", "ip addr; printf '\n==== routes ====\n'; ip route; printf '\n==== iptables ====\n'; iptables-save; printf '\n==== cni ====\n'; ls -al /etc/cni/net.d")
	}
}

func dumpNodeRuntime() {
	out, err := kubectlOutput(repoRoot, "get", "nodes", "-o", `jsonpath={range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.containerRuntimeVersion}{"\n"}{end}`)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "failed to dump node runtime info: %v\n", err)
		return
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "\nnode runtime info\n%s\n", out)

	nodes := append([]string{clusterName + "-control-plane"}, workerNodes...)
	for _, node := range nodes {
		if node == "" {
			continue
		}
		dumpDockerExec(node, "sh", "-lc", "crictl info | sed -n '1,120p'")
	}
}

func dumpDockerExec(container string, args ...string) {
	cmdArgs := append([]string{"exec", container}, args...)
	err := run(repoRoot, "docker", cmdArgs...)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "failed to inspect node %s: %v\n", container, err)
	}
}
