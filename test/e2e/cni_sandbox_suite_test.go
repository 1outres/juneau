package e2e

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	cniBinDir       = "/opt/cni/bin"
	cniPluginPath   = cniBinDir + "/juneau"
	cniConfigPath   = "/etc/cni/net.d/juneau.conf"
	cniNetNSDir     = "/var/run/netns"
	cniPodInterface = "eth0"
)

const (
	// cniVethHostIDLen is how much of the container ID the daemon keeps
	// when it names the host-side veth. Two sandboxes whose IDs agree
	// over that prefix would fight over one link, so a synthetic label
	// has to stay inside it.
	cniVethHostIDLen = 10
	// cniContainerIDLen is the length a container runtime gives its
	// sandbox IDs. Synthetic IDs use it too, so the daemon has to
	// shorten them for the veth name just like it does in production.
	cniContainerIDLen = 64
	// cniSyntheticIDPrefix marks the container IDs this suite made up,
	// so a leftover veth on a node is recognizable.
	cniSyntheticIDPrefix = "e2e"
)

// cniPod is the Pod a hand-run CNI command acts on. The daemon looks the
// NetworkInterface up by these values and the interface name, so they
// have to name a Pod the controller already allocated an address for.
type cniPod struct {
	namespace string
	name      string
	uid       string
}

func lookupCNIPod(namespace, name string) cniPod {
	GinkgoHelper()
	uid, err := kubectlJSONPath(repoRoot, "{.metadata.uid}", "-n", namespace, "get", "pod", name)
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.TrimSpace(uid)).NotTo(BeEmpty())
	return cniPod{namespace: namespace, name: name, uid: strings.TrimSpace(uid)}
}

// cniSandbox is one sandbox generation of a Pod as the CNI contract sees
// it: the container ID the runtime hands the plugin, and the network
// namespace that sandbox runs in. A Pod keeps its UID when its sandbox
// is rebuilt, so the container ID is what tells the generations apart.
type cniSandbox struct {
	containerID string
	netnsPath   string
}

// runtimeSandbox names a sandbox the container runtime built. Only its
// ID is known: DEL never opens the namespace, and a sandbox that was
// already removed no longer has one.
func runtimeSandbox(containerID string) cniSandbox {
	return cniSandbox{containerID: containerID}
}

// syntheticSandbox is a sandbox a spec builds itself. kubelet only ever
// runs ADD before DEL for one sandbox, so a spec that needs a late DEL
// has to own both ends of the pair.
type syntheticSandbox struct {
	cniSandbox

	node      string
	netnsName string
}

func newSyntheticSandbox(node, label string) syntheticSandbox {
	GinkgoHelper()
	prefix := cniSyntheticIDPrefix + label
	Expect(len(prefix)).To(BeNumerically("<=", cniVethHostIDLen),
		"sandbox label %q does not fit in the veth name the daemon derives", label)

	netnsName := "e2e-cni-" + label
	return syntheticSandbox{
		cniSandbox: cniSandbox{
			containerID: prefix + strings.Repeat("0", cniContainerIDLen-len(prefix)),
			netnsPath:   cniNetNSDir + "/" + netnsName,
		},
		node:      node,
		netnsName: netnsName,
	}
}

// hostVethName mirrors the daemon's CNIServer.vethHostName. The e2e
// module is a separate Go module and does not import the daemon.
func (s syntheticSandbox) hostVethName() string {
	return cniPodInterface + "+" + s.containerID[:cniVethHostIDLen]
}

func (s syntheticSandbox) create() {
	GinkgoHelper()
	out, err := dockerExecOutput(s.node, "ip", "netns", "add", s.netnsName)
	Expect(err).NotTo(HaveOccurred(), "ip netns add %s: %s", s.netnsName, out)
}

// remove drops what the sandbox left on the node. A spec that failed
// before its DEL still has a veth and a namespace there, and the next
// spec on that node must not run into them.
func (s syntheticSandbox) remove() {
	runBestEffort(repoRoot, "docker", "exec", s.node, "ip", "link", "delete", s.hostVethName())
	runBestEffort(repoRoot, "docker", "exec", s.node, "ip", "netns", "delete", s.netnsName)
}

// runCNI runs the plugin the daemon installed on the node the way the
// container runtime would: the command and the sandbox arrive in the
// environment, the netconf on stdin. Driving the plugin directly is the
// only way to pick the order of ADD and DEL, which a Pod lifecycle
// never puts under a test's control.
func runCNI(node, command string, pod cniPod, sandbox cniSandbox) (string, error) {
	env := []string{
		"CNI_COMMAND=" + command,
		"CNI_CONTAINERID=" + sandbox.containerID,
		"CNI_NETNS=" + sandbox.netnsPath,
		"CNI_IFNAME=" + cniPodInterface,
		"CNI_PATH=" + cniBinDir,
		"CNI_ARGS=" + cniArgs(pod),
	}
	return dockerExecEnvOutput(node, env, "sh", "-c", cniPluginPath+" < "+cniConfigPath)
}

func cniArgs(pod cniPod) string {
	return strings.Join([]string{
		"K8S_POD_NAMESPACE=" + pod.namespace,
		"K8S_POD_NAME=" + pod.name,
		"K8S_POD_UID=" + pod.uid,
	}, ";")
}

func expectCNI(node, command string, pod cniPod, sandbox cniSandbox) {
	GinkgoHelper()
	out, err := runCNI(node, command, pod, sandbox)
	Expect(err).NotTo(HaveOccurred(), "CNI %s for container %s: %s", command, sandbox.containerID, out)
}

func dockerExecEnvOutput(container string, env []string, args ...string) (string, error) {
	full := []string{"exec"}
	for _, entry := range env {
		full = append(full, "-e", entry)
	}
	full = append(full, container)
	return dockerOutput(append(full, args...)...)
}

type networkEndpointObject struct {
	Spec networkEndpointSpec `json:"spec"`
}

type networkEndpointSpec struct {
	MACAddress string                     `json:"macAddress"`
	Attachment *networkEndpointAttachment `json:"attachment,omitempty"`
}

type networkEndpointAttachment struct {
	Ifindex        int    `json:"ifindex"`
	HostMACAddress string `json:"hostMACAddress"`
	ContainerID    string `json:"containerID,omitempty"`
}

// podNetworkEndpointName mirrors the daemon's networkEndpointName.
func podNetworkEndpointName(podName string) string {
	return podName + "." + cniPodInterface
}

func getPodNetworkEndpoint(namespace, podName string) (networkEndpointObject, error) {
	name := podNetworkEndpointName(podName)
	out, err := kubectlOutput(repoRoot, "get", "networkendpoints.juneau.loutres.me",
		name, "-n", namespace, "-o", "json")
	if err != nil {
		return networkEndpointObject{}, err
	}

	var obj networkEndpointObject
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return networkEndpointObject{}, fmt.Errorf("decode NetworkEndpoint %s/%s: %w", namespace, name, err)
	}
	return obj, nil
}

func podNetworkEndpointExists(namespace, podName string) (bool, error) {
	out, err := kubectlOutput(repoRoot, "get", "networkendpoints.juneau.loutres.me",
		podNetworkEndpointName(podName), "-n", namespace, "--ignore-not-found", "-o", "name")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

// waitPodAttachment waits until the endpoint names the given sandbox and
// reports what it recorded for it.
func waitPodAttachment(namespace, podName, containerID string) networkEndpointSpec {
	GinkgoHelper()
	var spec networkEndpointSpec
	Eventually(func(g Gomega) {
		obj, err := getPodNetworkEndpoint(namespace, podName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(obj.Spec.Attachment).NotTo(BeNil())
		g.Expect(obj.Spec.Attachment.ContainerID).To(Equal(containerID))
		spec = obj.Spec
	}).Should(Succeed())
	return spec
}

// readPodAttachment reads the endpoint once. A CNI DEL has finished
// every write it makes by the time the plugin exits, so a spec that
// checks what a DEL did must not poll: polling would let a wrong delete
// pass as a read that arrived too early.
func readPodAttachment(namespace, podName string) networkEndpointSpec {
	GinkgoHelper()
	obj, err := getPodNetworkEndpoint(namespace, podName)
	Expect(err).NotTo(HaveOccurred())
	return obj.Spec
}

// findRuntimeSandboxID asks the node's container runtime which sandbox
// it currently runs a Pod in. containerd passes that same ID to the CNI
// plugin as the container ID, so it is what the attachment records.
func findRuntimeSandboxID(node, namespace, podName string) (string, error) {
	out, err := dockerExecOutput(node, "crictl", "pods", "-q", "--state", "ready",
		"--namespace", namespace, "--name", podName)
	if err != nil {
		return "", err
	}

	ids := strings.Fields(out)
	if len(ids) != 1 {
		return "", fmt.Errorf("node %s reports %d ready sandboxes for Pod %s/%s: %v",
			node, len(ids), namespace, podName, ids)
	}
	return ids[0], nil
}

func waitRuntimeSandboxID(node, namespace, podName string) string {
	GinkgoHelper()
	var id string
	Eventually(func(g Gomega) {
		found, err := findRuntimeSandboxID(node, namespace, podName)
		g.Expect(err).NotTo(HaveOccurred())
		id = found
	}).Should(Succeed())
	return id
}

// assertAttachedVeth checks the endpoint records the veth the daemon
// really built for that sandbox, rather than numbers that only look
// plausible.
func assertAttachedVeth(node string, sandbox syntheticSandbox, spec networkEndpointSpec) {
	GinkgoHelper()
	Expect(spec.Attachment).NotTo(BeNil())

	veth := sandbox.hostVethName()
	Expect(hostIfaceAttr(node, veth, "ifindex")).To(Equal(strconv.Itoa(spec.Attachment.Ifindex)))
	Expect(hostIfaceAttr(node, veth, "address")).To(Equal(spec.Attachment.HostMACAddress))
}
