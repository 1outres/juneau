package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Juneau policy epoch E2E coverage.
//
// The data plane puts the policy generation in every conntrack key it
// writes, so a rule change moves every admission out of reach and the
// flow is evaluated again. Changing a rule therefore has to stop
// traffic the old rules already let through.
//
// A curl probe cannot show that. Each request opens a new source port,
// so it builds a conntrack key the data plane has never seen and would
// be evaluated against the new rules whether or not the generation
// moved. These specs hold one TCP connection open instead: the sink Pod
// appends whatever arrives to a file, the source Pod sends a line a
// second down a single connection, and the assertion is about the file
// growing and then not growing.

const (
	policyStreamPort = 9000
	policyStreamSink = "/tmp/received"
	policyStreamLine = "policy-epoch-probe"

	// policyStreamSample is how far apart two size readings are taken.
	// The source writes once a second, so a sample this wide sees
	// several lines when the flow is live.
	policyStreamSample = 3 * time.Second
	// policyStreamQuiet is how long the sink has to stay silent after
	// the rules stop admitting the flow.
	policyStreamQuiet = 10 * time.Second
)

var _ = Describe("Juneau policy epoch", func() {
	DescribeTable("a rule change stops a flow the data plane already admitted",
		runPolicyEpochScenario,
		Entry("NetworkACL", policyLayerACL),
		Entry("SecurityGroup", policyLayerSG),
	)
})

func runPolicyEpochScenario(layer policyLayer) {
	fix := newPolicyFixture(sanitizeName("policy-epoch-" + string(layer)))
	DeferCleanup(fix.Cleanup)
	fix.applyPlacement(placementSameNode)
	fix.CreateNetwork()

	var serverSGs, clientSGs []string
	if layer.usesSG() {
		fix.CreateSG("client-sg", policySGEgressAllowAll)
		fix.CreateSG("server-sg", policySGIngressPort(policyStreamPort))
		serverSGs = []string{"server-sg"}
		clientSGs = []string{"client-sg"}
	}
	if layer.usesACL() {
		fix.CreateACL("policy-acl", policyACLIngressPort(policyStreamPort))
		fix.AttachACL(fix.serverSubnet, "policy-acl")
		fix.AttachACL(fix.clientSubnet, "policy-acl")
	}

	By("opening a long-lived connection the rules admit")
	fix.CreatePodWithContainers(serverPodName, fix.serverSubnet, fix.serverNode,
		streamSinkContainer(policyStreamPort, policyStreamSink), serverSGs)
	waitPodsReady(fix.namespace, serverPodName)

	serverIP := mustPodIP(fix.namespace, serverPodName)
	fix.CreatePodWithContainers(clientPodName, fix.clientSubnet, fix.clientNode,
		streamSourceContainer(serverIP, policyStreamPort), clientSGs)
	waitPodsReady(fix.namespace, clientPodName)

	waitStreamGrows(fix.namespace, serverPodName, policyStreamSink)

	By("taking the admission away")
	if layer.usesSG() {
		fix.ReplaceSGRules("server-sg", policySGIngressFromElsewhere(policyStreamPort))
	}
	if layer.usesACL() {
		fix.ReplaceACLRules("policy-acl", policyACLIngressDeny)
	}

	By("requiring the flow that was already running to stop")
	settled := waitStreamStops(fix.namespace, serverPodName, policyStreamSink)
	Consistently(func(g Gomega) {
		g.Expect(streamBytes(g, fix.namespace, serverPodName, policyStreamSink)).To(Equal(settled))
	}, policyStreamQuiet, policyStreamSample).Should(Succeed())
}

// streamBytes reports how much the sink Pod has appended so far.
func streamBytes(g Gomega, namespace string, pod string, path string) int {
	out, err := kubectlOutput(repoRoot, "exec", "-n", namespace, pod, "--", "sh", "-c", "wc -c < "+path)
	g.Expect(err).NotTo(HaveOccurred(), "wc output: %s", out)

	size, convErr := strconv.Atoi(strings.TrimSpace(out))
	g.Expect(convErr).NotTo(HaveOccurred(), "unexpected wc output: %q", out)
	return size
}

// waitStreamGrows waits until two readings one sample apart differ,
// which is the point where the connection is established and carrying
// data.
func waitStreamGrows(namespace string, pod string, path string) {
	Eventually(func(g Gomega) {
		before := streamBytes(g, namespace, pod, path)
		time.Sleep(policyStreamSample)
		g.Expect(streamBytes(g, namespace, pod, path)).To(BeNumerically(">", before))
	}).Should(Succeed())
}

// waitStreamStops waits until two readings one sample apart match and
// reports the size the sink settled at.
//
// The size has to be above zero: a sink container that restarted
// truncates the file, and a stuck-at-zero file would otherwise read as
// a flow that stopped.
func waitStreamStops(namespace string, pod string, path string) int {
	var settled int
	Eventually(func(g Gomega) {
		before := streamBytes(g, namespace, pod, path)
		time.Sleep(policyStreamSample)
		after := streamBytes(g, namespace, pod, path)
		g.Expect(after).To(BeNumerically(">", 0))
		g.Expect(after).To(Equal(before))
		settled = after
	}).Should(Succeed())
	return settled
}

// streamSinkContainer listens on `port` and appends everything it reads
// to `sink`. Only options every busybox nc build carries are used: -l
// to listen and -p to pick the port. busybox nc serves one connection
// and exits, so the loop puts the listener back.
func streamSinkContainer(port int, sink string) string {
	return fmt.Sprintf(`    - name: server
      image: %s
      command:
        - /bin/sh
        - -c
        - |
          : > %s
          while true; do
            nc -l -p %d >> %s
            sleep 1
          done
      ports:
        - containerPort: %d`, busyboxImage, sink, port, sink, port)
}

// streamSourceContainer sends one line a second down a single
// connection. The outer loop only exists to cover the gap between the
// sink Pod becoming Ready and its listener binding; once the rules stop
// admitting the flow, the reconnect attempts get dropped too.
func streamSourceContainer(serverIP string, port int) string {
	return fmt.Sprintf(`    - name: client
      image: %s
      command:
        - /bin/sh
        - -c
        - |
          while true; do
            while true; do echo %s; sleep 1; done | nc %s %d
            sleep 2
          done`, busyboxImage, policyStreamLine, serverIP, port)
}
