package e2e

import (
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type bgpNodeStateObject struct {
	Metadata bgpNodeStateMeta   `json:"metadata"`
	Status   bgpNodeStateStatus `json:"status"`
}

type bgpNodeStateMeta struct {
	Name string `json:"name"`
}

type bgpNodeStateStatus struct {
	Heartbeat      string                       `json:"heartbeat,omitempty"`
	BGPSessions    []bgpNodeStateSession        `json:"bgpSessions,omitempty"`
	Advertisements []bgpNodeStateAdvertisement  `json:"advertisements,omitempty"`
	Conditions     []bgpNodeStateConditionEntry `json:"conditions,omitempty"`
	Errors         []bgpNodeStateError          `json:"errors,omitempty"`
}

type bgpNodeStateSession struct {
	PeerAddress string `json:"peerAddress,omitempty"`
	PeerName    string `json:"peerName,omitempty"`
	State       string `json:"state,omitempty"`
	UpSince     string `json:"upSince,omitempty"`
	LastError   string `json:"lastError,omitempty"`
}

type bgpNodeStateAdvertisement struct {
	AddressPool  string   `json:"addressPool,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
	LastSyncedAt string   `json:"lastSyncedAt,omitempty"`
}

type bgpNodeStateConditionEntry struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type bgpNodeStateError struct {
	ResourceKind string `json:"resourceKind,omitempty"`
	ResourceName string `json:"resourceName,omitempty"`
	Message      string `json:"message,omitempty"`
}

func getBGPNodeState(name string) (*bgpNodeStateObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "bgpnodestate", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var obj bgpNodeStateObject
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, fmt.Errorf("decode bgpnodestate/%s: %w", name, err)
	}
	return &obj, nil
}

func findSessionByPeerAddress(sessions []bgpNodeStateSession, peerAddress string) *bgpNodeStateSession {
	for i := range sessions {
		if sessions[i].PeerAddress == peerAddress {
			return &sessions[i]
		}
	}
	return nil
}

func findAdvertisementByPool(adverts []bgpNodeStateAdvertisement, pool string) *bgpNodeStateAdvertisement {
	for i := range adverts {
		if adverts[i].AddressPool == pool {
			return &adverts[i]
		}
	}
	return nil
}

func conditionStatus(conditions []bgpNodeStateConditionEntry, conditionType string) string {
	for _, c := range conditions {
		if c.Type == conditionType {
			return c.Status
		}
	}
	return ""
}

func applyBGPPeer(name string, peerAddress string) error {
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: BGPPeer
metadata:
  name: %s
spec:
  myASN: %d
  peerASN: %d
  peerAddress: %s
`, name, bgpLocalAS, bgpRouterAS, peerAddress)
	return applyManifest(manifest)
}

func applyAddressPool(name string, addresses []string) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: AddressPool
metadata:
  name: %s
spec:
  advertiseMode: bgp
  addresses:
`, name))
	for _, a := range addresses {
		b.WriteString(fmt.Sprintf("    - %s\n", a))
	}
	return applyManifest(b.String())
}

func applyBGPAdvertisement(name string, pools []string) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: BGPAdvertisement
metadata:
  name: %s
spec:
  addressPools:
`, name))
	for _, p := range pools {
		b.WriteString(fmt.Sprintf("    - %s\n", p))
	}
	return applyManifest(b.String())
}

func applyExternalNetwork(name string, pools []string) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: ExternalNetwork
metadata:
  name: %s
spec:
  type: bgp
  addressPools:
`, name))
	for _, p := range pools {
		b.WriteString(fmt.Sprintf("    - %s\n", p))
	}
	return applyManifest(b.String())
}

func applyElasticIP(namespace string, name string, externalNetwork string) error {
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: ElasticIP
metadata:
  namespace: %s
  name: %s
spec:
  externalNetwork: %s
`, namespace, name, externalNetwork)
	return applyManifest(manifest)
}

func applyElasticIPAttachment(namespace string, name string, eipName string, networkInterfaceName string) error {
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: ElasticIPAttachment
metadata:
  namespace: %s
  name: %s
spec:
  elasticIPRef:
    name: %s
  targetRef:
    networkInterfaceName: %s
`, namespace, name, eipName, networkInterfaceName)
	return applyManifest(manifest)
}

func waitBGPSessionUp(node string, peerAddress string, peerName string) {
	Eventually(func(g Gomega) {
		state, err := getBGPNodeState(node)
		g.Expect(err).NotTo(HaveOccurred())
		session := findSessionByPeerAddress(state.Status.BGPSessions, peerAddress)
		g.Expect(session).NotTo(BeNil(), "node %s missing BGP session for %s", node, peerAddress)
		g.Expect(session.State).To(Equal("Up"), "node %s session state %q", node, session.State)
		g.Expect(session.UpSince).NotTo(BeEmpty(), "node %s session upSince empty", node)
		g.Expect(session.PeerName).To(Equal(peerName), "node %s session peerName mismatch", node)
		g.Expect(conditionStatus(state.Status.Conditions, "Ready")).To(Equal("True"), "node %s Ready condition", node)
		g.Expect(conditionStatus(state.Status.Conditions, "BirdRunning")).To(Equal("True"), "node %s BirdRunning condition", node)
		g.Expect(conditionStatus(state.Status.Conditions, "BMPConnected")).To(Equal("True"), "node %s BMPConnected condition", node)
	}).Should(Succeed())
}

func waitBGPSessionDown(node string, peerAddress string) {
	Eventually(func(g Gomega) {
		state, err := getBGPNodeState(node)
		g.Expect(err).NotTo(HaveOccurred())
		session := findSessionByPeerAddress(state.Status.BGPSessions, peerAddress)
		g.Expect(session).NotTo(BeNil(), "node %s missing BGP session for %s", node, peerAddress)
		g.Expect(session.State).NotTo(Equal("Up"), "node %s session unexpectedly Up", node)
		g.Expect(session.LastError).NotTo(BeEmpty(), "node %s lastError should be set after disconnect", node)
	}).Should(Succeed())
}

func waitBGPAdvertisement(node string, pool string, prefix string) {
	Eventually(func(g Gomega) {
		state, err := getBGPNodeState(node)
		g.Expect(err).NotTo(HaveOccurred())
		adv := findAdvertisementByPool(state.Status.Advertisements, pool)
		g.Expect(adv).NotTo(BeNil(), "node %s missing advertisement for pool %s", node, pool)
		g.Expect(adv.Prefixes).To(ContainElement(prefix), "node %s advertisement prefixes %v", node, adv.Prefixes)
	}).Should(Succeed())
}

func waitBirdRouteOnRouter(router *bgpRouterInstance, prefix string, expectedNextHopCount int) {
	Eventually(func(g Gomega) {
		out, err := router.Exec("birdc", "show", "route", prefix)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring(prefix), "birdc output: %s", out)

		kernelOut, err := router.Exec("ip", "route", "show", prefix)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(kernelOut).NotTo(BeEmpty(), "kernel route for %s missing", prefix)

		if expectedNextHopCount > 1 {
			g.Expect(strings.Count(kernelOut, "nexthop")).To(BeNumerically(">=", expectedNextHopCount-1),
				"expected ECMP, got: %s", kernelOut)
		}
	}).Should(Succeed())
}

func waitElasticIPAddress(namespace string, name string) string {
	var address string
	Eventually(func(g Gomega) {
		addr, err := kubectlJSONPath(repoRoot, `{.status.address}`, "-n", namespace, "get", "elasticip", name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(addr)).NotTo(BeEmpty(), "elasticip %s address empty", name)
		address = strings.TrimSpace(addr)
	}).Should(Succeed())
	return address
}

func waitElasticIPAttached(namespace string, name string) {
	Eventually(func(g Gomega) {
		phase, err := kubectlJSONPath(repoRoot, `{.status.phase}`, "-n", namespace, "get", "elasticip", name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(phase)).To(Equal("Attached"), "elasticip %s phase", name)
	}).Should(Succeed())
}

func waitElasticIPAttachmentReady(namespace string, name string) {
	Eventually(func(g Gomega) {
		ready, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].status}`, "-n", namespace, "get", "elasticipattachment", name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(ready)).To(Equal("True"), "elasticipattachment %s Ready", name)

		phase, err := kubectlJSONPath(repoRoot, `{.status.phase}`, "-n", namespace, "get", "elasticipattachment", name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(phase)).To(Equal("Attached"), "elasticipattachment %s phase", name)
	}).Should(Succeed())
}

func dumpBGPDiagnostics(router *bgpRouterInstance) {
	dumpResource("bgpnodestates")
	for _, node := range workerNodes {
		out, err := kubectlOutput(repoRoot, "get", "bgpnodestate", node, "-o", "yaml")
		if err != nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "failed to dump bgpnodestate %s: %v\n", node, err)
			continue
		}
		_, _ = fmt.Fprintf(GinkgoWriter, "\nbgpnodestate %s\n%s\n", node, out)
	}
	dumpResource("bgppeers")
	dumpResource("bgpadvertisements")
	dumpResource("addresspools")
	dumpResource("externalnetworks")
	dumpResource("elasticips", "-A")
	dumpResource("elasticipattachments", "-A")

	if router == nil {
		return
	}
	if out, err := router.Exec("birdc", "show", "protocols", "all"); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "\nrouter birdc show protocols all\n%s\n", out)
	}
	if out, err := router.Exec("birdc", "show", "route"); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "\nrouter birdc show route\n%s\n", out)
	}
	if out, err := router.Exec("ip", "route"); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "\nrouter ip route\n%s\n", out)
	}
}
