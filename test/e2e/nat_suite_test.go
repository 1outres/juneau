package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type natGatewayObject struct {
	Metadata natGatewayMeta   `json:"metadata"`
	Spec     natGatewaySpec   `json:"spec"`
	Status   natGatewayStatus `json:"status"`
}

type natGatewayMeta struct {
	Name string `json:"name"`
}

type natGatewaySpec struct {
	Vpc             string `json:"vpc"`
	ExternalNetwork string `json:"externalNetwork"`
}

type natGatewayStatus struct {
	GatewayID  uint32                       `json:"gatewayID,omitempty"`
	Conditions []bgpNodeStateConditionEntry `json:"conditions,omitempty"`
}

type externalNetworkAttachmentObject struct {
	Metadata externalNetworkAttachmentMeta   `json:"metadata"`
	Spec     externalNetworkAttachmentSpec   `json:"spec"`
	Status   externalNetworkAttachmentStatus `json:"status"`
}

type externalNetworkAttachmentList struct {
	Items []externalNetworkAttachmentObject `json:"items"`
}

type externalNetworkAttachmentMeta struct {
	Name            string                              `json:"name"`
	OwnerReferences []externalNetworkAttachmentOwnerRef `json:"ownerReferences,omitempty"`
}

type externalNetworkAttachmentOwnerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type externalNetworkAttachmentSpec struct {
	ExternalNetwork string `json:"externalNetwork"`
	NodeName        string `json:"nodeName"`
}

type externalNetworkAttachmentStatus struct {
	AssignedIP string                       `json:"assignedIP,omitempty"`
	Conditions []bgpNodeStateConditionEntry `json:"conditions,omitempty"`
}

type routeTableObject struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Status struct {
		TableID    uint32                       `json:"tableID,omitempty"`
		Routes     []routeTableRoute            `json:"routes,omitempty"`
		Conditions []bgpNodeStateConditionEntry `json:"conditions,omitempty"`
	} `json:"status"`
}

type routeTableRoute struct {
	Dst string `json:"dst"`
	Via struct {
		Type       string `json:"type"`
		NATGateway string `json:"natGateway,omitempty"`
	} `json:"via"`
}

func applyNATGateway(name, vpc, externalNetwork string) error {
	manifest := fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: NATGateway
metadata:
  name: %s
spec:
  vpc: %s
  externalNetwork: %s
`, name, vpc, externalNetwork)
	return applyManifest(manifest)
}

func getNATGateway(name string) (*natGatewayObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "natgateway", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var obj natGatewayObject
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, fmt.Errorf("decode natgateway/%s: %w", name, err)
	}
	return &obj, nil
}

func waitNATGatewayReady(name string) {
	Eventually(func(g Gomega) {
		obj, err := getNATGateway(name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(obj.Status.GatewayID).NotTo(BeZero(), "natgateway %s missing GatewayID", name)
		g.Expect(conditionStatus(obj.Status.Conditions, "Ready")).To(Equal("True"), "natgateway %s Ready condition", name)
	}).Should(Succeed())
}

func listExternalNetworkAttachments() ([]externalNetworkAttachmentObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "externalnetworkattachments", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list externalNetworkAttachmentList
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("decode externalnetworkattachments: %w", err)
	}
	return list.Items, nil
}

// attachmentIPForNode returns the address the ExternalNetwork assigned to
// the given Node. That address is the NAPT source every Pod on the Node
// egresses with.
func attachmentIPForNode(externalNetwork string, node string) string {
	var assignedIP string
	Eventually(func(g Gomega) {
		attachments, err := listExternalNetworkAttachments()
		g.Expect(err).NotTo(HaveOccurred())
		for _, att := range attachments {
			if att.Spec.ExternalNetwork != externalNetwork || att.Spec.NodeName != node {
				continue
			}
			assignedIP = strings.TrimSpace(att.Status.AssignedIP)
			g.Expect(assignedIP).NotTo(BeEmpty(), "attachment %s missing AssignedIP", att.Metadata.Name)
			return
		}
		g.Expect(false).To(BeTrue(), "no attachment found for node %s on %s", node, externalNetwork)
	}).Should(Succeed())
	return assignedIP
}

// waitRouterLearnsNAPTPrefix blocks until the opposing router has a route
// for the Node's NAPT address with that Node as the next hop. Until it
// does, a reply has nowhere to go and every data-plane assertion below
// would fail for a reason that has nothing to do with the data plane.
func waitRouterLearnsNAPTPrefix(router *bgpRouterInstance, node string, prefix string) {
	Eventually(func(g Gomega) {
		out, err := router.Exec("birdc", "show", "route", prefix, "all")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring(router.workerIPs[node]),
			"expected next-hop %s in birdc output: %s", router.workerIPs[node], out)
	}).Should(Succeed())
}

// The network every ICMP-error spec aims at, whether the Pod sits behind
// a NATGateway or an ElasticIP. Nothing lives there; it exists so the
// opposing router has something to forward towards and therefore
// something to raise ICMP errors about.
const (
	natBeyondCIDR = "198.18.0.0/30"
	natBeyondHost = "198.18.0.2"
	natBeyondMTU  = 1280
	// Payload size for the PMTUD probe. 1300 + 8 (ICMP) + 20 (IP) is over
	// natBeyondMTU but still under the VXLAN-reduced Pod MTU.
	natPMTUDPayload = "1300"
)

// setupRouterBeyondNetwork makes the opposing router act like a router
// rather than an endpoint: it gains an on-link route to a network where
// nothing answers, capped at a small MTU. Traffic aimed there is
// forwarded, so a TTL-limited probe comes back as ICMP Time Exceeded and
// an oversized one as ICMP Fragmentation Needed. Nothing has to answer
// on the far side — the error messages are the whole point, and an
// unanswered ARP is what stops the packet.
//
// The route carries an explicit mtu because the forwarding path always
// honours a route metric, and every interface in the container sits at
// the host MTU.
//
// Every Node gets a matching route so the packet leaves the Node
// straight at the router, which makes the router hop 1 for a traceroute
// started inside a Pod.
//
// ip_forward is only written when it is off, because some container
// runtimes mount /proc/sys read-only while already having forwarding
// enabled. A write that is not needed must not fail the setup; a write
// that is needed still does.
func setupRouterBeyondNetwork(router *bgpRouterInstance, nodes []string) {
	By(fmt.Sprintf("turning the opposing router into a router towards %s (mtu %d)", natBeyondCIDR, natBeyondMTU))
	script := fmt.Sprintf(`set -eu
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]; then
  sysctl -wq net.ipv4.ip_forward=1
fi
uplink=$(ip -o -4 route show default | awk '{print $5; exit}')
ip route replace %s dev "$uplink" mtu %d
`, natBeyondCIDR, natBeyondMTU)
	out, err := router.Exec("sh", "-c", script)
	Expect(err).NotTo(HaveOccurred(), "router setup output: %s", out)

	for _, node := range nodes {
		out, err := dockerExecOutput(node, "ip", "route", "replace", natBeyondCIDR, "via", router.ip)
		Expect(err).NotTo(HaveOccurred(), "node %s route output: %s", node, out)
	}
}

func teardownRouterBeyondNetwork(router *bgpRouterInstance, nodes []string) {
	for _, node := range nodes {
		_, _ = dockerExecOutput(node, "ip", "route", "del", natBeyondCIDR)
	}
	if router != nil {
		_, _ = router.Exec("ip", "route", "del", natBeyondCIDR)
	}
}

// routerSecondaryAddress is an extra address the opposing router carries
// on the link it shares with the Nodes.
type routerSecondaryAddress struct {
	IP   string
	CIDR string
}

// addRouterSecondaryAddress gives the opposing router a second address on
// the link it shares with the Nodes, and returns it.
//
// A spec about neighbor resolution needs a next hop that nothing else on
// the Node ever talks to. The router's primary address does not qualify:
// the BGP session keeps its neighbor entry warm, so the entry would come
// back on its own and the spec would pass without the data plane having
// done anything. The address is taken from the top of the docker network
// prefix, which docker hands out from the bottom, so it does not collide
// with a container.
func addRouterSecondaryAddress(router *bgpRouterInstance) routerSecondaryAddress {
	subnet := kindNetworkIPv4Subnet()
	_, prefix, err := net.ParseCIDR(subnet)
	Expect(err).NotTo(HaveOccurred(), "parse docker network subnet %q", subnet)

	base := prefix.IP.To4()
	secondary := make(net.IP, len(base))
	for i := range base {
		secondary[i] = base[i] | ^prefix.Mask[i]
	}
	secondary[len(secondary)-1]--
	ones, _ := prefix.Mask.Size()
	addr := routerSecondaryAddress{
		IP:   secondary.String(),
		CIDR: fmt.Sprintf("%s/%d", secondary, ones),
	}

	By(fmt.Sprintf("giving the opposing router a second address %s", addr.CIDR))
	out, err := router.Exec("sh", "-c", fmt.Sprintf(`set -eu
uplink=$(ip -o -4 route show default | awk '{print $5; exit}')
ip addr replace %s dev "$uplink"
`, addr.CIDR))
	Expect(err).NotTo(HaveOccurred(), "router address setup output: %s", out)
	return addr
}

// removeRouterSecondaryAddress drops the address again. Best effort: the
// router container may already be gone, which takes the address with it.
func removeRouterSecondaryAddress(router *bgpRouterInstance, addr routerSecondaryAddress) {
	_, _ = router.Exec("sh", "-c", fmt.Sprintf(`uplink=$(ip -o -4 route show default | awk '{print $5; exit}')
ip addr del %s dev "$uplink"
`, addr.CIDR))
}

// kindNetworkIPv4Subnet returns the IPv4 prefix of the docker network the
// Nodes and the opposing router share.
func kindNetworkIPv4Subnet() string {
	out, err := dockerOutput("network", "inspect", "-f",
		"{{range .IPAM.Config}}{{.Subnet}} {{end}}", kindDockerNetwork)
	Expect(err).NotTo(HaveOccurred(), "docker network inspect %s", kindDockerNetwork)
	for subnet := range strings.FieldsSeq(out) {
		if ip, _, err := net.ParseCIDR(subnet); err == nil && ip.To4() != nil {
			return subnet
		}
	}
	Fail(fmt.Sprintf("docker network %s has no IPv4 subnet: %q", kindDockerNetwork, out))
	return ""
}

func getRouteTableObject(name string) (*routeTableObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "routetable", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var obj routeTableObject
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, fmt.Errorf("decode routetable/%s: %w", name, err)
	}
	return &obj, nil
}

func dumpNATDiagnostics() {
	dumpResource("natgateways")
	dumpResource("externalnetworkattachments")
	dumpResource("externalnetworks")
	dumpResource("addresspools")
	dumpResource("routetables")
}
