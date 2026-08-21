package e2e

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/gomega"
)

const (
	arpClientContainerName = "juneau-e2e-arp-client"
	arpClientImage         = "alpine:3.23"
	arpClientReadyTimeout  = 3 * time.Minute
	arpProbeCount          = 3
	arpProbeDeadline       = "5"
)

// arpClientInstance is a plain container on the docker network the Nodes
// share. ARP mode puts the external addresses on that same link, so the
// client resolves them itself and no router sits in between. It also serves
// a one-line page so the NAT egress spec can read the source address a Pod
// reached it with.
type arpClientInstance struct {
	name string
	ip   string
}

func ensureARPClient() (*arpClientInstance, error) {
	inst := &arpClientInstance{name: arpClientContainerName}

	runBestEffort(repoRoot, "docker", "rm", "-f", inst.name)

	// httpd needs -f -v for the same reason the BGP router does: -f keeps
	// it in the foreground so its access log stays on the container's
	// stderr and `docker logs` can read it.
	entrypoint := "set -e; " +
		"apk add --no-cache iproute2 busybox-extras curl >/dev/null; " +
		"mkdir -p /www && echo ok > /www/index.html; " +
		"exec httpd -f -v -p 80 -h /www"
	if err := run(repoRoot, "docker", "run", "-d",
		"--name", inst.name,
		"--network", kindDockerNetwork,
		"--cap-add", "NET_ADMIN",
		"--entrypoint", "sh",
		arpClientImage,
		"-c", entrypoint,
	); err != nil {
		return nil, fmt.Errorf("start arp client container: %w", err)
	}

	ip, err := discoverRouterIP(inst.name)
	if err != nil {
		return nil, fmt.Errorf("discover arp client IP: %w", err)
	}
	inst.ip = ip

	if err := inst.waitReady(arpClientReadyTimeout); err != nil {
		return nil, fmt.Errorf("wait arp client ready: %w", err)
	}
	return inst, nil
}

func teardownARPClient() {
	if strings.EqualFold(os.Getenv("E2E_KEEP_CLUSTER"), "true") {
		return
	}
	runBestEffort(repoRoot, "docker", "rm", "-f", arpClientContainerName)
}

func (c *arpClientInstance) Exec(args ...string) (string, error) {
	return dockerOutput(append([]string{"exec", c.name}, args...)...)
}

func (c *arpClientInstance) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := c.Exec("sh", "-c", "command -v arping >/dev/null && command -v curl >/dev/null && command -v ip >/dev/null")
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("arp client tools never became available: %w", err)
		}
		time.Sleep(2 * time.Second)
	}
}

// arping asks the shared link who owns address and returns the combined
// output. -b keeps every probe a broadcast, so each node gets the chance to
// answer and a second answering node shows up as a second reply. Without it
// busybox unicasts follow-up probes at whoever replied first and a
// split-brain would stay invisible. A missing answer is an ordinary result
// here, so the exit status is returned rather than raised.
func (c *arpClientInstance) arping(address string) (string, error) {
	return c.Exec("sh", "-c", fmt.Sprintf("arping -b -c %d -w %s %s 2>&1",
		arpProbeCount, arpProbeDeadline, address))
}

// flushNeighbor drops the client's neighbor entry for address. juneau sends
// no gratuitous ARP, so after an address moves to another node the client
// keeps using the old MAC until its own entry ages out.
func (c *arpClientInstance) flushNeighbor(address string) error {
	_, err := c.Exec("ip", "neigh", "flush", "to", address)
	return err
}

func (c *arpClientInstance) curl(url string) (string, error) {
	return c.Exec("curl", "-sS", "--max-time", "5", url)
}

var arpReplyMACPattern = regexp.MustCompile(`reply from \S+ \[([0-9a-fA-F:]{17})\]`)

// arpReplyMACs returns the distinct MACs that answered, in the order they
// first appeared. The same node answering several probes is one MAC; two
// MACs mean two nodes answered for one address.
func arpReplyMACs(output string) []string {
	seen := make(map[string]struct{})
	macs := []string{}
	for _, match := range arpReplyMACPattern.FindAllStringSubmatch(output, -1) {
		mac := strings.ToLower(match[1])
		if _, ok := seen[mac]; ok {
			continue
		}
		seen[mac] = struct{}{}
		macs = append(macs, mac)
	}
	return macs
}

// assertARPAnsweredBy requires address to be answered by exactly one MAC,
// the NIC of node. One MAC is as much of the claim as the reply itself: an
// address belongs to a single node, so a second MAC means a second node also
// answers and the peers' neighbor entries would disagree on where to send.
func assertARPAnsweredBy(client *arpClientInstance, address string, node string) {
	expected := nodeExternalMAC(node)
	Eventually(func(g Gomega) {
		g.Expect(client.flushNeighbor(address)).To(Succeed())
		out, _ := client.arping(address)
		g.Expect(arpReplyMACs(out)).To(ConsistOf(expected),
			"expected only %s (%s) to answer for %s; arping output: %s", node, expected, address, out)
	}).Should(Succeed())
}

// nodeExternalMAC returns the MAC of the NIC carrying the Node's InternalIP.
// That NIC is the one the daemon answers ARP on by default, so its MAC is
// what an ARP reply for a juneau-owned address must carry.
func nodeExternalMAC(node string) string {
	address := nodeInternalIP(node)
	script := fmt.Sprintf(`set -eu
iface=$(ip -o -4 addr show | awk -v ip=%q 'index($4, ip "/") == 1 {print $2; exit}')
cat /sys/class/net/"$iface"/address
`, address)
	out, err := dockerExecOutput(node, "sh", "-c", script)
	Expect(err).NotTo(HaveOccurred(), "read NIC MAC on node %s: %s", node, out)

	mac := strings.ToLower(strings.TrimSpace(out))
	Expect(mac).NotTo(BeEmpty(), "node %s has no MAC on the NIC holding %s", node, address)
	return mac
}

func nodeInternalIP(node string) string {
	out, err := kubectlJSONPath(repoRoot, `{.status.addresses[?(@.type=="InternalIP")].address}`, "get", "node", node)
	Expect(err).NotTo(HaveOccurred())
	address := strings.TrimSpace(out)
	Expect(address).NotTo(BeEmpty(), "node %s has no InternalIP", node)
	return address
}

// arpAddressBlock is an inclusive address range an ARP-mode AddressPool is
// written from.
type arpAddressBlock struct {
	Start string
	End   string
}

func (b arpAddressBlock) poolEntry() string {
	return b.Start + "-" + b.End
}

// arpReservedTopAddresses keeps the two highest addresses of the docker
// network out of every block: the broadcast address, and the one below it
// that addRouterSecondaryAddress hands to the opposing router.
const arpReservedTopAddresses = 2

// newARPAddressBlock carves a block of size addresses out of the top of the
// docker network the Nodes share, skipping offsetFromTop addresses below the
// reserved ones. ARP mode needs the external addresses on the Nodes' own
// link, and docker allocates container addresses from the bottom of the
// prefix, so the top is both reachable and free.
func newARPAddressBlock(offsetFromTop, size int) arpAddressBlock {
	Expect(size).To(BeNumerically(">", 0), "address block size must be positive")

	subnet := kindNetworkIPv4Subnet()
	_, prefix, err := net.ParseCIDR(subnet)
	Expect(err).NotTo(HaveOccurred(), "parse docker network subnet %q", subnet)

	base := prefix.IP.To4()
	Expect(base).NotTo(BeNil(), "docker network subnet %q is not IPv4", subnet)

	broadcast := make(net.IP, len(base))
	for i := range base {
		broadcast[i] = base[i] | ^prefix.Mask[i]
	}

	end := binary.BigEndian.Uint32(broadcast) - arpReservedTopAddresses - uint32(offsetFromTop)
	start := end - uint32(size) + 1
	Expect(start).To(BeNumerically(">", binary.BigEndian.Uint32(base)),
		"docker network subnet %q is too small for a block of %d addresses", subnet, size)

	return arpAddressBlock{Start: uint32ToIPv4(start), End: uint32ToIPv4(end)}
}

func uint32ToIPv4(value uint32) string {
	address := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(address, value)
	return address.String()
}

func applyARPAddressPool(name string, addresses []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, `apiVersion: juneau.loutres.me/v1alpha1
kind: AddressPool
metadata:
  name: %s
spec:
  advertiseMode: arp
  addresses:
`, name)
	for _, a := range addresses {
		fmt.Fprintf(&b, "    - %s\n", a)
	}
	return applyManifest(b.String())
}

func applyARPExternalNetwork(name string, pools []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, `apiVersion: juneau.loutres.me/v1alpha1
kind: ExternalNetwork
metadata:
  name: %s
spec:
  type: arp
  addressPools:
`, name)
	for _, p := range pools {
		fmt.Fprintf(&b, "    - %s\n", p)
	}
	return applyManifest(b.String())
}

type allocationPoolObject struct {
	Spec allocationPoolSpec `json:"spec"`
}

type allocationPoolSpec struct {
	IP allocationPoolIPSpec `json:"ip"`
}

type allocationPoolIPSpec struct {
	CIDRs  []string                `json:"cidrs,omitempty"`
	Ranges []allocationPoolIPRange `json:"ranges,omitempty"`
}

type allocationPoolIPRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

func getAllocationPool(name string) (*allocationPoolObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "allocationpool", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var obj allocationPoolObject
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, fmt.Errorf("decode allocationpool/%s: %w", name, err)
	}
	return &obj, nil
}

type arpAdvertisementObject struct {
	Metadata arpAdvertisementMeta `json:"metadata"`
	Spec     arpAdvertisementSpec `json:"spec"`
}

type arpAdvertisementMeta struct {
	Name string `json:"name"`
}

type arpAdvertisementSpec struct {
	ExternalNetwork string `json:"externalNetwork"`
	Address         string `json:"address"`
	NodeName        string `json:"nodeName"`
}

type arpAdvertisementList struct {
	Items []arpAdvertisementObject `json:"items"`
}

func listARPAdvertisements() ([]arpAdvertisementObject, error) {
	out, err := kubectlOutput(repoRoot, "get", "arpadvertisements", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list arpAdvertisementList
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("decode arpadvertisements: %w", err)
	}
	return list.Items, nil
}

func arpAdvertisementsForAddress(address string) ([]arpAdvertisementObject, error) {
	items, err := listARPAdvertisements()
	if err != nil {
		return nil, err
	}
	matching := []arpAdvertisementObject{}
	for _, item := range items {
		if strings.TrimSpace(item.Spec.Address) == address {
			matching = append(matching, item)
		}
	}
	return matching, nil
}

// waitARPAdvertisementNode blocks until exactly one ARPAdvertisement claims
// address and returns the node it names.
func waitARPAdvertisementNode(address string) string {
	var node string
	Eventually(func(g Gomega) {
		items, err := arpAdvertisementsForAddress(address)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(items).To(HaveLen(1), "expected exactly one ARPAdvertisement for %s, got %v", address, items)
		node = strings.TrimSpace(items[0].Spec.NodeName)
		g.Expect(node).NotTo(BeEmpty(), "ARPAdvertisement %s names no node", items[0].Metadata.Name)
	}).Should(Succeed())
	return node
}

func waitServiceLoadBalancerVIP(namespace, name string) string {
	var vip string
	Eventually(func(g Gomega) {
		out, err := kubectlJSONPath(repoRoot, "{.status.loadBalancer.ingress[0].ip}",
			"-n", namespace, "get", "service", name)
		g.Expect(err).NotTo(HaveOccurred())
		vip = strings.TrimSpace(out)
		g.Expect(vip).NotTo(BeEmpty())
	}).Should(Succeed())
	return vip
}

func loadBalancerServiceManifest(namespace, name, externalNetwork, selector string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  namespace: %s
  name: %s
  annotations:
    juneau.loutres.me/load-balancer-external-network: %s
spec:
  type: LoadBalancer
  loadBalancerClass: juneau.loutres.me/load-balancer
  externalTrafficPolicy: Local
  selector:
    app: %s
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 80
`, namespace, name, externalNetwork, selector)
}

func dumpARPDiagnostics() {
	dumpResource("addresspools")
	dumpResource("allocationpools")
	dumpResource("externalnetworks")
	dumpResource("externalnetworkattachments")
	dumpResource("arpadvertisements")
	dumpResource("elasticips", "-A")
	dumpResource("elasticipattachments", "-A")
	dumpResource("serviceloadbalancers", "-A")
	dumpResource("natgateways")
}

// contains reports whether address falls inside the block. The allocator
// hands addresses out of the pool the block was written from, so this is how
// a spec checks it got one of ours rather than a coincidence.
func (b arpAddressBlock) contains(address string) bool {
	value := net.ParseIP(strings.TrimSpace(address)).To4()
	start := net.ParseIP(b.Start).To4()
	end := net.ParseIP(b.End).To4()
	if value == nil || start == nil || end == nil {
		return false
	}
	numeric := binary.BigEndian.Uint32(value)
	return numeric >= binary.BigEndian.Uint32(start) && numeric <= binary.BigEndian.Uint32(end)
}

// arpBackendPodManifest builds an nginx Pod carrying selector as its app
// label. The LoadBalancer specs put two Pods behind one Service, which the
// shared podManifest cannot express: it labels every Pod with its own name.
func arpBackendPodManifest(namespace, name, nodeName, subnet, selector string) string {
	annotation := ""
	if subnet != "" {
		annotation = fmt.Sprintf("  annotations:\n    juneau.loutres.me/subnet: %s\n", subnet)
	}

	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  namespace: %s
  name: %s
  labels:
    app: %s
%sspec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers:
    - name: server
      image: nginx:1.27
      ports:
        - containerPort: 80
`, namespace, name, selector, annotation, nodeName)
}
