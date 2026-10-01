package e2e

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	. "github.com/onsi/gomega"
)

const (
	vpnPoolName     = "e2e-vpn-public-pool"
	vpnExternalName = "e2e-vpn-public"
	vpnNATName      = "juneau-e2e-vpn-nat"
	vpnPrivateCIDR  = "172.29.251.0/24"
	vpnSiteASN      = 65072
	vpnCloudASN     = 65071
)

type vpnSite struct {
	name, peer, onPremIP, onPremCIDR, ikeID, psk string
	publicIP, cloudTunnelIP, siteTunnelIP        string
	privateIndex                                 int
	peerOwned                                    bool
}

type vpnFixture struct {
	namespace, vpc, subnet, subnetCIDR, natPublicIP string
	sites                                           []*vpnSite
	natOwned                                        bool
}

func newVPNFixture() *vpnFixture {
	return &vpnFixture{namespace: "e2e-vpn", vpc: "e2e-vpn-vpc", subnet: "e2e-vpn-subnet", subnetCIDR: "10.215.10.0/24"}
}

func (f *vpnFixture) Start() {
	createNamespace(f.namespace)
	block := newARPAddressBlock(80, 8)
	Expect(applyARPAddressPool(vpnPoolName, []string{block.poolEntry()})).To(Succeed())
	Expect(applyARPExternalNetwork(vpnExternalName, []string{vpnPoolName})).To(Succeed())
	Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: %s
spec:
  service:
    consume: true
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: %s
spec:
  vpc: %s
  cidr: %s
`, f.vpc, f.subnet, f.vpc, f.subnetCIDR))).To(Succeed())
	waitSubnetReady(f.subnet)

	Expect(run(repoRoot, "docker", "run", "-d", "--privileged", "--name", vpnNATName, "--network", kindDockerNetwork, "--entrypoint", "sh", vpnPeerImage, "-c", "sleep infinity")).To(Succeed())
	f.natOwned = true
	publicIP, err := dockerOutput("inspect", "-f", `{{(index .NetworkSettings.Networks "kind").IPAddress}}`, vpnNATName)
	Expect(err).NotTo(HaveOccurred())
	addr, err := netip.ParseAddr(strings.TrimSpace(publicIP))
	Expect(err).NotTo(HaveOccurred())
	Expect(addr.Is4()).To(BeTrue())
	f.natPublicIP = addr.String()
	_, err = dockerOutput("exec", vpnNATName, "sh", "-ec", fmt.Sprintf("sysctl -w net.ipv4.ip_forward=1; iptables -t nat -A POSTROUTING -s %s -o eth0 -j MASQUERADE", vpnPrivateCIDR))
	Expect(err).NotTo(HaveOccurred())
}

func (f *vpnFixture) Cleanup() {
	clearMainRouteTableRoutes(f.vpc)
	for _, site := range f.sites {
		runBestEffort(repoRoot, "kubectl", "delete", "vpn", site.name, "-n", f.namespace, "--ignore-not-found=true", "--wait=true", "--timeout=90s")
		if site.peerOwned {
			runBestEffort(repoRoot, "docker", "rm", "-f", site.peer)
		}
	}
	runBestEffort(repoRoot, "kubectl", "delete", "namespace", f.namespace, "--ignore-not-found=true", "--timeout=90s")
	runBestEffort(repoRoot, "kubectl", "delete", "subnet", f.subnet, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "vpc", f.vpc, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "externalnetwork", vpnExternalName, "--ignore-not-found=true")
	runBestEffort(repoRoot, "kubectl", "delete", "addresspool", vpnPoolName, "--ignore-not-found=true")
	if f.natOwned {
		runBestEffort(repoRoot, "docker", "rm", "-f", vpnNATName)
	}
}

func vpnContainerPID(name string) int {
	out, err := dockerOutput("inspect", "-f", "{{.State.Pid}}", name)
	Expect(err).NotTo(HaveOccurred())
	pid, err := strconv.Atoi(strings.TrimSpace(out))
	Expect(err).NotTo(HaveOccurred())
	Expect(pid).To(BeNumerically(">", 0))
	return pid
}

func vpnPrivateAddress(index, host int) string {
	return fmt.Sprintf("172.29.251.%d", index*4+host)
}

func (f *vpnFixture) AddSite(name, onPremIP, onPremCIDR string) *vpnSite {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	Expect(err).NotTo(HaveOccurred())
	site := &vpnSite{name: name, peer: "juneau-e2e-" + name, onPremIP: onPremIP, onPremCIDR: onPremCIDR, ikeID: "@" + name + ".example", psk: hex.EncodeToString(key), privateIndex: len(f.sites)}
	f.sites = append(f.sites, site)
	secret := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s-psk
  namespace: %s
stringData:
  psk: %s
`, site.name, f.namespace, site.psk)
	Expect(runWithStdin(repoRoot, secret, "kubectl", "apply", "-f", "-")).To(Succeed())
	Expect(applyManifest(fmt.Sprintf(`apiVersion: juneau.loutres.me/v1alpha1
kind: VPN
metadata:
  name: %s
  namespace: %s
spec:
  vpc: %s
  subnet: %s
  externalNetwork: %s
  localASN: %d
  remoteASN: %d
  peerIKEID: %q
  pskSecretRef:
    name: %s-psk
    key: psk
`, name, f.namespace, f.vpc, f.subnet, vpnExternalName, vpnCloudASN, vpnSiteASN, site.ikeID, name))).To(Succeed())
	return site
}

func (s *vpnSite) WaitEndpoint(namespace string) {
	Eventually(func(g Gomega) {
		for _, pair := range []struct {
			path  string
			value *string
		}{
			{"{.status.publicIP}", &s.publicIP}, {"{.status.localTunnelIP}", &s.cloudTunnelIP}, {"{.status.remoteTunnelIP}", &s.siteTunnelIP},
		} {
			out, err := kubectlJSONPath(repoRoot, pair.path, "-n", namespace, "get", "vpn", s.name)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).NotTo(BeEmpty())
			*pair.value = strings.TrimSpace(out)
		}
	}).Should(Succeed())
}

func (f *vpnFixture) RouteSites() {
	routes := make([]route, 0, len(f.sites))
	for _, site := range f.sites {
		routes = append(routes, vpnRoute(site.onPremCIDR, f.namespace, site.name))
	}
	setMainRouteTableRoutes(f.vpc, routes...)
	waitObservedGeneration("routetable", waitVpcMainRouteTable(f.vpc))
}

func vpnRoute(dst, namespace, name string) route {
	return route{Dst: dst, Via: routeVia{Type: "vpn", VPN: &vpnRouteRef{Namespace: namespace, Name: name}}}
}

func vpnPeerConfig(site *vpnSite, peerIP string) string {
	return fmt.Sprintf(`connections {
  branch {
    version = 2
    local_addrs = %s
    remote_addrs = %s
    proposals = aes256gcm16-prfsha384-ecp384
    encap = yes
    mobike = no
    dpd_delay = 5s
    local {
      auth = psk
      id = %s
    }
    remote {
      auth = psk
      id = %s
    }
    children {
      branch {
        local_ts = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        mode = tunnel
        if_id_in = 42
        if_id_out = 42
        esp_proposals = aes256gcm16-ecp384
        start_action = none
        dpd_action = start
      }
    }
  }
}
secrets {
  ike-branch {
    id-local = %s
    id-remote = %s
    secret = 0x%s
  }
}
`, peerIP, site.publicIP, site.ikeID, site.publicIP, site.ikeID, site.publicIP, hex.EncodeToString([]byte(site.psk)))
}

func (f *vpnFixture) Connect(site *vpnSite) {
	site.WaitEndpoint(f.namespace)
	Expect(run(repoRoot, "docker", "run", "-d", "--privileged", "--name", site.peer, "--network", "none", "--entrypoint", "sh", vpnPeerImage, "-c", "sleep infinity")).To(Succeed())
	site.peerOwned = true
	peerIP := vpnPrivateAddress(site.privateIndex, 2)
	natIP := vpnPrivateAddress(site.privateIndex, 1)
	natLink := fmt.Sprintf("jevn%d", site.privateIndex)
	peerLink := fmt.Sprintf("jevs%d", site.privateIndex)
	link := fmt.Sprintf(`trap 'ip link del %s 2>/dev/null || true; ip link del %s 2>/dev/null || true' EXIT
ip link add %s type veth peer name %s
ip link set %s netns %d
ip link set %s netns %d
`, natLink, peerLink, natLink, peerLink, natLink, vpnContainerPID(vpnNATName), peerLink, vpnContainerPID(site.peer))
	Expect(run(repoRoot, "docker", "run", "--rm", "--privileged", "--pid", "host", "--network", "host", "--entrypoint", "sh", vpnPeerImage, "-ec", link)).To(Succeed())
	_, err := dockerOutput("exec", vpnNATName, "sh", "-ec", fmt.Sprintf("ip addr add %s/30 dev %s; ip link set %s up", natIP, natLink, natLink))
	Expect(err).NotTo(HaveOccurred())
	_, err = dockerOutput("exec", site.peer, "sh", "-ec", fmt.Sprintf(`ip addr add %s/30 dev %s
ip link set %s up
ip route replace %s/32 via %s
ip link add ipsec0 type xfrm if_id 42 dev %s
ip addr add %s/32 dev ipsec0
ip link set ipsec0 up
ip route replace %s/32 dev ipsec0 src %s
ip addr add %s/32 dev lo
`, peerIP, peerLink, peerLink, site.publicIP, natIP, peerLink, site.siteTunnelIP, site.cloudTunnelIP, site.siteTunnelIP, site.onPremIP))
	Expect(err).NotTo(HaveOccurred())
	cfg := vpnPeerConfig(site, peerIP)
	Expect(runWithStdin(repoRoot, cfg, "docker", "exec", "-i", site.peer, "sh", "-c", "umask 077; cat > /etc/swanctl/swanctl.conf")).To(Succeed())
	bird := fmt.Sprintf(`router id %s;
protocol device {}
protocol kernel { ipv4 { import none; export all; }; }
protocol static injected { ipv4; route 198.18.99.0/24 blackhole; }
protocol static tunnelnext { ipv4; route %s/32 via "ipsec0"; }
protocol bgp juneau {
  local as %d;
  neighbor %s as %d;
  source address %s;
  multihop;
  ipv4 {
    import all;
    export filter { if proto = "injected" then accept; reject; };
  };
}
`, site.siteTunnelIP, site.cloudTunnelIP, vpnSiteASN, site.cloudTunnelIP, vpnCloudASN, site.siteTunnelIP)
	Expect(runWithStdin(repoRoot, bird, "docker", "exec", "-i", site.peer, "sh", "-c", "cat > /etc/bird.conf")).To(Succeed())
	_, err = dockerOutput("exec", "-d", site.peer, "/usr/lib/ipsec/charon")
	Expect(err).NotTo(HaveOccurred())
	Eventually(func(g Gomega) {
		_, err := dockerOutput("exec", site.peer, "swanctl", "--load-all")
		g.Expect(err).NotTo(HaveOccurred())
	}).Should(Succeed())
	_, err = dockerOutput("exec", site.peer, "bird", "-c", "/etc/bird.conf", "-s", "/run/bird.ctl")
	Expect(err).NotTo(HaveOccurred())
	Eventually(func(g Gomega) {
		_, err := dockerOutput("exec", site.peer, "swanctl", "--initiate", "--child", "branch")
		g.Expect(err).NotTo(HaveOccurred())
	}).Should(Succeed())
	Eventually(func(g Gomega) {
		out, err := dockerOutput("exec", site.peer, "birdc", "-s", "/run/bird.ctl", "show", "protocols", "all", "juneau")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(MatchRegexp(`(?m)BGP state:\s+Established`))
		out, err = dockerOutput("exec", site.peer, "birdc", "-s", "/run/bird.ctl", "show", "route", f.subnetCIDR)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring(f.subnetCIDR))
	}).Should(Succeed())
	EventualVPNReady(f.namespace, site.name)
}

func EventualVPNReady(namespace, name string) {
	Eventually(func(g Gomega) {
		out, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].status}`, "-n", namespace, "get", "vpn", name)
		g.Expect(err).NotTo(HaveOccurred())
		reason, err := kubectlJSONPath(repoRoot, `{.status.conditions[?(@.type=="Ready")].reason}`, "-n", namespace, "get", "vpn", name)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(Equal("True"), "VPN %s/%s reason: %s", namespace, name, reason)
	}).Should(Succeed())
}

func (s *vpnSite) Exec(args ...string) (string, error) {
	return dockerOutput(append([]string{"exec", s.peer}, args...)...)
}

func (s *vpnSite) TerminateSA() {
	sas, err := s.Exec("swanctl", "--list-sas")
	Expect(err).NotTo(HaveOccurred())
	if strings.Contains(sas, "branch: #") {
		_, err = s.Exec("swanctl", "--terminate", "--ike", "branch")
		Expect(err).NotTo(HaveOccurred())
	}
}

func (s *vpnSite) AssertTunnelEstablished() {
	sas, err := s.Exec("swanctl", "--list-sas")
	Expect(err).NotTo(HaveOccurred())
	Expect(sas).To(MatchRegexp(`(?m)branch: #\d+, ESTABLISHED`))
	Expect(sas).To(MatchRegexp(`(?m)branch: #\d+, reqid \d+, INSTALLED`))
	protocols, err := s.Exec("birdc", "-s", "/run/bird.ctl", "show", "protocols", "all", "juneau")
	Expect(err).NotTo(HaveOccurred())
	Expect(protocols).To(MatchRegexp(`(?m)BGP state:\s+Established`))
}

func (s *vpnSite) StartServer() {
	code := `from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  data = self.client_address[0].encode()
  self.send_response(200)
  self.send_header('Content-Length', str(len(data)))
  self.end_headers()
  self.wfile.write(data)
 def log_message(self, *args): pass
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()`
	_, err := dockerOutput("exec", "-d", s.peer, "python3", "-c", code)
	Expect(err).NotTo(HaveOccurred())
}

func (s *vpnSite) Curl(target string) (string, error) {
	return s.Exec("curl", "--noproxy", "*", "--interface", s.onPremIP, "-fsS", "--max-time", "3", "http://"+target)
}

func (s *vpnSite) WaitGatewayAdvertises(namespace, prefix string) {
	Eventually(func(g Gomega) {
		uid, err := kubectlJSONPath(repoRoot, `{.metadata.uid}`, "-n", namespace, "get", "vpn", s.name)
		g.Expect(err).NotTo(HaveOccurred())
		hash := sha256.Sum256([]byte(uid))
		pod := fmt.Sprintf("vpn-%s-%x", s.name, hash[:8])
		phase, err := kubectlJSONPath(repoRoot, `{.status.phase}`, "-n", namespace, "get", "pod", pod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(phase).To(Equal("Running"))
		routes, err := kubectlJSONPath(repoRoot, `{.spec.containers[0].env[?(@.name=="VPN_ADVERTISED_ROUTES")].value}`, "-n", namespace, "get", "pod", pod)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(routes).To(ContainSubstring(prefix))
	}).Should(Succeed())
}

func (s *vpnSite) GatewayPod(namespace string) (string, string) {
	uid, err := kubectlJSONPath(repoRoot, `{.metadata.uid}`, "-n", namespace, "get", "vpn", s.name)
	Expect(err).NotTo(HaveOccurred())
	hash := sha256.Sum256([]byte(uid))
	pod := fmt.Sprintf("vpn-%s-%x", s.name, hash[:8])
	podUID, err := kubectlJSONPath(repoRoot, `{.metadata.uid}`, "-n", namespace, "get", "pod", pod)
	Expect(err).NotTo(HaveOccurred())
	Expect(podUID).NotTo(BeEmpty())
	return pod, podUID
}
