package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

const (
	bgpRouterContainerName = "juneau-e2e-bgp-peer"
	bgpRouterImage         = "alpine:3.23"
	bgpRouterAS            = uint32(65000)
	bgpLocalAS             = uint32(64512)
	bgpExternalCIDR        = "192.0.2.0/24"
	kindDockerNetwork      = "kind"
	bgpRouterReadyTimeout  = 3 * time.Minute
)

type bgpRouterInstance struct {
	name      string
	ip        string
	asn       uint32
	workerIPs map[string]string
}

func ensureBGPRouter(nodes []string) (*bgpRouterInstance, error) {
	workerIPs, err := discoverWorkerInternalIPs(nodes)
	if err != nil {
		return nil, fmt.Errorf("discover worker IPs: %w", err)
	}
	if err := applyKindBridgeHostRPFWorkaround(bgpExternalCIDR); err != nil {
		return nil, fmt.Errorf("apply kind bridge RPF workaround: %w", err)
	}
	inst := &bgpRouterInstance{
		name:      bgpRouterContainerName,
		asn:       bgpRouterAS,
		workerIPs: workerIPs,
	}

	runBestEffort(repoRoot, "docker", "rm", "-f", inst.name)

	// Create without --ip: docker engines on some hosts (e.g. GitHub Actions
	// with docker >= 25) reject a user-specified IP against an
	// auto-allocated subnet with "user specified IP address is supported
	// only when connecting to networks with user configured subnets". The
	// entrypoint waits for /etc/bird.conf so we can render the config after
	// the container has an IP assigned.
	// L4 multipath hash policy ensures successive curls hash to different
	// next-hops even when the src/dst IP pair is fixed, so the test reaches
	// the node that actually hosts the target Pod within Eventually retries.
	entrypoint := "apk add --no-cache bird curl iproute2 >/dev/null && " +
		"until [ -f /etc/bird.conf ]; do sleep 0.5; done && " +
		"exec bird -f -c /etc/bird.conf"
	if err := run(repoRoot, "docker", "create",
		"--name", inst.name,
		"--network", kindDockerNetwork,
		"--cap-add", "NET_ADMIN",
		"--sysctl", "net.ipv4.fib_multipath_hash_policy=1",
		"--entrypoint", "sh",
		bgpRouterImage,
		"-c", entrypoint,
	); err != nil {
		return nil, fmt.Errorf("create router container: %w", err)
	}
	if err := run(repoRoot, "docker", "start", inst.name); err != nil {
		return nil, fmt.Errorf("start router container: %w", err)
	}
	ip, err := discoverRouterIP(inst.name)
	if err != nil {
		return nil, fmt.Errorf("discover router IP: %w", err)
	}
	inst.ip = ip

	cfg, err := inst.renderConfig()
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(os.TempDir(), "juneau-e2e-bird.conf")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return nil, fmt.Errorf("write bird.conf: %w", err)
	}
	if err := run(repoRoot, "docker", "cp", cfgPath, inst.name+":/etc/bird.conf"); err != nil {
		return nil, fmt.Errorf("copy bird.conf: %w", err)
	}
	if err := inst.waitReady(bgpRouterReadyTimeout); err != nil {
		return nil, fmt.Errorf("wait bird ready: %w", err)
	}
	return inst, nil
}

func discoverRouterIP(name string) (string, error) {
	out, err := dockerOutput("inspect", "-f",
		fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}", kindDockerNetwork), name)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(out)
	if ip == "" {
		return "", fmt.Errorf("container %s has no IPv4 on docker network %q", name, kindDockerNetwork)
	}
	return ip, nil
}

func teardownBGPRouter() {
	if strings.EqualFold(os.Getenv("E2E_KEEP_CLUSTER"), "true") {
		return
	}
	runBestEffort(repoRoot, "docker", "rm", "-f", bgpRouterContainerName)
	cleanupKindBridgeHostRPFWorkaround(bgpExternalCIDR)
}

// applyKindBridgeHostRPFWorkaround installs a host-side route pointing the
// advertised CIDR at the kind docker bridge. kind places the BGP peer and
// workers on the same L2 bridge, so SNAT'd responses from a worker carry a
// source IP that has no route in the host netns. NixOS (and any distro that
// enables iptables strict RPF via xt_rpfilter) drops those frames at
// mangle/PREROUTING before FORWARD is even consulted. Adding the route
// gives RPF a valid reverse path via the bridge interface. send_redirects is
// disabled so the bridge does not ICMP-redirect the peer away from its BGP
// next-hop.
func applyKindBridgeHostRPFWorkaround(cidr string) error {
	bridge, err := kindBridgeName()
	if err != nil {
		return err
	}
	script := fmt.Sprintf(`set -eu
ip route replace %s dev %s
sysctl -wq net.ipv4.conf.%s.send_redirects=0
`, cidr, bridge, bridge)
	return run(repoRoot, "docker", "run", "--rm", "--privileged", "--network", "host",
		bgpRouterImage, "sh", "-c", script)
}

func cleanupKindBridgeHostRPFWorkaround(cidr string) {
	bridge, err := kindBridgeName()
	if err != nil {
		return
	}
	script := fmt.Sprintf(`ip route del %s dev %s 2>/dev/null
sysctl -wq net.ipv4.conf.%s.send_redirects=1 2>/dev/null
true
`, cidr, bridge, bridge)
	runBestEffort(repoRoot, "docker", "run", "--rm", "--privileged", "--network", "host",
		bgpRouterImage, "sh", "-c", script)
}

func kindBridgeName() (string, error) {
	out, err := dockerOutput("network", "inspect", kindDockerNetwork, "-f", "{{.Id}}")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(out)
	if len(id) < 12 {
		return "", fmt.Errorf("unexpected kind network id %q", id)
	}
	return "br-" + id[:12], nil
}

func discoverWorkerInternalIPs(nodes []string) (map[string]string, error) {
	result := make(map[string]string, len(nodes))
	for _, node := range nodes {
		ip, err := kubectlJSONPath(repoRoot, `{.status.addresses[?(@.type=="InternalIP")].address}`, "get", "node", node)
		if err != nil {
			return nil, err
		}
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return nil, fmt.Errorf("node %s has no InternalIP", node)
		}
		result[node] = ip
	}
	return result, nil
}

// merge paths on lets the kernel install ECMP next-hops for the same
// prefix when both workers advertise it.
const bgpRouterConfigTemplate = `router id {{ .RouterID }};
log stderr all;

protocol device {}

protocol kernel {
  ipv4 {
    import none;
    export all;
  };
  merge paths on;
}

{{ range $i, $peer := .Peers }}
protocol bgp worker_{{ $i }} {
  local {{ $.RouterID }} as {{ $.LocalAS }};
  neighbor {{ $peer.IP }} as {{ $peer.RemoteAS }};
  ipv4 {
    import all;
    export none;
  };
}
{{ end }}
`

type bgpRouterConfigParams struct {
	RouterID string
	LocalAS  uint32
	Peers    []bgpRouterConfigPeer
}

type bgpRouterConfigPeer struct {
	Name     string
	IP       string
	RemoteAS uint32
}

func (r *bgpRouterInstance) renderConfig() (string, error) {
	params := bgpRouterConfigParams{
		RouterID: r.ip,
		LocalAS:  r.asn,
	}
	for _, name := range sortedKeys(r.workerIPs) {
		params.Peers = append(params.Peers, bgpRouterConfigPeer{
			Name:     name,
			IP:       r.workerIPs[name],
			RemoteAS: bgpLocalAS,
		})
	}
	tmpl, err := template.New("bird-router").Parse(bgpRouterConfigTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *bgpRouterInstance) Exec(args ...string) (string, error) {
	cmdArgs := append([]string{"exec", r.name}, args...)
	return dockerOutput(cmdArgs...)
}

func (r *bgpRouterInstance) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		out, err := r.Exec("birdc", "show", "status")
		if err == nil && strings.Contains(out, "Router ID is") {
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			if lastErr == nil {
				return fmt.Errorf("birdc show status output unexpected: %q", out)
			}
			return fmt.Errorf("birdc show status: %w", lastErr)
		}
		time.Sleep(2 * time.Second)
	}
}

func (r *bgpRouterInstance) Stop() error {
	return run(repoRoot, "docker", "stop", r.name)
}

func (r *bgpRouterInstance) Start() error {
	if err := run(repoRoot, "docker", "start", r.name); err != nil {
		return err
	}
	return r.waitReady(bgpRouterReadyTimeout)
}

func dockerOutput(args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	cmd.Dir = repoRoot
	cmd.Env = os.Environ()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_, _ = fmt.Fprintf(GinkgoWriter, "running: docker %s\n", strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			_, _ = GinkgoWriter.Write(stderr.Bytes())
		}
		return strings.TrimSpace(stdout.String()), fmt.Errorf("docker %s failed: %w", strings.Join(args, " "), err)
	}
	if stdout.Len() > 0 {
		_, _ = GinkgoWriter.Write(stdout.Bytes())
	}
	if stderr.Len() > 0 {
		_, _ = GinkgoWriter.Write(stderr.Bytes())
	}
	return strings.TrimSpace(stdout.String()), nil
}
