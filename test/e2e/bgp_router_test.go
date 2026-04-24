package e2e

import (
	"bytes"
	"fmt"
	"net"
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
	routerIP, err := chooseBGPRouterIP()
	if err != nil {
		return nil, fmt.Errorf("choose router IP: %w", err)
	}
	workerIPs, err := discoverWorkerInternalIPs(nodes)
	if err != nil {
		return nil, fmt.Errorf("discover worker IPs: %w", err)
	}
	inst := &bgpRouterInstance{
		name:      bgpRouterContainerName,
		ip:        routerIP,
		asn:       bgpRouterAS,
		workerIPs: workerIPs,
	}

	runBestEffort(repoRoot, "docker", "rm", "-f", inst.name)

	cfg, err := inst.renderConfig()
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(os.TempDir(), "juneau-e2e-bird.conf")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return nil, fmt.Errorf("write bird.conf: %w", err)
	}

	// L4 multipath hash policy ensures successive curls hash to different
	// next-hops even when the src/dst IP pair is fixed, so the test reaches
	// the node that actually hosts the target Pod within Eventually retries.
	if err := run(repoRoot, "docker", "create",
		"--name", inst.name,
		"--network", kindDockerNetwork,
		"--ip", inst.ip,
		"--cap-add", "NET_ADMIN",
		"--sysctl", "net.ipv4.fib_multipath_hash_policy=1",
		"--entrypoint", "sh",
		bgpRouterImage,
		"-c", "apk add --no-cache bird curl iproute2 && exec bird -f -c /etc/bird.conf",
	); err != nil {
		return nil, fmt.Errorf("create router container: %w", err)
	}
	if err := run(repoRoot, "docker", "cp", cfgPath, inst.name+":/etc/bird.conf"); err != nil {
		return nil, fmt.Errorf("copy bird.conf: %w", err)
	}
	if err := run(repoRoot, "docker", "start", inst.name); err != nil {
		return nil, fmt.Errorf("start router container: %w", err)
	}
	if err := inst.waitReady(bgpRouterReadyTimeout); err != nil {
		return nil, fmt.Errorf("wait bird ready: %w", err)
	}
	return inst, nil
}

func teardownBGPRouter() {
	if strings.EqualFold(os.Getenv("E2E_KEEP_CLUSTER"), "true") {
		return
	}
	runBestEffort(repoRoot, "docker", "rm", "-f", bgpRouterContainerName)
}

func chooseBGPRouterIP() (string, error) {
	if v := strings.TrimSpace(os.Getenv("E2E_BGP_PEER_IP")); v != "" {
		return v, nil
	}
	out, err := dockerOutput("network", "inspect", kindDockerNetwork, "-f", "{{range .IPAM.Config}}{{.Subnet}}\n{{end}}")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		base := network.IP.To4()
		if base == nil {
			continue
		}
		candidate := net.IPv4(base[0], base[1], base[2], 200)
		if !network.Contains(candidate) {
			return "", fmt.Errorf("kind network %s does not contain %s", network, candidate)
		}
		return candidate.String(), nil
	}
	return "", fmt.Errorf("no IPv4 subnet for docker network %q", kindDockerNetwork)
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
