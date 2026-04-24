//go:build integration

package bird_test

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/1outres/juneau/bgp-speaker/internal/bird"
	bgptypes "github.com/1outres/juneau/bgp-speaker/internal/types"
)

// TestBuild_ParsesWithBird3 runs `bird -p -c <config>` inside an alpine:3.23
// container (which provides bird 3.1.6) and asserts the generated config is
// syntactically accepted. Skipped when docker is unavailable.
func TestBuild_ParsesWithBird3(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	b := bird.NewPlaceholderBuilder("node-a", "10.0.0.1",
		bird.WithBMPStation("127.0.0.1", 5601))
	_, ipnet, _ := net.ParseCIDR("10.1.0.0/24")
	out, err := b.Build(&bgptypes.DesiredConfig{
		Peers: []*bgptypes.Peer{{
			LocalASN:  64512,
			RemoteIP:  "10.0.0.2",
			RemoteASN: 64513,
			Prefixes:  []*net.IPNet{ipnet},
		}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	dir := t.TempDir()
	confPath := filepath.Join(dir, "bird.conf")
	if err := os.WriteFile(confPath, []byte(out), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command("docker", "run", "--rm",
		"-v", dir+":/mnt",
		"alpine:3.23",
		"sh", "-c",
		"apk add --no-cache bird >/dev/null 2>&1 && bird -p -c /mnt/bird.conf 2>&1")
	combined, err := cmd.CombinedOutput()
	t.Logf("bird output:\n%s", string(combined))
	t.Logf("generated config:\n%s", out)
	if err != nil {
		t.Fatalf("bird -p: %v", err)
	}
}
