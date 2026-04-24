package bird_test

import (
	"net"
	"strings"
	"testing"

	"github.com/1outres/juneau/bgp-speaker/internal/bird"
	bgptypes "github.com/1outres/juneau/bgp-speaker/internal/types"
)

func TestBuild_IncludesBMPStationBlock(t *testing.T) {
	t.Parallel()

	b := bird.NewPlaceholderBuilder("node-a", "10.0.0.1",
		bird.WithBMPStation("127.0.0.1", 5601))
	out, err := b.Build(&bgptypes.DesiredConfig{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if !strings.Contains(out, "protocol bmp") {
		t.Errorf("want `protocol bmp`, got:\n%s", out)
	}
	if !strings.Contains(out, "station address ip 127.0.0.1 port 5601") {
		t.Errorf("want station address line, got:\n%s", out)
	}
	if !strings.Contains(out, "monitoring rib in pre_policy") {
		t.Errorf("want pre_policy monitoring, got:\n%s", out)
	}
	if !strings.Contains(out, "monitoring rib in post_policy") {
		t.Errorf("want post_policy monitoring, got:\n%s", out)
	}
}

func TestBuild_NoBMPBlock_WhenStationUnset(t *testing.T) {
	t.Parallel()

	b := bird.NewPlaceholderBuilder("node-a", "10.0.0.1")
	out, err := b.Build(&bgptypes.DesiredConfig{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if strings.Contains(out, "protocol bmp") {
		t.Errorf("want no `protocol bmp` when station unset, got:\n%s", out)
	}
}

func TestBuild_BGPChannel_HasImportTableOn(t *testing.T) {
	t.Parallel()

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

	// Within the bgp protocol's ipv4 channel we need BMP pre-policy wiring.
	if !strings.Contains(out, "import table on") {
		t.Errorf("want `import table on;` in BGP channel, got:\n%s", out)
	}
	if !strings.Contains(out, "import keep filtered on") {
		t.Errorf("want `import keep filtered on;` in BGP channel, got:\n%s", out)
	}
}
