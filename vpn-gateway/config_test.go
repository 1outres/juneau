package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func sampleConfig() Config {
	return Config{PublicIP: "203.0.113.20", LocalTunnelIP: "169.254.51.1", RemoteTunnelIP: "169.254.51.2", LocalASN: 64512, RemoteASN: 64513, PeerIKEID: "@branch.example", PSK: []byte("secret"), RemoteRoutes: []string{"192.168.10.0/24"}, AdvertisedRoutes: []string{"10.1.0.0/16"}}
}

func TestRenderIKEIsResponderOnlyAndUsesDynamicNATTPeer(t *testing.T) {
	cfg := sampleConfig()
	text, err := renderSwanctl(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"local_addrs = 203.0.113.20", "remote_addrs = %any", "version = 2", "id = @branch.example", "if_id_in = 42", "if_id_out = 42", "local_ts = 0.0.0.0/0", "remote_ts = 0.0.0.0/0", "start_action = none", "secret = 0x736563726574", "encap = yes", "proposals = aes256gcm16-prfsha384-ecp384", "esp_proposals = aes256gcm16-ecp384"} {
		if !strings.Contains(text, fragment) {
			t.Errorf("missing %q", fragment)
		}
	}
	if strings.Contains(text, "secret = secret") || strings.Contains(text, "remote_addrs = 192") {
		t.Fatal("unsafe config")
	}
}

func TestGatewayImageIncludesECDHProvider(t *testing.T) {
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerfile), "libstrongswan-standard-plugins") {
		t.Fatal("ECP-384 requires the strongSwan OpenSSL plugin")
	}
}

func TestSwanctlSettingsUseSeparateLines(t *testing.T) {
	text, err := renderSwanctl(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, ";") {
		t.Fatal("swanctl settings must be separated by newlines")
	}
}

func TestBirdRejectsAllImportsAndDoesNotInstallStaticBlackholes(t *testing.T) {
	text, err := renderBird(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"import none;", "export none;", "route 10.1.0.0/16 blackhole;", "protocol bgp " + birdProtocol + " {", "neighbor 169.254.51.2 as 64513;", "source address 169.254.51.1;", "multihop;",  "if proto = \"advertised\" then accept;"} {
		if !strings.Contains(text, fragment) {
			t.Errorf("missing %q", fragment)
		}
	}
	if strings.Contains(text, "192.168.10.0/24") || strings.Contains(text, "route 0.0.0.0/0") {
		t.Fatal("leaked remote route into BGP")
	}
}

func TestRenderedBirdConfigParses(t *testing.T) {
	bird, err := exec.LookPath("bird")
	if err != nil {
		t.Skip("BIRD is not available for static configuration check")
	}
	config, err := renderBird(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bird.conf")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(bird, "-p", "-c", path).CombinedOutput()
	if err != nil || len(output) != 0 {
		t.Fatalf("BIRD rejected generated config: %v: %s", err, output)
	}
}

func TestConfigRejectsUnsafeInputAndOverlaps(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"same tunnel IP", func(c *Config) { c.RemoteTunnelIP = c.LocalTunnelIP }},
		{"IPv6", func(c *Config) { c.PublicIP = "::1" }},
		{"peer injection", func(c *Config) { c.PeerIKEID = "@branch\nremote_addrs=%any" }},
		{"ASN", func(c *Config) { c.RemoteASN = c.LocalASN }},
		{"empty key", func(c *Config) { c.PSK = nil }},
		{"advertise default", func(c *Config) { c.AdvertisedRoutes = []string{"0.0.0.0/0"} }},
		{"advertise remote", func(c *Config) { c.AdvertisedRoutes = []string{"192.168.10.0/24"} }},
		{"overlapping static route", func(c *Config) { c.RemoteRoutes = append(c.RemoteRoutes, "192.168.10.0/25") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := sampleConfig()
			tt.change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestExplicitDefaultPermitsSpecificRemoteRoutes(t *testing.T) {
	c := sampleConfig()
	c.RemoteRoutes = []string{"0.0.0.0/0", "192.168.10.0/24"}
	if err := c.Validate(); err != nil {
		t.Fatalf("default and specific remote route: %v", err)
	}
	c.RemoteRoutes = append(c.RemoteRoutes, "192.168.10.0/25")
	if err := c.Validate(); err == nil {
		t.Fatal("overlapping specific routes accepted")
	}
}

func TestDefaultDoesNotMaskAdvertisedOverlap(t *testing.T) {
	c := sampleConfig()
	c.RemoteRoutes = []string{"0.0.0.0/0", "10.1.0.0/24"}
	if err := c.Validate(); err == nil {
		t.Fatal("overlapping advertised and remote prefixes accepted")
	}
}

func TestHealthRequiresChildSAAndEstablishedBGP(t *testing.T) {
	sa := `juneau: #1, ESTABLISHED, IKEv2, 1234
  juneau: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
`
	bgp := `vpn BGP --- up 2025-01-01 Established
  BGP state:          Established
`
	if !healthy(sa, bgp) {
		t.Fatal("valid SA and BGP not healthy")
	}
	for _, input := range []struct{ sa, bgp string }{{"", bgp}, {strings.Replace(sa, "INSTALLED", "REKEYED", 1), bgp}, {sa, strings.Replace(bgp, "Established", "Idle", -1)}} {
		if healthy(input.sa, input.bgp) {
			t.Fatal("unhealthy state accepted")
		}
	}
}

func TestLoadEnvRequiresAllFieldsAndReadsPSKFromMountedFile(t *testing.T) {
	c := sampleConfig()
	file := t.TempDir() + "/psk"
	if err := os.WriteFile(file, c.PSK, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUBLIC_IP", c.PublicIP)
	t.Setenv("LOCAL_TUNNEL_IP", c.LocalTunnelIP)
	t.Setenv("REMOTE_TUNNEL_IP", c.RemoteTunnelIP)
	t.Setenv("LOCAL_ASN", "64512")
	t.Setenv("REMOTE_ASN", "64513")
	t.Setenv("PEER_IKE_ID", c.PeerIKEID)
	t.Setenv("VPN_PSK_FILE", file)
	t.Setenv("VPN_REMOTE_ROUTES", `["192.168.10.0/24"]`)
	t.Setenv("VPN_ADVERTISED_ROUTES", `["10.1.0.0/16"]`)
	got, err := loadEnv()
	if err != nil {
		t.Fatal(err)
	}
	if string(got.PSK) != "secret" {
		t.Fatal("PSK not read")
	}
	for _, missing := range []string{"", "null"} {
		t.Setenv("VPN_ADVERTISED_ROUTES", missing)
		if _, err := loadEnv(); err == nil {
			t.Fatal("missing routes must not be accepted")
		}
	}
}
