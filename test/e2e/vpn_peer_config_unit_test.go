package e2e

import (
	"strings"
	"testing"
)

func TestVPNPeerRestartsAfterGatewayReplacement(t *testing.T) {
	site := &vpnSite{publicIP: "192.0.2.8", ikeID: "@branch.example", psk: "sample"}
	config := vpnPeerConfig(site, "172.29.251.2")
	for _, setting := range []string{"dpd_delay = 5s", "dpd_action = start"} {
		if !strings.Contains(config, setting) {
			t.Errorf("peer config does not contain %q", setting)
		}
	}
}
