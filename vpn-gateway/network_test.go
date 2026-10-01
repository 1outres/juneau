package main

import (
	"strings"
	"testing"
)

func TestNetworkPlanDropsSpoofedLocalSourceBeforeAllowingDefaultRoute(t *testing.T) {
	cfg := sampleConfig()
	cfg.RemoteRoutes = []string{"0.0.0.0/0"}
	steps, err := networkSteps(cfg)
	if err != nil {
		t.Fatal(err)
	}
	deny, allow := -1, -1
	for i, step := range steps {
		line := strings.Join(step, " ")
		if line == "iptables -w -A FORWARD -i ipsec0 -o eth0 -m addrtype --src-type LOCAL -j DROP" {
			deny = i
		}
		if line == "iptables -w -A FORWARD -i ipsec0 -o eth0 -s 0.0.0.0/0 -d 10.1.0.0/16 -j ACCEPT" {
			allow = i
		}
	}
	if deny < 0 || allow < 0 || deny >= allow {
		t.Fatalf("spoofed gateway source must be dropped before forwarding: %v", steps)
	}
}

func TestNetworkPlanDoesNotForwardToAnotherVPN(t *testing.T) {
	cfg := sampleConfig()
	cfg.RemoteRoutes = []string{"0.0.0.0/0"}
	cfg.AdvertisedRoutes = []string{"10.1.0.0/16"}
	steps, err := networkSteps(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		line := strings.Join(step, " ")
		if strings.Contains(line, "-i ipsec0 -o eth0") && strings.HasSuffix(line, "-j ACCEPT") && !strings.Contains(line, "-d 10.1.0.0/16") {
			t.Fatalf("tunnel can forward outside advertised Vpc routes: %s", line)
		}
	}
}

func TestNetworkPlanForwardsOnlyConfiguredTunnelSourcesAndDestinations(t *testing.T) {
	steps, err := networkSteps(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	joined := make([]string, 0, len(steps))
	for _, step := range steps {
		joined = append(joined, strings.Join(step, " "))
	}
	plan := strings.Join(joined, "\n")
	for _, want := range []string{
		"ip link add ipsec0 type xfrm if_id 42 dev ext0",
		"ip route replace 192.168.10.0/24 dev ipsec0 table 200",
		"ip route replace prohibit default table 200",
		"iptables -w -P FORWARD DROP",
		"iptables -w -A FORWARD -i ipsec0 -o eth0 -s 192.168.10.0/24 -d 10.1.0.0/16 -j ACCEPT",
		"iptables -w -A FORWARD -i eth0 -o ipsec0 -d 192.168.10.0/24 -j ACCEPT",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(plan, "-i ipsec0 -o eth0 -s 192.168.10.0/24 -j ACCEPT") || strings.Contains(plan, "SNAT") || strings.Contains(plan, "MASQUERADE") || strings.Contains(plan, "ip route replace default dev ipsec0") {
		t.Fatal("leaks or NATs traffic")
	}
}
