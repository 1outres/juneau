package e2e

import (
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestVPNACLRuleKeepsTunnelControlTraffic(t *testing.T) {
	for _, action := range []string{"allow", "deny"} {
		t.Run(action, func(t *testing.T) {
			var rules struct {
				Ingress []struct {
					Action   string `yaml:"action"`
					Protocol string `yaml:"protocol"`
					CIDR     string `yaml:"cidr"`
					Ports    []struct {
						Port int `yaml:"port"`
					} `yaml:"ports"`
				} `yaml:"ingress"`
				Egress []struct {
					Action   string `yaml:"action"`
					Protocol string `yaml:"protocol"`
					CIDR     string `yaml:"cidr"`
				} `yaml:"egress"`
			}
			if err := yaml.Unmarshal([]byte(vpnACLRule(action, "198.18.11.0/24", "169.254.51.2", "172.18.0.9")), &rules); err != nil {
				t.Fatal(err)
			}
			if len(rules.Ingress) != 3 {
				t.Fatalf("ingress rules = %d; want data, BGP and NAT-T rules", len(rules.Ingress))
			}
			data, control, natT := rules.Ingress[0], rules.Ingress[1], rules.Ingress[2]
			if data.Action != action || data.Protocol != "tcp" || data.CIDR != "198.18.11.0/24" || len(data.Ports) != 2 || data.Ports[0].Port != 80 || data.Ports[1].Port != 9000 {
				t.Fatalf("data rule = %+v", data)
			}
			if control.Action != "allow" || control.Protocol != "tcp" || control.CIDR != "169.254.51.2/32" || len(control.Ports) != 0 {
				t.Fatalf("BGP rule = %+v", control)
			}
			if natT.Action != "allow" || natT.Protocol != "udp" || natT.CIDR != "172.18.0.9/32" || len(natT.Ports) != 2 || natT.Ports[0].Port != 500 || natT.Ports[1].Port != 4500 {
				t.Fatalf("NAT-T rule = %+v", natT)
			}
			if len(rules.Egress) != 1 || rules.Egress[0].Action != "allow" || rules.Egress[0].Protocol != "all" || rules.Egress[0].CIDR != "0.0.0.0/0" {
				t.Fatalf("egress rules = %+v", rules.Egress)
			}
		})
	}
}
