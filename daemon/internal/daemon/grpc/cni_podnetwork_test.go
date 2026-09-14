package grpc

import (
	"strings"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestParsePodInterfaceConfigOfASubnetNIC(t *testing.T) {
	config, err := parsePodInterfaceConfig(&juneauv1alpha1.NetworkInterfaceStatus{
		Address: "10.16.0.5/24",
		Routes:  []juneauv1alpha1.NetworkRoute{{Dst: "0.0.0.0/0", GW: "10.16.0.1"}},
	})
	if err != nil {
		t.Fatalf("parsePodInterfaceConfig: %v", err)
	}
	if got := config.address.String(); got != "10.16.0.5/24" {
		t.Errorf("address = %s, want the host address with the Subnet mask", got)
	}
	if len(config.routes) != 1 {
		t.Fatalf("routes = %v, want one", config.routes)
	}
	route := config.routes[0].netlinkRoute(7)
	if route.LinkIndex != 7 || route.Dst.String() != "0.0.0.0/0" || !route.Gw.Equal([]byte{10, 16, 0, 1}) {
		t.Errorf("route = %+v, want default via 10.16.0.1 on link 7", route)
	}
	if route.Flags != 0 || route.Table != 0 {
		t.Errorf("route flags = %d table = %d, want a plain route in the main table", route.Flags, route.Table)
	}
	if len(config.rules) != 0 {
		t.Errorf("rules = %v, want none", config.rules)
	}
}

func TestParsePodInterfaceConfigOfAnElasticIPOnEth0(t *testing.T) {
	config, err := parsePodInterfaceConfig(&juneauv1alpha1.NetworkInterfaceStatus{
		Address: "203.0.113.10/32",
		Routes: []juneauv1alpha1.NetworkRoute{{
			Dst: "0.0.0.0/0", GW: juneauv1alpha1.PodElasticIPGateway, OnLink: true,
		}},
	})
	if err != nil {
		t.Fatalf("parsePodInterfaceConfig: %v", err)
	}
	if got := config.address.String(); got != "203.0.113.10/32" {
		t.Errorf("address = %s, want the ElasticIP as a /32", got)
	}
	route := config.routes[0].netlinkRoute(3)
	if route.Flags&int(netlink.FLAG_ONLINK) == 0 {
		t.Errorf("route flags = %d, want onlink: no address of a /32 covers %s", route.Flags, juneauv1alpha1.PodElasticIPGateway)
	}
	if !config.routes[0].inMainTable() {
		t.Error("the default route of eth0 belongs in the main table")
	}
}

func TestParsePodInterfaceConfigOfAnElasticIPOnAnExtraNIC(t *testing.T) {
	const table = 3405803786
	config, err := parsePodInterfaceConfig(&juneauv1alpha1.NetworkInterfaceStatus{
		Address: "203.0.113.10/32",
		Routes: []juneauv1alpha1.NetworkRoute{{
			Dst: "0.0.0.0/0", GW: juneauv1alpha1.PodElasticIPGateway, OnLink: true, Table: table,
		}},
		Rules: []juneauv1alpha1.NetworkRoutingRule{{
			From: "203.0.113.10/32", Table: table, Priority: juneauv1alpha1.PodElasticIPRulePriority,
		}},
	})
	if err != nil {
		t.Fatalf("parsePodInterfaceConfig: %v", err)
	}

	route := config.routes[0]
	if route.inMainTable() {
		t.Error("the default route of an extra NIC must stay out of the main table, or it would replace the one of eth0")
	}
	if got := route.netlinkRoute(4).Table; got != table {
		t.Errorf("route table = %d, want %d", got, table)
	}

	if len(config.rules) != 1 {
		t.Fatalf("rules = %v, want one", config.rules)
	}
	rule := config.rules[0].netlinkRule()
	if rule.Src.String() != "203.0.113.10/32" || rule.Table != table || rule.Priority != int(juneauv1alpha1.PodElasticIPRulePriority) {
		t.Errorf("rule = %s, want from 203.0.113.10/32 lookup %d priority %d", rule, table, juneauv1alpha1.PodElasticIPRulePriority)
	}
	if rule.Family != unix.AF_INET {
		t.Errorf("rule family = %d, want IPv4", rule.Family)
	}
}

func TestParsePodInterfaceConfigOfAnL2NetworkNICWithoutAddress(t *testing.T) {
	config, err := parsePodInterfaceConfig(&juneauv1alpha1.NetworkInterfaceStatus{})
	if err != nil {
		t.Fatalf("parsePodInterfaceConfig: %v", err)
	}
	if config.address != nil || len(config.routes) != 0 || len(config.rules) != 0 {
		t.Errorf("config = %+v, want nothing to put on the NIC", config)
	}
}

func TestPodRouteInMainTable(t *testing.T) {
	for _, tc := range []struct {
		table int
		want  bool
	}{
		{table: 0, want: true},
		{table: unix.RT_TABLE_MAIN, want: true},
		{table: 256, want: false},
	} {
		if got := (podRoute{table: tc.table}).inMainTable(); got != tc.want {
			t.Errorf("table %d: inMainTable = %v, want %v", tc.table, got, tc.want)
		}
	}
}

func TestParsePodInterfaceConfigRejectsWhatItCannotProgram(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status juneauv1alpha1.NetworkInterfaceStatus
		want   string
	}{
		{
			name:   "address",
			status: juneauv1alpha1.NetworkInterfaceStatus{Address: "203.0.113.10"},
			want:   "address",
		},
		{
			name: "route destination",
			status: juneauv1alpha1.NetworkInterfaceStatus{
				Routes: []juneauv1alpha1.NetworkRoute{{Dst: "default", GW: "10.0.0.1"}},
			},
			want: "destination",
		},
		{
			name: "route gateway",
			status: juneauv1alpha1.NetworkInterfaceStatus{
				Routes: []juneauv1alpha1.NetworkRoute{{Dst: "0.0.0.0/0", GW: ""}},
			},
			want: "gateway",
		},
		{
			name: "route table",
			status: juneauv1alpha1.NetworkInterfaceStatus{
				Routes: []juneauv1alpha1.NetworkRoute{{Dst: "0.0.0.0/0", GW: "10.0.0.1", Table: 1 << 32}},
			},
			want: "table",
		},
		{
			name: "rule source",
			status: juneauv1alpha1.NetworkInterfaceStatus{
				Rules: []juneauv1alpha1.NetworkRoutingRule{{From: "203.0.113.10", Table: 300, Priority: 100}},
			},
			want: "from",
		},
		{
			name: "rule table",
			status: juneauv1alpha1.NetworkInterfaceStatus{
				Rules: []juneauv1alpha1.NetworkRoutingRule{{From: "203.0.113.10/32", Table: 0, Priority: 100}},
			},
			want: "table",
		},
		{
			name: "rule priority",
			status: juneauv1alpha1.NetworkInterfaceStatus{
				Rules: []juneauv1alpha1.NetworkRoutingRule{{From: "203.0.113.10/32", Table: 300, Priority: -1}},
			},
			want: "priority",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePodInterfaceConfig(&tc.status)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should name the %s", err, tc.want)
			}
		})
	}
}
