package grpc

import (
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const testExtraNICTable = 3405803786

func elasticIPEth0Status() *juneauv1alpha1.NetworkInterfaceStatus {
	return &juneauv1alpha1.NetworkInterfaceStatus{
		Address: "203.0.113.10/32",
		Routes: []juneauv1alpha1.NetworkRoute{{
			Dst: "0.0.0.0/0", GW: juneauv1alpha1.PodElasticIPGateway, OnLink: true,
		}},
	}
}

func elasticIPExtraNICStatus() *juneauv1alpha1.NetworkInterfaceStatus {
	return &juneauv1alpha1.NetworkInterfaceStatus{
		Address: "203.0.113.11/32",
		Routes: []juneauv1alpha1.NetworkRoute{{
			Dst: "0.0.0.0/0", GW: juneauv1alpha1.PodElasticIPGateway, OnLink: true, Table: testExtraNICTable,
		}},
		Rules: []juneauv1alpha1.NetworkRoutingRule{{
			From: "203.0.113.11/32", Table: testExtraNICTable, Priority: juneauv1alpha1.PodElasticIPRulePriority,
		}},
	}
}

func mustParsePodInterfaceConfig(t *testing.T, status *juneauv1alpha1.NetworkInterfaceStatus) *podInterfaceConfig {
	t.Helper()
	config, err := parsePodInterfaceConfig(status)
	if err != nil {
		t.Fatalf("parsePodInterfaceConfig: %v", err)
	}
	return config
}

func routesOf(t *testing.T, link netlink.Link, table int) []netlink.Route {
	t.Helper()
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{LinkIndex: link.Attrs().Index, Table: table},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("list routes of %s in table %d: %v", link.Attrs().Name, table, err)
	}
	return routes
}

func defaultRouteOf(t *testing.T, link netlink.Link, table int) *netlink.Route {
	t.Helper()
	for _, route := range routesOf(t, link, table) {
		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" {
			return &route
		}
	}
	return nil
}

func rulesFrom(t *testing.T, from string) []netlink.Rule {
	t.Helper()
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	var matched []netlink.Rule
	for _, rule := range rules {
		if rule.Src != nil && rule.Src.String() == from {
			matched = append(matched, rule)
		}
	}
	return matched
}

func TestConfigurePodInterfaceGivesEth0AnOnLinkDefaultRoute(t *testing.T) {
	enterTestNetns(t)
	link := addTestLink(t, "eth0")

	added, err := configurePodInterface(link, mustParsePodInterfaceConfig(t, elasticIPEth0Status()))
	if err != nil {
		t.Fatalf("configurePodInterface: %v", err)
	}
	if len(added) != 0 {
		t.Errorf("added rules = %v, want none for eth0", added)
	}

	route := defaultRouteOf(t, link, unix.RT_TABLE_MAIN)
	if route == nil {
		t.Fatalf("main table has no default route on eth0: %v", routesOf(t, link, unix.RT_TABLE_MAIN))
	}
	if !route.Gw.Equal([]byte{169, 254, 0, 1}) || route.Flags&int(netlink.FLAG_ONLINK) == 0 {
		t.Errorf("default route = %s flags %d, want via %s onlink", route, route.Flags, juneauv1alpha1.PodElasticIPGateway)
	}
}

func TestConfigurePodInterfaceSendsAnExtraNICThroughItsOwnTable(t *testing.T) {
	enterTestNetns(t)
	eth0 := addTestLink(t, "eth0")
	eth1 := addTestLink(t, "eth1")

	if _, err := configurePodInterface(eth0, mustParsePodInterfaceConfig(t, elasticIPEth0Status())); err != nil {
		t.Fatalf("configure eth0: %v", err)
	}
	added, err := configurePodInterface(eth1, mustParsePodInterfaceConfig(t, elasticIPExtraNICStatus()))
	if err != nil {
		t.Fatalf("configure eth1: %v", err)
	}
	if len(added) != 1 {
		t.Fatalf("added rules = %v, want the one rule of eth1", added)
	}

	if route := defaultRouteOf(t, eth1, unix.RT_TABLE_MAIN); route != nil {
		t.Errorf("eth1 put a default route into the main table: %s", route)
	}
	route := defaultRouteOf(t, eth1, testExtraNICTable)
	if route == nil {
		t.Fatalf("table %d has no default route on eth1", testExtraNICTable)
	}
	if route.Flags&int(netlink.FLAG_ONLINK) == 0 {
		t.Errorf("default route of eth1 = %s flags %d, want onlink", route, route.Flags)
	}

	rules := rulesFrom(t, "203.0.113.11/32")
	if len(rules) != 1 {
		t.Fatalf("rules from 203.0.113.11/32 = %v, want one", rules)
	}
	if rules[0].Table != testExtraNICTable || rules[0].Priority != int(juneauv1alpha1.PodElasticIPRulePriority) {
		t.Errorf("rule = %s, want lookup %d priority %d", rules[0], testExtraNICTable, juneauv1alpha1.PodElasticIPRulePriority)
	}

	reply, err := netlink.RouteGetWithOptions([]byte{198, 51, 100, 7}, &netlink.RouteGetOptions{SrcAddr: []byte{203, 0, 113, 11}})
	if err != nil {
		t.Fatalf("look up a reply from the address of eth1: %v", err)
	}
	if len(reply) != 1 || reply[0].LinkIndex != eth1.Attrs().Index {
		t.Errorf("a reply from 203.0.113.11 leaves through %v, want eth1", reply)
	}
	fresh, err := netlink.RouteGet([]byte{198, 51, 100, 7})
	if err != nil {
		t.Fatalf("look up a new connection: %v", err)
	}
	if len(fresh) != 1 || fresh[0].LinkIndex != eth0.Attrs().Index {
		t.Errorf("a new connection leaves through %v, want eth0", fresh)
	}
}

func TestConfigurePodInterfaceAcceptsARuleLeftByAnEarlierAdd(t *testing.T) {
	enterTestNetns(t)
	config := mustParsePodInterfaceConfig(t, elasticIPExtraNICStatus())

	first := addTestLink(t, "eth1")
	if _, err := configurePodInterface(first, config); err != nil {
		t.Fatalf("first configure: %v", err)
	}
	if err := netlink.LinkDel(first); err != nil {
		t.Fatalf("delete the first link: %v", err)
	}

	second := addTestLink(t, "eth1")
	added, err := configurePodInterface(second, config)
	if err != nil {
		t.Fatalf("second configure: %v", err)
	}
	if len(added) != 0 {
		t.Errorf("added rules = %v, want none: the rule was already there", added)
	}
	if rules := rulesFrom(t, "203.0.113.11/32"); len(rules) != 1 {
		t.Errorf("rules from 203.0.113.11/32 = %v, want exactly one", rules)
	}
}

func TestRemovePodRules(t *testing.T) {
	enterTestNetns(t)
	link := addTestLink(t, "eth1")
	added, err := configurePodInterface(link, mustParsePodInterfaceConfig(t, elasticIPExtraNICStatus()))
	if err != nil {
		t.Fatalf("configurePodInterface: %v", err)
	}

	if err := removePodRules(added); err != nil {
		t.Fatalf("removePodRules: %v", err)
	}
	if rules := rulesFrom(t, "203.0.113.11/32"); len(rules) != 0 {
		t.Errorf("rules from 203.0.113.11/32 = %v, want none", rules)
	}
	if err := removePodRules(added); err != nil {
		t.Errorf("removing rules that are gone: %v", err)
	}
}
