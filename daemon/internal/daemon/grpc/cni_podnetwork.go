package grpc

import (
	"errors"
	"fmt"
	"math"
	"net"
	"syscall"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// podRoute is one route of a NIC, already parsed.
type podRoute struct {
	dst    *net.IPNet
	gw     net.IP
	onLink bool
	table  int
}

// podRule is one policy routing rule of a NIC, already parsed.
type podRule struct {
	from     *net.IPNet
	table    int
	priority int
}

// podInterfaceConfig is what the pod side of one NIC carries. It is read
// off the status of the NetworkInterface alone, whatever network the NIC
// joined: the controller already turned the network into an address,
// routes and rules, so the CNI server only has to program them.
type podInterfaceConfig struct {
	// address is nil for a NIC on an L2Network without a CIDR.
	address *net.IPNet
	routes  []podRoute
	rules   []podRule
}

func parsePodInterfaceConfig(status *juneauv1alpha1.NetworkInterfaceStatus) (*podInterfaceConfig, error) {
	config := &podInterfaceConfig{
		routes: make([]podRoute, 0, len(status.Routes)),
		rules:  make([]podRule, 0, len(status.Rules)),
	}

	if status.Address != "" {
		ip, ipnet, err := net.ParseCIDR(status.Address)
		if err != nil {
			return nil, fmt.Errorf("parse address %q: %w", status.Address, err)
		}
		config.address = &net.IPNet{IP: ip, Mask: ipnet.Mask}
	}

	for i, route := range status.Routes {
		parsed, err := parsePodRoute(route)
		if err != nil {
			return nil, fmt.Errorf("routes[%d]: %w", i, err)
		}
		config.routes = append(config.routes, parsed)
	}

	for i, rule := range status.Rules {
		parsed, err := parsePodRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		config.rules = append(config.rules, parsed)
	}

	return config, nil
}

func parsePodRoute(route juneauv1alpha1.NetworkRoute) (podRoute, error) {
	_, dst, err := net.ParseCIDR(route.Dst)
	if err != nil {
		return podRoute{}, fmt.Errorf("parse destination %q: %w", route.Dst, err)
	}
	gw := net.ParseIP(route.GW)
	if gw == nil {
		return podRoute{}, fmt.Errorf("parse gateway %q: not an IP address", route.GW)
	}
	table, err := routeTableNumber(route.Table)
	if err != nil {
		return podRoute{}, err
	}
	return podRoute{dst: dst, gw: gw, onLink: route.OnLink, table: table}, nil
}

func parsePodRule(rule juneauv1alpha1.NetworkRoutingRule) (podRule, error) {
	_, from, err := net.ParseCIDR(rule.From)
	if err != nil {
		return podRule{}, fmt.Errorf("parse from %q: %w", rule.From, err)
	}
	if rule.Table == 0 {
		return podRule{}, errors.New("table 0 names no route table")
	}
	table, err := routeTableNumber(rule.Table)
	if err != nil {
		return podRule{}, err
	}
	if rule.Priority < 0 {
		return podRule{}, fmt.Errorf("priority %d is negative", rule.Priority)
	}
	return podRule{from: from, table: table, priority: int(rule.Priority)}, nil
}

// routeTableNumber checks a table number of the status contract against
// what the kernel keys route tables by, a 32-bit number.
func routeTableNumber(table int64) (int, error) {
	if table < 0 || table > math.MaxUint32 {
		return 0, fmt.Errorf("table %d does not fit in 32 bits", table)
	}
	return int(table), nil
}

// inMainTable reports whether the route lands in the main table, which is
// the only table the CNI result can describe.
func (r podRoute) inMainTable() bool {
	return r.table == 0 || r.table == unix.RT_TABLE_MAIN
}

func (r podRoute) netlinkRoute(linkIndex int) *netlink.Route {
	route := &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       r.dst,
		Gw:        r.gw,
		Table:     r.table,
	}
	if r.onLink {
		route.Flags = int(netlink.FLAG_ONLINK)
	}
	return route
}

func (r podRule) netlinkRule() *netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Src = r.from
	rule.Table = r.table
	rule.Priority = r.priority
	return rule
}

// configurePodInterface puts the address, routes and rules of one NIC on
// its link. It has to run inside the pod network namespace.
//
// The link is always new, so its address and routes cannot be there yet.
// A rule is not tied to a link and outlives the veth of an ADD that failed
// in the same sandbox, so a rule that is already there counts as added.
// Only the rules this call really added are returned, for the rollback to
// take away again.
func configurePodInterface(link netlink.Link, config *podInterfaceConfig) ([]podRule, error) {
	ifname := link.Attrs().Name

	if config.address != nil {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: config.address}); err != nil {
			return nil, fmt.Errorf("assign address %s to interface %s: %w", config.address, ifname, err)
		}
	}

	for _, route := range config.routes {
		if err := netlink.RouteAdd(route.netlinkRoute(link.Attrs().Index)); err != nil {
			return nil, fmt.Errorf("add route %s via %s table %d to interface %s: %w",
				route.dst, route.gw, route.table, ifname, err)
		}
	}

	added := make([]podRule, 0, len(config.rules))
	for _, rule := range config.rules {
		err := netlink.RuleAdd(rule.netlinkRule())
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		if err != nil {
			return added, fmt.Errorf("add rule from %s lookup %d priority %d for interface %s: %w",
				rule.from, rule.table, rule.priority, ifname, err)
		}
		added = append(added, rule)
	}
	return added, nil
}

// removePodRules takes rules back out of the pod network namespace it runs
// in. A rule that is already gone counts as removed.
func removePodRules(rules []podRule) error {
	var errs []error
	for _, rule := range rules {
		err := netlink.RuleDel(rule.netlinkRule())
		if err == nil || errors.Is(err, syscall.ENOENT) {
			continue
		}
		errs = append(errs, fmt.Errorf("delete rule from %s lookup %d priority %d: %w", rule.from, rule.table, rule.priority, err))
	}
	return errors.Join(errs...)
}
