package mapinventory

import (
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// RegisterPodEgress wires every map exposed by the pod-egress program
// into inv. Maps are pinned by name across programs so registering
// the pod-egress handle is sufficient — the same kernel object backs
// the corresponding handles in pod_ingress, vxlan_ingress, and
// node_ingress.
//
// New map?  Add a Descriptor here and a sanity entry in
// register_test.go's coverage list. The schema definition lives next
// to the registration so changes to maps.h surface as a single PR
// touching both.
func RegisterPodEgress(inv *Inventory, p *program.PodEgress) error {
	for _, fn := range []func(*Inventory, *program.PodEgress) error{
		registerSubnet,
		registerIfindexSubnet,
		registerIfindexHostMac,
		registerArpTable,
		registerFdb,
		registerVxlanIfindex,
		registerHostUnderlay,
		registerServiceNATIP,
		registerFib,
		registerBGPAddressPools,
		registerNATSnat,
		registerNATDnat,
		registerService,
		registerServiceACL,
		registerBackend,
		registerCT,
		registerNAPTSrc,
		registerVirtualService,
		registerVirtualServiceFlow,
		registerSGMembership,
		registerSGMeta,
		registerSGRule,
		registerACLMeta,
		registerACLRule,
	} {
		if err := fn(inv, p); err != nil {
			return err
		}
	}
	return nil
}

// ----- per-map descriptors ----------------------------------------------

func registerSubnet(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "subnet_map",
		Map:  p.Objs.SubnetMap,
		Key: Schema{Fields: []Field{
			FieldU32Named("subnet_id"),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("table_id", "FIB table id this Subnet is bound to"),
			FieldU32Named("vpc_id"),
			FieldMACNamed("gw_mac"),
			FieldPadOf(2),
			FieldIPv4BENamed("gw_addr", "gateway IPv4 (network byte order)"),
			FieldU32Named("mask"),
			FieldU32Named("acl_id", "0 means no NetworkACL attached"),
		}},
	})
}

func registerIfindexSubnet(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "ifindex_subnet",
		Map:  p.Objs.IfindexSubnet,
		Key: Schema{Fields: []Field{
			FieldU32Named("ifindex"),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("subnet_id"),
		}},
	})
}

func registerIfindexHostMac(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "ifindex_host_mac",
		Map:  p.Objs.IfindexHostMac,
		Key: Schema{Fields: []Field{
			FieldU32Named("ifindex"),
		}},
		Value: Schema{Fields: []Field{
			FieldMACNamed("mac"),
		}},
	})
}

func registerArpTable(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "arp_table",
		Map:  p.Objs.ArpTable,
		Key: Schema{Fields: []Field{
			FieldU32Named("subnet_id"),
			FieldIPv4BENamed("ipaddr"),
		}},
		Value: Schema{Fields: []Field{
			FieldMACNamed("mac"),
		}},
	})
}

func registerFdb(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "fdb",
		Map:  p.Objs.Fdb,
		Key: Schema{Fields: []Field{
			FieldU32Named("subnet_id"),
			FieldMACNamed("mac"),
			FieldPadOf(2),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("ifindex", "0 means remote (use vtep_ip via VXLAN)"),
			FieldIPv4BENamed("vtep_ip"),
		}},
	})
}

func registerVxlanIfindex(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "vxlan_ifindex",
		Map:  p.Objs.VxlanIfindex,
		Key: Schema{Fields: []Field{
			FieldU32Named("index"),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("vxlan_ifindex"),
		}},
	})
}

func registerHostUnderlay(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "host_underlay",
		Map:  p.Objs.HostUnderlay,
		Key: Schema{Fields: []Field{
			FieldU32Named("index"),
		}},
		Value: Schema{Fields: []Field{
			FieldIPv4BENamed("host_ip"),
		}},
	})
}

func registerServiceNATIP(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "service_nat_ip",
		Map:  p.Objs.ServiceNatIp,
		Key: Schema{Fields: []Field{
			FieldU32Named("provider_vpc_id"),
		}},
		Value: Schema{Fields: []Field{
			FieldIPv4BENamed("snat_ip"),
		}},
	})
}

func registerFib(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name:       "fib_map",
		Map:        p.Objs.FibMap,
		HashOfMaps: true,
		InnerProto: p.MapSpecs.FibInner,
		Key: Schema{Fields: []Field{
			FieldU32Named("table_id"),
		}},
		Value: Schema{Fields: []Field{
			// outer ValueSize is the inner map fd; surfaced as raw
			// padding so the schema-mismatch check on the outer is
			// skipped for HASH_OF_MAPS.
		}},
		InnerKey: Schema{Fields: []Field{
			FieldU32Named("prefixlen"),
			FieldIPv4BENamed("dst"),
		}},
		InnerValue: Schema{Fields: []Field{
			FieldEnumNamed("type", 1, FIBRouteTypeEnum),
			FieldMACNamed("dmac"),
			FieldMACNamed("smac"),
			FieldPadOf(3),
			FieldU32Named("subnet_id"),
			FieldU32Named("oif"),
		}},
	})
}

func registerBGPAddressPools(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "bgp_address_pools",
		Map:  p.Objs.BgpAddressPools,
		Key: Schema{Fields: []Field{
			FieldU32Named("prefixlen"),
			FieldIPv4BENamed("addr"),
		}},
		Value: Schema{Fields: []Field{
			FieldU8Named("present"),
		}},
	})
}

func registerNATSnat(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "nat_snat_map",
		Map:  p.Objs.NatSnatMap,
		Key: Schema{Fields: []Field{
			FieldU32Named("subnet_id"),
			FieldIPv4BENamed("addr"),
		}},
		Value: Schema{Fields: []Field{
			FieldIPv4BENamed("addr"),
		}},
	})
}

func registerNATDnat(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "nat_dnat_map",
		Map:  p.Objs.NatDnatMap,
		Key: Schema{Fields: []Field{
			FieldIPv4BENamed("addr"),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("subnet_id"),
			FieldIPv4BENamed("addr"),
		}},
	})
}

func registerService(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "service_map",
		Map:  p.Objs.ServiceMap,
		Key: Schema{Fields: []Field{
			FieldIPv4BENamed("cluster_ip"),
			FieldPortNamed("port"),
			FieldEnumNamed("proto", 1, IPProtoEnum),
			FieldPadOf(1),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("owner_vpc_id"),
			FieldU32Named("backend_count"),
			FieldU32Named("affinity_sec"),
			FieldFlagsNamed("flags", 4, SVCFlagDict),
		}},
	})
}

func registerServiceACL(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "service_acl_map",
		Map:  p.Objs.ServiceAclMap,
		Key: Schema{Fields: []Field{
			FieldIPv4BENamed("cluster_ip"),
			FieldPortNamed("port"),
			FieldEnumNamed("proto", 1, IPProtoEnum),
			FieldPadOf(1),
			FieldU32Named("caller_vpc_id"),
		}},
		Value: Schema{Fields: []Field{
			FieldU8Named("present"),
		}},
	})
}

func registerBackend(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "backend_map",
		Map:  p.Objs.BackendMap,
		Key: Schema{Fields: []Field{
			FieldIPv4BENamed("cluster_ip"),
			FieldPortNamed("port"),
			FieldEnumNamed("proto", 1, IPProtoEnum),
			FieldPadOf(1),
			FieldU32Named("index"),
		}},
		Value: Schema{Fields: []Field{
			FieldIPv4BENamed("backend_ip"),
			FieldPortNamed("backend_port"),
			FieldEnumNamed("kind", 1, BackendKindEnum),
			FieldPadOf(1),
			FieldU32Named("backend_subnet_id", "0 = host-network underlay backend"),
		}},
	})
}

func registerCT(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "ct_map",
		Map:  p.Objs.CtMap,
		Key: Schema{Fields: []Field{
			FieldEnumNamed("scope", 4, CTScopeEnum, "0=host keyspace, otherwise vpc_id"),
			FieldIPv4BENamed("saddr"),
			FieldIPv4BENamed("daddr"),
			FieldPortNamed("sport"),
			FieldPortNamed("dport"),
			FieldEnumNamed("proto", 1, IPProtoEnum),
			FieldPadOf(3),
		}},
		Value: Schema{Fields: []Field{
			FieldIPv4BENamed("new_saddr"),
			FieldIPv4BENamed("new_daddr"),
			FieldPortNamed("new_sport"),
			FieldPortNamed("new_dport"),
			FieldU32Named("next_subnet_id"),
			FieldEnumNamed("action", 1, CTActionEnum),
			FieldEnumNamed("state", 1, CTStateEnum),
			FieldU8Named("flags_seen", "TCP flags OR-accumulated on this direction"),
			FieldPadOf(5),
			FieldU64Named("last_seen_ns"),
		}},
	})
}

func registerNAPTSrc(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "napt_src",
		Map:  p.Objs.NaptSrc,
		Key: Schema{Fields: []Field{
			FieldU32Named("nat_gateway_id"),
		}},
		Value: Schema{Fields: []Field{
			FieldIPv4BENamed("host_ip"),
		}},
	})
}

func registerVirtualService(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "virtual_service_map",
		Map:  p.Objs.VirtualServiceMap,
		Key: Schema{Fields: []Field{
			FieldU32Named("subnet_id"),
			FieldIPv4BENamed("dst_ip"),
			FieldPortBENamed("dst_port"),
			FieldEnumNamed("proto", 1, IPProtoEnum),
			FieldPadOf(1),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("service_id"),
			FieldU32Named("tap_ifindex", "0 = registered but TAP not ready"),
			FieldMACNamed("service_mac"),
			FieldPadOf(2),
			FieldFlagsNamed("flags", 4, VirtSvcFlagDict),
		}},
	})
}

func registerVirtualServiceFlow(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "virtual_service_flow_map",
		Map:  p.Objs.VirtualServiceFlowMap,
		Key: Schema{Fields: []Field{
			FieldU32Named("subnet_id"),
			FieldIPv4BENamed("src_ip"),
			FieldIPv4BENamed("dst_ip"),
			FieldPortBENamed("src_port"),
			FieldPortBENamed("dst_port"),
			FieldEnumNamed("proto", 1, IPProtoEnum),
			FieldPadOf(3),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("vpc_id"),
			FieldU32Named("service_id"),
			FieldU32Named("pod_ifindex"),
			FieldMACNamed("pod_mac"),
			FieldMACNamed("service_mac"),
			FieldPadOf(2),
			FieldRawNamed("_align_pad", 6, "alignment for last_seen_ns"),
			FieldU64Named("last_seen_ns"),
		}},
	})
}

func registerSGMembership(inv *Inventory, p *program.PodEgress) error {
	// sg_membership_val carries a fixed-size sgs[2] array. We surface
	// each slot individually so kubectl can render them as columns.
	return inv.Register(&Descriptor{
		Name: "sg_membership_map",
		Map:  p.Objs.SgMembershipMap,
		Key: Schema{Fields: []Field{
			FieldU32Named("vpc_id"),
			FieldIPv4BENamed("ipv4"),
		}},
		Value: Schema{Fields: []Field{
			FieldU8Named("count"),
			FieldPadOf(3),
			FieldU32Named("sg0"),
			FieldU32Named("sg1"),
		}},
	})
}

func registerSGMeta(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "sg_meta_map",
		Map:  p.Objs.SgMetaMap,
		Key: Schema{Fields: []Field{
			FieldU32Named("sg_id"),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("ingress_count"),
			FieldU32Named("egress_count"),
			FieldU32Named("ruleset_version"),
			FieldU8Named("has_egress_rules", "0=default-allow egress, 1=allow-list only"),
			FieldPadOf(3),
		}},
	})
}

func registerSGRule(inv *Inventory, p *program.PodEgress) error {
	innerProto := p.MapSpecs.SgRulesInnerProto
	if innerProto == nil {
		// Fallback for the unusual case where MapSpecs is not present
		// (test harnesses that bypass program loading). Layout match
		// will fail loudly downstream.
		innerProto = bpf.PodEgressMapSpecs{}.SgRulesInnerProto
	}
	return inv.Register(&Descriptor{
		Name:       "sg_rule_table",
		Map:        p.Objs.SgRuleTable,
		HashOfMaps: true,
		InnerProto: innerProto,
		Key: Schema{Fields: []Field{
			FieldU32Named("sg_id"),
		}},
		Value:    Schema{},
		InnerKey: Schema{Fields: []Field{FieldU32Named("slot")}},
		InnerValue: Schema{Fields: []Field{
			FieldEnumNamed("direction", 1, SGDirEnum),
			FieldEnumNamed("proto", 1, IPProtoEnum),
			FieldU16Named("port_lo"),
			FieldU16Named("port_hi"),
			FieldEnumNamed("peer_kind", 1, SGPeerKindEnum),
			FieldU8Named("peer_prefixlen"),
			FieldIPv4BENamed("peer_v4", "CIDR base (NBO) or peer sg_id"),
			FieldEnumNamed("verdict", 1, SGVerdictEnum),
			FieldPadOf(3),
		}},
	})
}

func registerACLMeta(inv *Inventory, p *program.PodEgress) error {
	return inv.Register(&Descriptor{
		Name: "acl_meta_map",
		Map:  p.Objs.AclMetaMap,
		Key: Schema{Fields: []Field{
			FieldU32Named("acl_id"),
		}},
		Value: Schema{Fields: []Field{
			FieldU32Named("ingress_count"),
			FieldU32Named("egress_count"),
			FieldU64Named("ruleset_version"),
			FieldU8Named("has_ingress_rules"),
			FieldU8Named("has_egress_rules"),
			FieldPadOf(6),
		}},
	})
}

func registerACLRule(inv *Inventory, p *program.PodEgress) error {
	innerProto := p.MapSpecs.AclRulesInnerProto
	if innerProto == nil {
		innerProto = bpf.PodEgressMapSpecs{}.AclRulesInnerProto
	}
	return inv.Register(&Descriptor{
		Name:       "acl_rule_table",
		Map:        p.Objs.AclRuleTable,
		HashOfMaps: true,
		InnerProto: innerProto,
		Key: Schema{Fields: []Field{
			FieldU32Named("acl_id"),
		}},
		Value:    Schema{},
		InnerKey: Schema{Fields: []Field{FieldU32Named("slot")}},
		InnerValue: Schema{Fields: []Field{
			FieldEnumNamed("direction", 1, ACLDirEnum),
			FieldEnumNamed("proto", 1, IPProtoEnum),
			FieldU16Named("port_lo"),
			FieldU16Named("port_hi"),
			FieldU8Named("prefixlen"),
			FieldEnumNamed("verdict", 1, ACLVerdictEnum),
			FieldU16Named("priority"),
			FieldPadOf(2),
			FieldIPv4BENamed("peer_v4"),
		}},
	})
}
