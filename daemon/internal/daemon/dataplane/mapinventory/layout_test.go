package mapinventory

import (
	"testing"
	"unsafe"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// TestSchemaLayoutMatchesGenerated guards against drift between the
// hand-written Schemas in register.go and the bpf2go-generated Go
// structs (which mirror the C structs in daemon/bpf/maps.h byte-for-
// byte). When this fires, either the C struct changed and the
// schema needs updating, or vice versa.
//
// The check is registry-time-equivalent: Register() also verifies
// against the live *ebpf.Map's KeySize/ValueSize. Failing here is
// strictly a Go-side mismatch; failing at Register is a BPF-loaded
// mismatch.
func TestSchemaLayoutMatchesGenerated(t *testing.T) {
	cases := []struct {
		name      string
		key, val  Schema
		keySize   uintptr
		valueSize uintptr
	}{
		{
			name:      "subnet_map",
			key:       schemaSubnetKey(),
			val:       schemaSubnetVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressSubnetKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressSubnetVal{}),
		},
		{
			name:      "arp_table",
			key:       schemaArpKey(),
			val:       schemaArpVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressArpTableKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressArpTableVal{}),
		},
		{
			name:      "external_arp_table",
			key:       schemaExternalArpKey(),
			val:       schemaExternalArpVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressExternalArpKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressExternalArpVal{}),
		},
		{
			name:      "fdb",
			key:       schemaFdbKey(),
			val:       schemaFdbVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressFdbKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressFdbVal{}),
		},
		{
			name:      "service_map",
			key:       schemaServiceKey(),
			val:       schemaServiceVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressServiceKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressServiceVal{}),
		},
		{
			name: "vpc_endpoint_map",
			key: Schema{Fields: []Field{
				FieldU32Named("vpc_id"), FieldIPv4Named("address"), FieldPortNamed("port"), FieldEnumNamed("proto", 1, IPProtoEnum), FieldPadOf(1),
			}},
			val:       Schema{Fields: []Field{FieldIPv4Named("cluster_ip")}},
			keySize:   unsafe.Sizeof(bpf.PodEgressVpcEndpointKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressVpcEndpointVal{}),
		},
		{
			name:      "service_acl_map",
			key:       schemaServiceACLKey(),
			val:       schemaPresentVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressServiceAclKey{}),
			valueSize: 1,
		},
		{
			name:      "backend_map",
			key:       schemaBackendKey(),
			val:       schemaBackendVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressBackendKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressBackendVal{}),
		},
		{
			name:      "service_affinity_map",
			key:       schemaServiceAffinityKey(),
			val:       schemaServiceAffinityVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressServiceAffinityKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressServiceAffinityVal{}),
		},
		{
			name:      "ct_map",
			key:       schemaCTKey(),
			val:       schemaCTVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressCtKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressCtVal{}),
		},
		{
			name:      "policy_ct_map",
			key:       schemaPolicyCTKey(),
			val:       schemaPolicyCTVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressPolicyCtKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressPolicyCtVal{}),
		},
		{
			name:      "policy_epoch_map",
			key:       schemaPolicyEpochKey(),
			val:       schemaPolicyEpochVal(),
			keySize:   4,
			valueSize: 4,
		},
		{
			name:      "ipv4_frag_map",
			key:       schemaIPv4FragKey(),
			val:       schemaIPv4FragVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressIpv4FragKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressIpv4FragVal{}),
		},
		{
			name:      "virtual_service_map",
			key:       schemaVirtSvcKey(),
			val:       schemaVirtSvcVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressVirtualServiceKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressVirtualServiceVal{}),
		},
		{
			name:      "virtual_service_flow_map",
			key:       schemaVirtSvcFlowKey(),
			val:       schemaVirtSvcFlowVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressVirtualServiceFlowKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressVirtualServiceFlowVal{}),
		},
		{
			name:      "fib_inner",
			key:       schemaFibInnerKey(),
			val:       schemaFibInnerVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressFibKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressFibVal{}),
		},
		{
			name:      "sg_membership_map",
			key:       schemaSGMembershipKey(),
			val:       schemaSGMembershipVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressSgMembershipKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressSgMembershipVal{}),
		},
		{
			name:      "sg_meta_map",
			key:       schemaSGMetaKey(),
			val:       schemaSGMetaVal(),
			keySize:   4,
			valueSize: unsafe.Sizeof(bpf.PodEgressSgMetaVal{}),
		},
		{
			name:      "sg_rule_inner",
			key:       schemaSlotKey(),
			val:       schemaSGRuleInner(),
			keySize:   4,
			valueSize: unsafe.Sizeof(bpf.PodEgressSgRule{}),
		},
		{
			name:      "acl_meta_map",
			key:       schemaACLMetaKey(),
			val:       schemaACLMetaVal(),
			keySize:   4,
			valueSize: unsafe.Sizeof(bpf.PodEgressAclMetaVal{}),
		},
		{
			name:      "acl_rule_inner",
			key:       schemaSlotKey(),
			val:       schemaACLRuleInner(),
			keySize:   4,
			valueSize: unsafe.Sizeof(bpf.PodEgressAclRule{}),
		},
		{
			name:      "lb_service_map",
			key:       schemaLBServiceKey(),
			val:       schemaLBServiceVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressLbServiceKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressLbServiceVal{}),
		},
		{
			name:      "lb_backend_map",
			key:       schemaLBBackendKey(),
			val:       schemaLBBackendVal(),
			keySize:   unsafe.Sizeof(bpf.PodEgressLbBackendKey{}),
			valueSize: unsafe.Sizeof(bpf.PodEgressLbBackendVal{}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.key.Width(); uintptr(got) != tc.keySize {
				t.Errorf("%s key: schema=%d, generated=%d", tc.name, got, tc.keySize)
			}
			if got := tc.val.Width(); uintptr(got) != tc.valueSize {
				t.Errorf("%s value: schema=%d, generated=%d", tc.name, got, tc.valueSize)
			}
		})
	}
}

// ----- schema builders mirrored from register.go ------------------------
//
// Kept as private helpers so the test can compare widths without
// constructing full Descriptors (which require live *ebpf.Map
// handles). When register.go changes, mirror it here too — the
// failure mode is loud and obvious.

func schemaSubnetKey() Schema { return Schema{Fields: []Field{FieldU32Named("subnet_id")}} }
func schemaSubnetVal() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("table_id"),
		FieldU32Named("vpc_id"),
		FieldMACNamed("gw_mac"),
		FieldPadOf(2),
		FieldIPv4BENamed("gw_addr"),
		FieldU32Named("mask"),
		FieldU32Named("acl_id"),
	}}
}

func schemaIPv4FragKey() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("vpc_id"),
		FieldIPv4BENamed("saddr"),
		FieldIPv4BENamed("daddr"),
		FieldPortBENamed("id"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(1),
	}}
}
func schemaIPv4FragVal() Schema {
	return Schema{Fields: []Field{
		FieldPortBENamed("sport"),
		FieldPortBENamed("dport"),
		FieldPadOf(4),
		FieldU64Named("last_seen_ns"),
	}}
}

func schemaArpKey() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("subnet_id"),
		FieldIPv4BENamed("ipaddr"),
	}}
}
func schemaArpVal() Schema { return Schema{Fields: []Field{FieldMACNamed("mac")}} }

func schemaExternalArpKey() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("ifindex"),
		FieldIPv4Named("ipaddr"),
	}}
}
func schemaExternalArpVal() Schema {
	return Schema{Fields: []Field{
		FieldMACNamed("mac"),
		FieldPadOf(2),
	}}
}

func schemaFdbKey() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("subnet_id"),
		FieldMACNamed("mac"),
		FieldPadOf(2),
	}}
}
func schemaFdbVal() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("ifindex"),
		FieldIPv4BENamed("vtep_ip"),
	}}
}

func schemaServiceKey() Schema {
	return Schema{Fields: []Field{
		FieldIPv4BENamed("cluster_ip"),
		FieldPortNamed("port"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(1),
	}}
}
func schemaServiceVal() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("owner_vpc_id"),
		FieldU32Named("backend_count"),
		FieldU32Named("affinity_sec"),
		FieldFlagsNamed("flags", 4, SVCFlagDict),
		FieldU32Named("gen"),
	}}
}

func schemaServiceAffinityKey() Schema {
	return Schema{Fields: []Field{
		FieldIPv4BENamed("cluster_ip"),
		FieldPortNamed("port"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(1),
		FieldIPv4BENamed("client_ip"),
	}}
}
func schemaServiceAffinityVal() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("backend_index"),
		FieldU32Named("backend_gen"),
		FieldU64Named("expires_at_ns"),
	}}
}

func schemaServiceACLKey() Schema {
	return Schema{Fields: []Field{
		FieldIPv4BENamed("cluster_ip"),
		FieldPortNamed("port"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(1),
		FieldU32Named("caller_vpc_id"),
	}}
}
func schemaPresentVal() Schema {
	return Schema{Fields: []Field{FieldU8Named("present")}}
}

func schemaBackendKey() Schema {
	return Schema{Fields: []Field{
		FieldIPv4BENamed("cluster_ip"),
		FieldPortNamed("port"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(1),
		FieldU32Named("index"),
	}}
}
func schemaBackendVal() Schema {
	return Schema{Fields: []Field{
		FieldIPv4BENamed("backend_ip"),
		FieldPortNamed("backend_port"),
		FieldEnumNamed("kind", 1, BackendKindEnum),
		FieldPadOf(1),
		FieldU32Named("backend_subnet_id"),
	}}
}

func schemaCTKey() Schema {
	return Schema{Fields: []Field{
		FieldEnumNamed("scope", 4, CTScopeEnum),
		FieldIPv4BENamed("saddr"),
		FieldIPv4BENamed("daddr"),
		FieldPortNamed("sport"),
		FieldPortNamed("dport"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(3),
	}}
}
func schemaCTVal() Schema {
	return Schema{Fields: []Field{
		FieldIPv4BENamed("new_saddr"),
		FieldIPv4BENamed("new_daddr"),
		FieldPortNamed("new_sport"),
		FieldPortNamed("new_dport"),
		FieldU32Named("next_subnet_id"),
		FieldEnumNamed("action", 1, CTActionEnum),
		FieldEnumNamed("state", 1, CTStateEnum),
		FieldU8Named("flags_seen"),
		FieldPadOf(5),
		FieldU64Named("last_seen_ns"),
	}}
}

func schemaPolicyCTKey() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("epoch"),
		FieldEnumNamed("scope", 4, CTScopeEnum),
		FieldIPv4BENamed("saddr"),
		FieldIPv4BENamed("daddr"),
		FieldPortBENamed("sport"),
		FieldPortBENamed("dport"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldEnumNamed("hook", 1, PolicyHookEnum),
		FieldPadOf(2),
	}}
}
func schemaPolicyCTVal() Schema {
	return Schema{Fields: []Field{
		FieldEnumNamed("state", 1, CTStateEnum),
		FieldU8Named("flags_seen"),
		FieldPadOf(6),
		FieldU64Named("last_seen_ns"),
	}}
}

func schemaPolicyEpochKey() Schema {
	return Schema{Fields: []Field{FieldU32Named("index")}}
}
func schemaPolicyEpochVal() Schema {
	return Schema{Fields: []Field{FieldU32Named("epoch")}}
}

func schemaVirtSvcKey() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("subnet_id"),
		FieldIPv4BENamed("dst_ip"),
		FieldPortBENamed("dst_port"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(1),
	}}
}
func schemaVirtSvcVal() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("service_id"),
		FieldU32Named("tap_ifindex"),
		FieldMACNamed("service_mac"),
		FieldPadOf(2),
		FieldFlagsNamed("flags", 4, VirtSvcFlagDict),
	}}
}

func schemaVirtSvcFlowKey() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("subnet_id"),
		FieldIPv4BENamed("src_ip"),
		FieldIPv4BENamed("dst_ip"),
		FieldPortBENamed("src_port"),
		FieldPortBENamed("dst_port"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(3),
	}}
}
func schemaVirtSvcFlowVal() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("vpc_id"),
		FieldU32Named("service_id"),
		FieldU32Named("pod_ifindex"),
		FieldMACNamed("pod_mac"),
		FieldMACNamed("service_mac"),
		FieldPadOf(2),
		FieldRawNamed("_align_pad", 6),
		FieldU64Named("last_seen_ns"),
	}}
}

func schemaFibInnerKey() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("prefixlen"),
		FieldIPv4BENamed("dst"),
	}}
}
func schemaFibInnerVal() Schema {
	return Schema{Fields: []Field{
		FieldEnumNamed("type", 1, FIBRouteTypeEnum),
		FieldMACNamed("dmac"),
		FieldMACNamed("smac"),
		FieldPadOf(3),
		FieldU32Named("subnet_id"),
		FieldU32Named("oif"),
	}}
}

func schemaSGMembershipKey() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("vpc_id"),
		FieldIPv4BENamed("ipv4"),
	}}
}
func schemaSGMembershipVal() Schema {
	return Schema{Fields: []Field{
		FieldU8Named("count"),
		FieldPadOf(3),
		FieldU32Named("sg0"),
		FieldU32Named("sg1"),
	}}
}

func schemaSGMetaKey() Schema { return Schema{Fields: []Field{FieldU32Named("sg_id")}} }
func schemaSGMetaVal() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("ingress_count"),
		FieldU32Named("egress_count"),
		FieldU32Named("ruleset_version"),
		FieldU8Named("has_egress_rules"),
		FieldPadOf(3),
	}}
}

func schemaSlotKey() Schema { return Schema{Fields: []Field{FieldU32Named("slot")}} }

func schemaSGRuleInner() Schema {
	return Schema{Fields: []Field{
		FieldEnumNamed("proto", 2, PolicyProtoEnum),
		FieldU16Named("port_lo"),
		FieldU16Named("port_hi"),
		FieldEnumNamed("direction", 1, SGDirEnum),
		FieldEnumNamed("peer_kind", 1, SGPeerKindEnum),
		FieldIPv4BENamed("peer_v4"),
		FieldU8Named("peer_prefixlen"),
		FieldEnumNamed("verdict", 1, SGVerdictEnum),
		FieldPadOf(2),
	}}
}

func schemaACLMetaKey() Schema { return Schema{Fields: []Field{FieldU32Named("acl_id")}} }
func schemaACLMetaVal() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("ingress_count"),
		FieldU32Named("egress_count"),
		FieldU64Named("ruleset_version"),
		FieldU8Named("has_ingress_rules"),
		FieldU8Named("has_egress_rules"),
		FieldPadOf(6),
	}}
}

func schemaACLRuleInner() Schema {
	return Schema{Fields: []Field{
		FieldEnumNamed("proto", 2, PolicyProtoEnum),
		FieldU16Named("port_lo"),
		FieldU16Named("port_hi"),
		FieldU16Named("priority"),
		FieldIPv4BENamed("peer_v4"),
		FieldEnumNamed("direction", 1, ACLDirEnum),
		FieldU8Named("prefixlen"),
		FieldEnumNamed("verdict", 1, ACLVerdictEnum),
		FieldPadOf(1),
	}}
}

func schemaLBServiceKey() Schema {
	return Schema{Fields: []Field{
		FieldIPv4BENamed("vip"),
		FieldPortNamed("port"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(1),
	}}
}

func schemaLBServiceVal() Schema {
	return Schema{Fields: []Field{
		FieldU32Named("backend_count"),
		FieldU32Named("gen"),
		FieldU32Named("flags"),
		FieldPadOf(4),
	}}
}

func schemaLBBackendKey() Schema {
	return Schema{Fields: []Field{
		FieldIPv4BENamed("vip"),
		FieldPortNamed("port"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(1),
		FieldU32Named("index"),
	}}
}

func schemaLBBackendVal() Schema {
	return Schema{Fields: []Field{
		FieldIPv4BENamed("backend_ip"),
		FieldPortNamed("backend_port"),
		FieldPadOf(2),
		FieldU32Named("backend_subnet_id"),
	}}
}
