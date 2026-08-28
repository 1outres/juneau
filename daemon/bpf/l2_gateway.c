// go:build ignore
//
// l2_gateway runs at the egress of the veth juneau builds as the router
// port of an L2Network, which is the way out of the Vpc and into the
// segment. It is the second half of a pair: the ingress of the same
// veth runs pod_egress, so everything the Vpc already knows how to do —
// RouteTable, NATGateway, ClusterIP Service, NetworkACL, SecurityGroup
// — applies to the segment without a line of its own.
//
// The two kinds of frame that reach this hook come from those two
// halves. An IPv4 packet was placed here by a route, still addressed to
// the gateway that received it, so this program resolves the
// destination address to a MAC and signs the frame with the gateway's
// own. An ARP frame is a reply pod_egress built for the gateway's
// address and already carries the right pair. Nothing else belongs on
// an L3 port, so nothing else is put on the segment.
//
// It is also where a Service reply gets its ClusterIP back, and where
// the NetworkACL and the SecurityGroups of the segment are read for the
// direction coming in. A Subnet does both of those in pod_ingress, on
// the veth of the Pod that asked, but an L2Network NIC carries
// l2_egress and l2_ingress and neither of those reads an address. This
// hook is the only one a packet entering the segment passes through.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "arp.h"
#include "l2.h"
#include "maps.h"
#include "nat.h"
#include "policy.h"
#include "trace.h"

// l2_gateway_policy runs the policy stage for the direction entering
// the segment.
//
// It is a BPF-to-BPF subprogram, and every argument is a scalar. Inlined
// into handle() the verifier walked 622,171 instructions: the rewrite
// above it leaves several packet-pointer states behind, and it re-walks
// the whole rule evaluation for each of them. Behind a call it walks the
// body once. policy-data-plane.md warns about the other half of this
// trade — a noinline call taking a stack pointer explodes instead — so
// nothing here is passed by address.
static __juneau_bpf_subprog int l2_gateway_policy(struct __sk_buff *skb,
                                                  __u32 vpc_id, __u32 acl_id,
                                                  __u32 trace_id, __u32 vni) {
  return apply_policy(skb, POLICY_HOOK_POD_INGRESS, vpc_id, acl_id, trace_id,
                      vni);
}

static __always_inline int handle(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  __u32 gw_ifindex = skb->ifindex;

  struct l2_ifindex_key pkey = {.ifindex = gw_ifindex};
  const struct l2_ifindex_val *port = bpf_map_lookup_elem(&l2_ifindex, &pkey);
  if (!port) {
    trace_emit_map_miss_l3(skb, trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, 0),
                           TRACE_REASON_MISS_L2_PORT, TRACE_HOOK_L2_GATEWAY,
                           TRACE_SCOPE_VPC, 0, 0, gw_ifindex);
    return TC_ACT_SHOT;
  }
  __u32 vni = port->vni;

  struct l2_network_key nkey = {.vni = vni};
  const struct l2_network_val *network =
      bpf_map_lookup_elem(&l2_network_map, &nkey);
  if (!network) {
    trace_emit_map_miss_l3(skb, trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, 0),
                           TRACE_REASON_MISS_L2_NETWORK, TRACE_HOOK_L2_GATEWAY,
                           TRACE_SCOPE_VPC, 0, vni, vni);
    return TC_ACT_SHOT;
  }
  __u32 vpc_id = network->vpc_id;

  __u32 __trace_id = 0;
  {
    struct trace_hook_ctx __ctx = {
        .reason = TRACE_REASON_ENTER_L2_GATEWAY,
        .hook = TRACE_HOOK_L2_GATEWAY,
        .vpc_id = vpc_id,
        .subnet_id = vni,
        .scope = TRACE_SCOPE_VPC,
    };
    __trace_id = trace_classify_and_emit_enter(skb, &__ctx);
  }

  // The ifindex is checked against the one the reconciler recorded. A
  // veth index the kernel handed out again would otherwise let a frame
  // leave with the MAC of a gateway that no longer lives here.
  struct l2_gateway_key gkey = {.vni = vni};
  const struct l2_gateway_val *gateway =
      bpf_map_lookup_elem(&l2_gateway, &gkey);
  if (!gateway || gateway->ifindex != gw_ifindex) {
    trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_MISS_L2_GATEWAY,
                           TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni,
                           gw_ifindex);
    return TC_ACT_SHOT;
  }

  struct l2_fdb_inner_map *table = l2_fdb_for(vni);
  if (!table) {
    trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
    return TC_ACT_SHOT;
  }

  __u16 h_proto = bpf_ntohs(eth->h_proto);
  if (h_proto == ETH_P_IP) {
    // The reply of a Service flow a workload on the segment opened.
    // The forward DNAT was recorded by pod_egress on the ingress of
    // this same veth, under the vpc_id l2_network_map carries, so the
    // entry is here to be found.
    //
    // A Subnet reverses that rewrite in pod_ingress, on the veth of the
    // Pod that asked. An L2Network NIC runs l2_egress and l2_ingress
    // instead, and neither of those reads an address, so this hook is
    // the only place on the way home where it can happen. Without it
    // the workload sees an answer from the backend it never wrote to
    // and drops it.
    if (nat_apply_reverse_snat(skb, vpc_id, vni, TRACE_HOOK_L2_GATEWAY) < 0) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
      return TC_ACT_SHOT;
    }

    // NetworkACL and SecurityGroup for the direction entering the
    // segment. The boundary is described by the same subnet_map entry
    // pod_egress reads on the ingress of this veth, so both directions
    // are judged against one ACL and one set of memberships.
    //
    // It runs after the rewrite above, the way pod_ingress runs it
    // after its own: a rule that names a Service has to see the address
    // the workload wrote to, not the backend that answered.
    struct subnet_key skey = {.subnet_id = vni};
    const struct subnet_val *boundary = bpf_map_lookup_elem(&subnet_map, &skey);
    if (!boundary) {
      trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_MISS_SUBNET,
                             TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id,
                             vni, vni);
      return TC_ACT_SHOT;
    }

    // POLICY_HOOK_POD_INGRESS and not a hook of its own. The enforcement
    // point is what policy_ct_map is keyed on, and policy_ct_install
    // writes every admission under both the hook that made it and the
    // one that sees the flow from the other side. pod_egress on the
    // ingress of this veth is that other side, so this program has to
    // take the name it expects: a flow the segment opened is admitted
    // there under POD_EGRESS, and the reply short-circuits here because
    // the same call wrote the mirrored tuple under POD_INGRESS. A third
    // hook id would leave both directions evaluating each other's
    // replies from scratch.
    //
    // The cost is that the per-layer trace events of this stage report
    // hook pod_ingress. The drop below is emitted under l2_gateway, so
    // a timeline still says where the packet stopped.
    int policy_rc =
        l2_gateway_policy(skb, vpc_id, boundary->acl_id, __trace_id, vni);
    if (policy_rc < 0) {
      __u32 reason = TRACE_REASON_DROP_SHOT;
      if (policy_rc == -1)
        reason = TRACE_REASON_POLICY_ACL_DROP;
      else if (policy_rc == -3)
        reason = TRACE_REASON_POLICY_SG_DROP;
      else if (policy_rc == -4)
        reason = TRACE_REASON_POLICY_PARSE_DROP;
      trace_emit_drop_l3(skb, __trace_id, reason, TRACE_HOOK_L2_GATEWAY,
                         TRACE_SCOPE_VPC, vpc_id, vni);
      return TC_ACT_SHOT;
    }

    // Both stages above reload skb->data, so the header pointers are
    // taken again rather than carried over them.
    struct iphdr *iph = nat_load_iph(skb);
    if (!iph)
      return TC_ACT_SHOT;
    eth = (struct ethhdr *)((void *)iph - sizeof(struct ethhdr));

    struct l2_arp_inner_map *addresses = l2_arp_for(vni);
    if (!addresses) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
      return TC_ACT_SHOT;
    }

    // The gateway sends no ARP of its own, so an address no host on the
    // segment has ever spoken from cannot be reached. A host that wants
    // to be reached from the Vpc asks the gateway for its MAC first,
    // and that request is what fills this table in.
    struct l2_arp_key akey = {.ipv4 = bpf_ntohl(iph->daddr)};
    const struct l2_arp_val *resolved = bpf_map_lookup_elem(addresses, &akey);
    if (!resolved) {
      trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_MISS_L2_ARP,
                             TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id,
                             vni, akey.ipv4);
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
      return TC_ACT_SHOT;
    }

    __builtin_memcpy(eth->h_dest, resolved->mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, gateway->mac, ETH_ALEN);
  } else if (h_proto != ETH_P_ARP) {
    trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
    return TC_ACT_SHOT;
  }

  __u8 dst_mac[ETH_ALEN];
  __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);

  // The gateway is a port of the segment like any other, so the frame
  // it puts on the segment is forwarded by the same rules: out of the
  // one port that holds the destination MAC, and never back out of the
  // port it came in on.
  struct l2_port from = {
      .vni = vni, .in_ifindex = gw_ifindex, .from_overlay = false};

  if (!l2_is_bum(dst_mac)) {
    struct l2_forward forwarded = {};
    if (l2_forward_unicast(skb, table, dst_mac, &from, &forwarded)) {
      if (forwarded.verdict == TC_ACT_SHOT)
        trace_emit_drop_l3(skb, __trace_id, forwarded.reason,
                           TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
      else
        trace_emit_redirect_l3(skb, __trace_id, forwarded.reason,
                               TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id,
                               vni, forwarded.target_ifindex);
      return forwarded.verdict;
    }
    trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_MISS_L2_FDB,
                           TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni,
                           vni);
  }

  // The address resolved but the MAC behind it has gone quiet, so the
  // frame is copied to every port the way a switch treats an unknown
  // unicast. It carries the destination's own MAC, so only that host
  // takes it.
  __u32 copies = l2_flood(skb, &from);
  trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_L2_FLOOD,
                         TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni,
                         copies);
  return TC_ACT_SHOT;
}

SEC("tc")
int tc_l2_gateway(struct __sk_buff *skb) {
  // See tc_pod_egress for why this anchor exists.
  (void)trace_is_active();
  return handle(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
