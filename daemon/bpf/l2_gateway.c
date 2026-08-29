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
// What it does not do is undo a NAT or read a policy. Both of those
// need the conntrack of the flow, and that lives on the node the flow
// was opened from. This program runs wherever the packet was routed,
// which for a reply is the node the far end sits on, so it would be
// reading a table that has never heard of the flow. l2_ingress does
// them instead: that hook always runs on the node of the workload the
// packet is addressed to, which is the node that holds the flow.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "arp.h"
#include "l2.h"
#include "maps.h"
#include "trace.h"

// ask_the_segment puts an ARP request for one address on the segment
// and reports the verdict for the packet that needed it, which is
// always a drop. target is in host byte order and target_be is the same
// address as it sits in the packet.
//
// This is what a router does with a packet for a neighbour it has not
// resolved, minus the one thing a BPF program cannot do: hold the
// packet until the answer arrives. There is no way to park an skb, so
// the first packet to an address nobody has spoken from is lost and a
// retransmit is what reaches the host. TCP hides that; a single ICMP
// echo or a lone UDP datagram does not.
//
// It is what makes the addresses juneau never handed out reachable —
// one a workload gave itself, one belonging to a host behind a bridge
// on the far side of a NIC — which is most of the reason to run an
// L2Network at all.
static __always_inline int ask_the_segment(struct __sk_buff *skb,
                                           __u32 trace_id, __u32 vpc_id,
                                           __u32 vni, __u32 gw_ifindex,
                                           const __u8 *gw_mac, __u32 target,
                                           __be32 target_be) {
  struct subnet_key skey = {.subnet_id = vni};
  const struct subnet_val *boundary = bpf_map_lookup_elem(&subnet_map, &skey);
  if (!boundary) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_SUBNET,
                           TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni,
                           vni);
    return TC_ACT_SHOT;
  }

  // Only the prefix of the segment is asked for. A router resolves the
  // neighbours of the link it is on and nothing else, and no host here
  // can answer for an address from anywhere else. Without the test, a
  // route aimed at this gateway by mistake would turn every packet it
  // carries into a request on every port.
  if ((target & boundary->mask) != (boundary->gw_addr & boundary->mask)) {
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
    return TC_ACT_SHOT;
  }

  struct l2_arp_probe_inner_map *asked = l2_arp_probe_for(vni);
  if (!asked) {
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
    return TC_ACT_SHOT;
  }
  if (!l2_arp_probe_take(asked, target)) {
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_L2_ARP_HELD,
                       TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
    return TC_ACT_SHOT;
  }

  // The gateway port itself is skipped, because the request leaves from
  // it. A copy handed back would reach l2_egress on that port, which
  // reads the sender of every ARP frame, and the segment would record
  // the gateway as the owner of the address it is still looking for.
  struct l2_port from = {
      .vni = vni, .in_ifindex = gw_ifindex, .from_overlay = false};
  int copies = l2_arp_request(skb, &from, gw_mac,
                              bpf_htonl(boundary->gw_addr), target_be);
  if (copies < 0) {
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
    return TC_ACT_SHOT;
  }

  trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_L2_ARP_ASKED,
                         TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni,
                         (__u32)copies);
  return TC_ACT_SHOT;
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
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
      return TC_ACT_SHOT;

    struct l2_arp_inner_map *addresses = l2_arp_for(vni);
    if (!addresses) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id, vni);
      return TC_ACT_SHOT;
    }

    // The table is filled in from the ARP that crosses the segment and
    // from the addresses the controller handed out. An address in
    // neither is one the gateway has to go and ask for.
    struct l2_arp_key akey = {.ipv4 = bpf_ntohl(iph->daddr)};
    const struct l2_arp_val *resolved = bpf_map_lookup_elem(addresses, &akey);
    if (!resolved) {
      __be32 target_be = iph->daddr;
      trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_MISS_L2_ARP,
                             TRACE_HOOK_L2_GATEWAY, TRACE_SCOPE_VPC, vpc_id,
                             vni, akey.ipv4);
      return ask_the_segment(skb, __trace_id, vpc_id, vni, gw_ifindex,
                             gateway->mac, akey.ipv4, target_be);
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
