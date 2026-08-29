// go:build ignore
//
// l2_egress runs at the ingress of the host side of a veth whose NIC
// joined an L2Network, which is the path frames take when they leave
// the workload. It learns the source MAC, sends the frame to the port
// that holds the destination MAC, and copies it to every other port
// when no port holds it.
//
// Nothing here reads an IP address. Every EtherType passes, which is
// the point of an L2Network: the workload may run its own bridge, its
// own DHCP server or a router, and juneau must not answer for it.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "l2.h"
#include "maps.h"
#include "trace.h"

static __always_inline int handle(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  __u32 in_ifindex = skb->ifindex;

  struct l2_ifindex_key pkey = {.ifindex = in_ifindex};
  const struct l2_ifindex_val *port = bpf_map_lookup_elem(&l2_ifindex, &pkey);
  if (!port) {
    // The veth carries this program but no L2Network claims it yet.
    // Passing the frame on would put workload traffic on the host
    // stack, so it waits for the reconciler instead.
    trace_emit_map_miss_l3(skb, trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, 0),
                           TRACE_REASON_MISS_L2_PORT, TRACE_HOOK_L2_EGRESS,
                           TRACE_SCOPE_VPC, 0, 0, in_ifindex);
    return TC_ACT_SHOT;
  }
  __u32 vni = port->vni;
  struct l2_port from = {.vni = vni, .in_ifindex = in_ifindex, .from_overlay = false};

  struct l2_network_key nkey = {.vni = vni};
  const struct l2_network_val *network =
      bpf_map_lookup_elem(&l2_network_map, &nkey);
  if (!network) {
    trace_emit_map_miss_l3(skb, trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, 0),
                           TRACE_REASON_MISS_L2_NETWORK, TRACE_HOOK_L2_EGRESS,
                           TRACE_SCOPE_VPC, 0, vni, vni);
    return TC_ACT_SHOT;
  }
  __u32 vpc_id = network->vpc_id;

  __u32 __trace_id = 0;
  {
    struct trace_hook_ctx __ctx = {
        .reason = TRACE_REASON_ENTER_L2_EGRESS,
        .hook = TRACE_HOOK_L2_EGRESS,
        .vpc_id = vpc_id,
        .subnet_id = vni,
        .scope = TRACE_SCOPE_VPC,
    };
    __trace_id = trace_classify_and_emit_enter(skb, &__ctx);
  }

  struct l2_fdb_inner_map *table = l2_fdb_for(vni);
  if (!table) {
    trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_L2_EGRESS, TRACE_SCOPE_VPC, vpc_id, vni);
    return TC_ACT_SHOT;
  }

  // Copy both addresses out of the packet before any helper that may
  // invalidate the bounds the verifier proved for eth.
  __u8 src_mac[ETH_ALEN];
  __u8 dst_mac[ETH_ALEN];
  __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
  __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);

  // The addresses an ARP frame carries are recorded before anything
  // else reads the segment: the gateway resolves a destination address
  // to a MAC out of this table, and it has no other way to fill it in.
  struct l2_arp_view arp = {};
  l2_arp_snoop(skb, vni, eth, &arp);

  // Whatever MAC the workload puts in the frame is learned as its own.
  // An L2Network is a segment the user builds, so who claims which
  // address on it is the user's business, and a nested VM or a bridge
  // behind the NIC has to be able to speak for itself.
  if (l2_learn(table, src_mac, in_ifindex, 0))
    trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_L2_LEARNED,
                           TRACE_HOOK_L2_EGRESS, TRACE_SCOPE_VPC, vpc_id, vni,
                           in_ifindex);

  // A reply addressed to the gateway answers a question one of them
  // asked, and the one that asked is usually on another node. It goes
  // to the gateway here, to the node that asked, and to every node that
  // holds a port, instead of to the one port that holds the MAC.
  //
  // The node that asked is looked up by the address it was asking
  // about, which is the address the host is now answering for. Nothing
  // is written down here; the record was made where the question
  // arrived, in vxlan_ingress.
  //
  // Nothing is traced here. The trace plane keys on an IPv4 tuple and an
  // ARP frame has none, so trace_classify_and_emit_enter hands back the
  // id 0 and every emit under it returns without writing. What the
  // copies achieved is read out of l2_arp instead.
  if (arp.answer_to_gateway) {
    l2_flood_answer(skb, &from, l2_arp_recall_asker(vni, arp.sender));
    return TC_ACT_SHOT;
  }

  if (!l2_is_bum(dst_mac)) {
    struct l2_forward forwarded = {};
    if (l2_forward_unicast(skb, table, dst_mac, &from, &forwarded)) {
      if (forwarded.verdict == TC_ACT_SHOT)
        trace_emit_drop_l3(skb, __trace_id, forwarded.reason,
                           TRACE_HOOK_L2_EGRESS, TRACE_SCOPE_VPC, vpc_id, vni);
      else
        trace_emit_redirect_l3(skb, __trace_id, forwarded.reason,
                               TRACE_HOOK_L2_EGRESS, TRACE_SCOPE_VPC, vpc_id,
                               vni, forwarded.target_ifindex);
      return forwarded.verdict;
    }
    trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_MISS_L2_FDB,
                           TRACE_HOOK_L2_EGRESS, TRACE_SCOPE_VPC, vpc_id, vni,
                           vni);
  }

  // Broadcast, multicast and unknown unicast all take the same path: a
  // copy to every other port of the segment. Flooding the unknown
  // unicast is what lets a workload reach a peer juneau has not seen
  // send a frame yet.
  __u32 copies = l2_flood(skb, &from);
  trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_L2_FLOOD,
                         TRACE_HOOK_L2_EGRESS, TRACE_SCOPE_VPC, vpc_id, vni,
                         copies);

  // Every port that had to see the frame got a copy of its own, so the
  // frame the copies were made from is done.
  return TC_ACT_SHOT;
}

SEC("tc")
int tc_l2_egress(struct __sk_buff *skb) {
  // See tc_pod_egress for why this anchor exists.
  (void)trace_is_active();
  return handle(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
