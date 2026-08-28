// go:build ignore
//
// l2_ingress runs at the egress of the host side of a veth whose NIC
// joined an L2Network, which is the last stop before the frame reaches
// the workload.
//
// Frames that stay on the segment pass through untouched. juneau reads
// no address and no policy for them, which is the whole point of an
// L2Network: the workload may run its own bridge, its own DHCP server
// or a router, and whatever it says to its neighbours is its business.
//
// A frame the gateway put on the segment is different. It crossed the
// boundary of the Vpc, so the NetworkACL and the SecurityGroups of the
// segment apply to it, and a Service reply has to get its ClusterIP
// back before the workload sees an answer from an address it never
// wrote to.
//
// Both of those need the conntrack of the flow, and conntrack lives on
// the node the flow was opened from. This hook is the only one on the
// way in that always runs there: the gateway port runs wherever the
// packet happened to be routed, which for a reply is the node the far
// end sits on. Doing it there read a table that had never heard of the
// flow, and every cross-node reply was dropped or left unrewritten.
//
// The two kinds of frame are told apart by the source address. Only the
// gateway signs with the gateway MAC, and l2_egress refuses to move
// that address off the gateway port, so a workload cannot take it over.
// A workload that puts it in a frame it sends is asking for its own
// traffic to be judged, which is a strange thing to ask for and not a
// way around anything.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "l2.h"
#include "maps.h"
#include "nat.h"
#include "policy.h"
#include "trace.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

// l2_ingress_policy runs the policy stage for a frame the gateway put
// on the segment.
//
// It is a BPF-to-BPF subprogram and every argument is a scalar. See
// policy-data-plane.md: inlined after a NAT rewrite, the verifier walks
// the rule evaluation once per packet-pointer state the rewrite leaves
// behind; behind a call that passes no address, it walks the body once.
//
// POLICY_HOOK_POD_INGRESS and not a hook of its own. policy_ct_map is
// keyed on the enforcement point, and policy_ct_install writes every
// admission twice: under the hook that made it, and as the mirrored
// tuple under the hook that sees the same flow from the other side.
// pod_egress on the gateway veth is that other side, and it runs on
// this same node, so this program has to take the name it expects. A
// third hook id would leave a flow the segment opened being judged
// again on the way home, and an ACL refusing everything inbound would
// then kill every outbound flow.
static __juneau_bpf_subprog int l2_ingress_policy(struct __sk_buff *skb,
                                                  __u32 vpc_id, __u32 acl_id,
                                                  __u32 trace_id, __u32 vni) {
  return apply_policy(skb, POLICY_HOOK_POD_INGRESS, vpc_id, acl_id, trace_id,
                      vni);
}

// from_gateway reports whether the gateway of this segment signed the
// frame.
static __always_inline bool from_gateway(const struct ethhdr *eth, __u32 vni) {
  struct l2_gateway_key gkey = {.vni = vni};
  const struct l2_gateway_val *gateway =
      bpf_map_lookup_elem(&l2_gateway, &gkey);
  if (!gateway)
    return false;

#pragma unroll
  for (int i = 0; i < ETH_ALEN; i++) {
    if (eth->h_source[i] != gateway->mac[i])
      return false;
  }
  return true;
}

static __always_inline int handle(struct __sk_buff *skb) {
  struct l2_ifindex_key pkey = {.ifindex = skb->ifindex};
  const struct l2_ifindex_val *port = bpf_map_lookup_elem(&l2_ifindex, &pkey);
  if (!port)
    return TC_ACT_OK;

  struct l2_network_key nkey = {.vni = port->vni};
  const struct l2_network_val *network =
      bpf_map_lookup_elem(&l2_network_map, &nkey);
  if (!network)
    return TC_ACT_OK;

  __u32 vni = port->vni;
  __u32 vpc_id = network->vpc_id;

  __u32 __trace_id = 0;
  {
    struct trace_hook_ctx __ctx = {
        .reason = TRACE_REASON_ENTER_L2_INGRESS,
        .hook = TRACE_HOOK_L2_INGRESS,
        .vpc_id = vpc_id,
        .subnet_id = vni,
        .scope = TRACE_SCOPE_VPC,
    };
    __trace_id = trace_classify_and_emit_enter(skb, &__ctx);
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  if (eth->h_proto == bpf_htons(ETH_P_IP) && from_gateway(eth, vni)) {
    // The rewrite comes first, the way pod_ingress orders its own. The
    // records both stages read were written against the address the
    // workload wrote to, so the reply has to carry that address again
    // before either of them can find the flow.
    if (nat_apply_reverse_snat(skb, vpc_id, vni, TRACE_HOOK_L2_INGRESS) < 0) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_L2_INGRESS, TRACE_SCOPE_VPC, vpc_id, vni);
      return TC_ACT_SHOT;
    }

    // The ACL of the segment sits in the subnet_map entry the gateway
    // reconciler wrote, which is the same entry pod_egress reads on the
    // ingress of the gateway veth. One boundary, one ruleset, both
    // directions.
    //
    // It is there whenever l2_gateway is: the reconciler writes this
    // one first and the gateway entry last, so a frame that got past
    // from_gateway cannot arrive before the boundary is described.
    struct subnet_key skey = {.subnet_id = vni};
    const struct subnet_val *boundary = bpf_map_lookup_elem(&subnet_map, &skey);
    if (!boundary) {
      trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_MISS_SUBNET,
                             TRACE_HOOK_L2_INGRESS, TRACE_SCOPE_VPC, vpc_id,
                             vni, vni);
      return TC_ACT_SHOT;
    }

    int policy_rc =
        l2_ingress_policy(skb, vpc_id, boundary->acl_id, __trace_id, vni);
    if (policy_rc < 0) {
      __u32 reason = TRACE_REASON_DROP_SHOT;
      if (policy_rc == -1)
        reason = TRACE_REASON_POLICY_ACL_DROP;
      else if (policy_rc == -3)
        reason = TRACE_REASON_POLICY_SG_DROP;
      else if (policy_rc == -4)
        reason = TRACE_REASON_POLICY_PARSE_DROP;
      trace_emit_drop_l3(skb, __trace_id, reason, TRACE_HOOK_L2_INGRESS,
                         TRACE_SCOPE_VPC, vpc_id, vni);
      return TC_ACT_SHOT;
    }
  }

  trace_emit_pass_kernel_l3(skb, __trace_id, TRACE_HOOK_L2_INGRESS,
                            TRACE_SCOPE_VPC, vpc_id, vni);
  return TC_ACT_OK;
}

SEC("tc")
int tc_l2_ingress(struct __sk_buff *skb) {
  // See tc_pod_egress for why this anchor exists.
  (void)trace_is_active();
  return handle(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
