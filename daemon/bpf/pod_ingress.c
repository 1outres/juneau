// go:build ignore
//
// pod_ingress is attached to the egress side of each Pod's host-side veth
// peer (i.e. packets destined for the Pod). It applies any reverse SNAT
// recorded in conntrack so that responses to Service requests carry the
// original ClusterIP rather than the backend Pod IP. Forward DNAT lives
// in pod_egress; the two programs together cover the symmetric NAT pair.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "ct.h"
#include "maps.h"
#include "nat.h"
#include "policy.h"
#include "sg.h"
#include "trace.h"

#define ETH_P_IP 0x0800
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

static __always_inline int handle(struct __sk_buff *skb) {
  void *data = nat_skb_data(skb);
  void *data_end = nat_skb_data_end(skb);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  __u16 h_proto = bpf_ntohs(eth->h_proto);

  // Resolve the receiving Pod's Subnet (and thus VPC) so the conntrack
  // key matches the forward entry installed by pod_egress on this node.
  //
  // This used to sit behind the ethertype check. It runs first now
  // because the ethertype decision needs the Pod's own address, and a
  // frame that is not IPv4 carries nothing the policy stage could look
  // the Pod up by.
  struct ifindex_subnet_key isk = {.ifindex = skb->ifindex};
  const struct ifindex_subnet_val *isv =
      bpf_map_lookup_elem(&ifindex_subnet, &isk);
  if (!isv)
    return TC_ACT_OK;

  struct subnet_key sk = {.subnet_id = isv->subnet_id};
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &sk);
  if (!subnet)
    return TC_ACT_OK;

  // Hook-entry trace event. Keep the trace_id so policy drops below
  // can attribute themselves to this hook in the timeline.
  __u32 __trace_id = 0;
  {
    struct trace_hook_ctx __ctx = {
        .reason = TRACE_REASON_ENTER_POD_INGRESS,
        .hook = TRACE_HOOK_POD_INGRESS,
        .vpc_id = subnet->vpc_id,
        .subnet_id = isv->subnet_id,
        .scope = TRACE_SCOPE_VPC,
    };
    __trace_id = trace_classify_and_emit_enter(skb, &__ctx);
  }

  if (h_proto != ETH_P_IP) {
    // ARP is let through whatever the policy says: juneau's own data
    // plane resolves Pod and gateway MACs with it, so a Pod that cannot
    // ARP has no working network at all.
    if (h_proto != ETH_P_ARP &&
        policy_enforced(subnet->vpc_id, subnet->acl_id, ACL_DIR_INGRESS,
                        isv->ipv4)) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_POLICY_ETHERTYPE_DROP,
                         TRACE_HOOK_POD_INGRESS, TRACE_SCOPE_VPC,
                         subnet->vpc_id, isv->subnet_id);
      return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
  }

  if (nat_apply_reverse_snat(skb, subnet->vpc_id, isv->subnet_id,
                             TRACE_HOOK_POD_INGRESS) < 0) {
    trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_INGRESS, TRACE_SCOPE_VPC,
                       subnet->vpc_id, isv->subnet_id);
    return TC_ACT_SHOT;
  }

  // Unified policy stage runs after reverse SNAT — the ACL and SG
  // layers evaluate the peer the *Pod* sees, which is the rewritten
  // src (= original ClusterIP for Service responses). Running this
  // after the reverse SNAT keeps user-facing rules ("admit traffic
  // from ClusterIP X") effective.
  int policy_rc =
      apply_policy(skb, POLICY_HOOK_POD_INGRESS, subnet->vpc_id,
                   subnet->acl_id, __trace_id, isv->subnet_id);
  if (policy_rc < 0) {
    // -1 = ACL deny, -3 = SG deny, -4 = L4 unreadable, -2 = internal
    // error.
    __u32 reason = TRACE_REASON_DROP_SHOT;
    if (policy_rc == -1)
      reason = TRACE_REASON_POLICY_ACL_DROP;
    else if (policy_rc == -3)
      reason = TRACE_REASON_POLICY_SG_DROP;
    else if (policy_rc == -4)
      reason = TRACE_REASON_POLICY_PARSE_DROP;
    trace_emit_drop_l3(skb, __trace_id, reason, TRACE_HOOK_POD_INGRESS,
                       TRACE_SCOPE_VPC, subnet->vpc_id, isv->subnet_id);
    return TC_ACT_SHOT;
  }

  // Terminal: hand the packet to the kernel for veth dispatch into
  // the Pod's netns. Emitting here gives the timeline a clear close
  // for the success path; without it the trace ended with the
  // hook-entry event and operators could not tell whether the
  // policy stage admitted the flow or silently dropped further down.
  trace_emit_pass_kernel_l3(skb, __trace_id, TRACE_HOOK_POD_INGRESS,
                            TRACE_SCOPE_VPC, subnet->vpc_id, isv->subnet_id);
  return TC_ACT_OK;
}

SEC("tc")
int tc_pod_ingress(struct __sk_buff *skb) {
  // See tc_pod_egress for why this anchor exists.
  (void)trace_is_active();
  return handle(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
