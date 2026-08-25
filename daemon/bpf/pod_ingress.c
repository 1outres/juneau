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

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// apply_reverse_snat looks up the conntrack table for the inbound
// packet's 5-tuple. If a SNAT entry exists (which means this is the
// response leg of a Service flow whose forward DNAT was registered on
// this node), the source IP+port are rewritten back to the ClusterIP.
//
// Non-matching packets pass through unchanged. The function returns -1
// only on packet rewrite failures.
static __always_inline int apply_reverse_snat(struct __sk_buff *skb,
                                              __u32 vpc_id, __u32 subnet_id) {
  struct iphdr *iph = nat_load_iph(skb);
  if (!iph)
    return 0;
  void *data_end = nat_skb_data_end(skb);

  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return 0;

  __be16 sport, dport;
  if (nat_read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return 0;

  struct ct_key ck = {
      .scope = vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (!cv || cv->action != CT_ACTION_SNAT)
    return 0;

  cv->last_seen_ns = bpf_ktime_get_ns();
  __be32 new_saddr = cv->new_saddr;
  __be16 new_sport = cv->new_sport;
  __be32 before_saddr = iph->saddr;
  __be32 before_daddr = iph->daddr;
  __u8   before_proto = iph->protocol;

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  if (nat_rewrite_ipv4_addr(skb, true, new_saddr) < 0)
    return -1;
  if (nat_rewrite_l4_port(skb, true, new_sport) < 0)
    return -1;

  // Trace: reverse SNAT applied. before = (backend Pod IP, caller),
  // after = (Service ClusterIP, caller). The learned tuple lets the
  // pod's network namespace see "from ClusterIP" responses match.
  {
    struct trace_nat_event __ne = {
        .vpc_id = vpc_id,
        .subnet_id = subnet_id,
        .hook = TRACE_HOOK_POD_INGRESS,
        .reason = TRACE_REASON_REVERSE_NAT_APPLIED,
        .scope = TRACE_SCOPE_VPC,
        .proto = before_proto,
        .before_saddr = before_saddr,
        .before_daddr = before_daddr,
        .before_sport = sport,
        .before_dport = dport,
        .after_saddr = new_saddr,
        .after_daddr = before_daddr,
        .after_sport = new_sport,
        .after_dport = dport,
    };
    trace_observe_nat(skb, &__ne);
  }

  if (have_tcp_flags)
    ct_observe_tcp(&ck, cv, tcp_flags);
  return 0;
}

static __always_inline int handle(struct __sk_buff *skb) {
  void *data = nat_skb_data(skb);
  void *data_end = nat_skb_data_end(skb);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  // Resolve the receiving Pod's Subnet (and thus VPC) so the conntrack
  // key matches the forward entry installed by pod_egress on this node.
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

  if (apply_reverse_snat(skb, subnet->vpc_id, isv->subnet_id) < 0) {
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
    // -1 = ACL deny, -3 = SG deny, -2 = internal error.
    __u32 reason = TRACE_REASON_DROP_SHOT;
    if (policy_rc == -1)
      reason = TRACE_REASON_POLICY_ACL_DROP;
    else if (policy_rc == -3)
      reason = TRACE_REASON_POLICY_SG_DROP;
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
