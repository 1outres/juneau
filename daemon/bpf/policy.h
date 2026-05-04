// Unified policy stage: NetworkACL → SecurityGroup → CT install.
//
// apply_policy_egress / apply_policy_ingress replace the per-layer
// apply_sg_egress / apply_sg_ingress used previously. They centralise:
//
//   * The single CT lookup that admits established flows past every
//     policy layer at once. CT entries created here use
//     CT_ACTION_POLICY_PASS, signifying "all applicable layers
//     admitted this flow"; reply packets short-circuit both ACL and
//     SG eval via the same CT entry.
//
//   * The evaluation order: ACL first (Subnet boundary, coarse), SG
//     second (per-NIC, fine). A DENY at either layer drops; a flow
//     is admitted only when neither layer denied AND at least one
//     layer affirmatively allowed (PASS-only outcomes leave the data
//     plane lookup-free, matching legacy behaviour for SG-less Pods).
//
//   * CT install at admission time is bidirectional so the reverse
//     leg (and follow-on packets in the original direction) skip
//     re-evaluation.

#ifndef JUNEAU_BPF_POLICY_H
#define JUNEAU_BPF_POLICY_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "acl.h"
#include "ct.h"
#include "maps.h"
#include "nat.h"
#include "sg.h"

// ct_install_policy_pass writes the bidirectional CT entries that
// represent "policy admitted this flow". Both directions share the
// same vpc_id-scoped namespace; the SG and ACL evaluations have
// already run, so the caller only supplies what's needed to mint the
// keys.
static __always_inline void ct_install_policy_pass(__u32 vpc_id,
                                                   __u8 proto,
                                                   __be32 saddr, __be32 daddr,
                                                   __u16 sport_h, __u16 dport_h,
                                                   __u8 init_state, __u8 init_flags) {
  __u64 now = bpf_ktime_get_ns();
  struct ct_key fwd_key = {
      .scope = vpc_id,
      .saddr = saddr,
      .daddr = daddr,
      .sport = bpf_htons(sport_h),
      .dport = bpf_htons(dport_h),
      .proto = proto,
  };
  struct ct_val fwd = {
      .action = CT_ACTION_POLICY_PASS,
      .state = init_state,
      .flags_seen = init_flags,
      .last_seen_ns = now,
  };
  bpf_map_update_elem(&ct_map, &fwd_key, &fwd, BPF_ANY);

  struct ct_key rev_key = {
      .scope = vpc_id,
      .saddr = daddr,
      .daddr = saddr,
      .sport = bpf_htons(dport_h),
      .dport = bpf_htons(sport_h),
      .proto = proto,
  };
  struct ct_val rev = {
      .action = CT_ACTION_POLICY_PASS,
      .state = init_state,
      .flags_seen = init_flags,
      .last_seen_ns = now,
  };
  bpf_map_update_elem(&ct_map, &rev_key, &rev, BPF_ANY);
}

// apply_policy_egress runs the unified policy stage for an egress
// packet leaving a Pod's veth.
//
// Returns:
//    1: admitted by policy and CT installed (caller continues)
//    0: established-flow short-circuit, or no enforcement applied
//   -1: terminal DENY (caller must TC_ACT_SHOT)
//   -2: internal error (caller must TC_ACT_SHOT)
static __always_inline int apply_policy_egress(struct __sk_buff *skb,
                                               __u32 vpc_id, __u32 acl_id) {
  struct iphdr *iph = nat_load_iph(skb);
  if (!iph)
    return -2;
  void *data_end = nat_skb_data_end(skb);

  __u8 proto = iph->protocol;
  __u16 sport = 0;
  __u16 dport = 0;
  if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
    __be16 sp_be, dp_be;
    if (nat_read_l4_ports(iph, data_end, &sp_be, &dp_be) < 0)
      return 0;
    sport = bpf_ntohs(sp_be);
    dport = bpf_ntohs(dp_be);
  } else if (proto != IPPROTO_ICMP) {
    return 0;
  }

  // Established-flow short-circuit. POLICY_PASS hits skip every
  // per-layer eval. Service-related actions (DNAT/SNAT/...) skip the
  // policy stage entirely — they were already admitted when the
  // flow's first packet was evaluated.
  struct ct_key ck = {
      .scope = vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = bpf_htons(sport),
      .dport = bpf_htons(dport),
      .proto = proto,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (cv) {
    if (cv->action == CT_ACTION_POLICY_PASS) {
      cv->last_seen_ns = bpf_ktime_get_ns();
      if (proto == IPPROTO_TCP) {
        __u8 f;
        if (ct_read_tcp_flags(iph, data_end, &f) == 0)
          ct_observe_tcp(&ck, cv, f);
      }
      return 0;
    }
    return 0;
  }

  // ACL eval first (Subnet boundary). Peer for egress is daddr.
  int acl_v = acl_evaluate(acl_id, ACL_DIR_EGRESS, proto, dport, iph->daddr);
  if (acl_v == ACL_VERDICT_DENY)
    return -1;

  // SG eval (per-NIC). Skip cleanly when self has no SG attached so
  // the legacy "no enforcement" behaviour is preserved for Pods that
  // sit behind only an ACL (or behind nothing at all).
  struct sg_membership_val *self = sg_membership_lookup(vpc_id, iph->saddr);
  struct sg_membership_val *peer = sg_membership_lookup(vpc_id, iph->daddr);
  int sg_v = SG_VERDICT_PASS;
  if (self != NULL && self->count > 0)
    sg_v = sg_eval(self, SG_DIR_EGRESS, proto, dport, iph->daddr, peer);
  if (sg_v == SG_VERDICT_DENY)
    return -1;

  // Install CT only when at least one layer affirmatively allowed.
  // Two PASS verdicts mean neither layer is enforcing this flow, so
  // a CT entry would only burn map space.
  if (acl_v != ACL_VERDICT_ALLOW && sg_v != SG_VERDICT_ALLOW)
    return 0;

  __u8 init_flags = 0;
  __u8 init_state = CT_STATE_ESTABLISHED;
  if (proto == IPPROTO_TCP) {
    __u8 f;
    if (ct_read_tcp_flags(iph, data_end, &f) == 0) {
      init_flags = f & TCP_FLAG_TRACKED;
      init_state = ct_initial_state_for_syn(f);
    }
  }
  ct_install_policy_pass(vpc_id, proto, iph->saddr, iph->daddr, sport, dport,
                         init_state, init_flags);
  return 1;
}

// apply_policy_ingress mirrors apply_policy_egress for inbound
// traffic at a local Pod's veth.
//
// Returns:
//    0: admitted (or short-circuited via CT, or no enforcement)
//   -1: terminal DENY (caller must TC_ACT_SHOT)
//   -2: internal error (caller must TC_ACT_SHOT)
static __always_inline int apply_policy_ingress(struct __sk_buff *skb,
                                                __u32 vpc_id, __u32 acl_id) {
  struct iphdr *iph = nat_load_iph(skb);
  if (!iph)
    return -2;
  void *data_end = nat_skb_data_end(skb);

  __u8 proto = iph->protocol;
  __u16 sport = 0;
  __u16 dport = 0;
  if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
    __be16 sp_be, dp_be;
    if (nat_read_l4_ports(iph, data_end, &sp_be, &dp_be) < 0)
      return 0;
    sport = bpf_ntohs(sp_be);
    dport = bpf_ntohs(dp_be);
  } else if (proto != IPPROTO_ICMP) {
    return 0;
  }

  struct ct_key ck = {
      .scope = vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = bpf_htons(sport),
      .dport = bpf_htons(dport),
      .proto = proto,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (cv) {
    if (cv->action == CT_ACTION_POLICY_PASS) {
      cv->last_seen_ns = bpf_ktime_get_ns();
      if (proto == IPPROTO_TCP) {
        __u8 f;
        if (ct_read_tcp_flags(iph, data_end, &f) == 0)
          ct_observe_tcp(&ck, cv, f);
      }
    }
    return 0;
  }

  // Peer for ingress is the sender (saddr). self is the receiving
  // Pod, identified by daddr.
  int acl_v = acl_evaluate(acl_id, ACL_DIR_INGRESS, proto, dport, iph->saddr);
  if (acl_v == ACL_VERDICT_DENY)
    return -1;

  struct sg_membership_val *self = sg_membership_lookup(vpc_id, iph->daddr);
  struct sg_membership_val *peer = sg_membership_lookup(vpc_id, iph->saddr);
  int sg_v = SG_VERDICT_PASS;
  if (self != NULL && self->count > 0)
    sg_v = sg_eval(self, SG_DIR_INGRESS, proto, dport, iph->saddr, peer);
  if (sg_v == SG_VERDICT_DENY)
    return -1;

  if (acl_v != ACL_VERDICT_ALLOW && sg_v != SG_VERDICT_ALLOW)
    return 0;

  __u8 init_flags = 0;
  __u8 init_state = CT_STATE_ESTABLISHED;
  if (proto == IPPROTO_TCP) {
    __u8 f;
    if (ct_read_tcp_flags(iph, data_end, &f) == 0) {
      init_flags = f & TCP_FLAG_TRACKED;
      init_state = ct_initial_state_for_syn(f);
    }
  }
  ct_install_policy_pass(vpc_id, proto, iph->saddr, iph->daddr, sport, dport,
                         init_state, init_flags);
  return 0;
}

#endif // JUNEAU_BPF_POLICY_H
