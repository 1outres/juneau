// Unified policy stage: NetworkACL → SecurityGroup → CT install.
//
// apply_policy replaces the per-layer apply_sg_egress / apply_sg_ingress
// used previously. It centralises:
//
//   * The single CT lookup that admits established flows past every
//     policy layer at once. Entries live in policy_ct_map, keyed by
//     the enforcement point that wrote them, so a hit means "this
//     hook already admitted this flow" and never "some other hook
//     did".
//
//   * The evaluation order: ACL first (Subnet boundary, coarse), SG
//     second (per-NIC, fine). A DENY at either layer drops. A CT
//     entry is written whenever either layer is attached, PASS
//     verdicts included, because the reply still has to get back past
//     this hook. A Pod behind neither layer leaves the data plane
//     lookup-free.
//
//   * CT install at admission time is bidirectional so the reverse
//     leg (and follow-on packets in the original direction) skip
//     re-evaluation.
//
// Both hooks share one function body. The hook is a compile-time
// constant at every call site, so the per-hook branches below fold
// away and each program still gets straight-line code.

#ifndef JUNEAU_BPF_POLICY_H
#define JUNEAU_BPF_POLICY_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "acl.h"
#include "ct.h"
#include "maps.h"
#include "nat.h"
#include "policy_ct.h"
#include "sg.h"
#include "trace.h"

// policy_trace_hook translates an enforcement point into the hook id
// the trace plane reports. The two numbering schemes happen to agree
// today; converting explicitly keeps them free to diverge.
static __always_inline __u32 policy_trace_hook(__u8 hook) {
  if (hook == POLICY_HOOK_POD_EGRESS)
    return TRACE_HOOK_POD_EGRESS;
  return TRACE_HOOK_POD_INGRESS;
}

// apply_policy runs the policy stage for one packet at one enforcement
// point. `hook` is a POLICY_HOOK_* value and decides four things: the
// ACL direction, the SG direction, which address identifies the Pod
// being protected ("self") and which identifies the other end
// ("peer"). Everything else is shared.
//
// Returns:
//    1: admitted by policy and CT installed (caller continues)
//    0: established-flow short-circuit, or no enforcement applied
//   -1: terminal DENY by NetworkACL (caller must TC_ACT_SHOT)
//   -2: internal error (caller must TC_ACT_SHOT)
//   -3: terminal DENY by SecurityGroup (caller must TC_ACT_SHOT)
//
// Negative codes are split per layer so callers can attribute the
// drop to the right policy stage in trace events. Pre-split callers
// only checked policy_rc < 0 and emitted a generic ACL_DROP, which
// hid SG denials behind the wrong label.
//
// Inlined into the caller. The state-explosion pressure that used to
// require a separate subprogram lives now in `acl_evaluate` and
// `sg_eval` (both noinline subprograms): the rule-scan loops are the
// real source, and isolating those is enough.
//
// trace_id / subnet_id thread the active trace session through the
// policy stage so per-layer PASS events can fire at the same site
// where the per-layer DROP events are caught. trace_id == 0 short-
// circuits every emit with one comparison, so the no-trace path keeps
// its near-zero overhead.
static __always_inline int apply_policy(struct __sk_buff *skb, __u8 hook,
                                        __u32 vpc_id, __u32 acl_id,
                                        __u32 trace_id, __u32 subnet_id) {
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

  int egress = (hook == POLICY_HOOK_POD_EGRESS);
  __be32 self_ip = egress ? iph->saddr : iph->daddr;
  __be32 peer_ip = egress ? iph->daddr : iph->saddr;
  __u8 acl_dir = egress ? ACL_DIR_EGRESS : ACL_DIR_INGRESS;
  __u8 sg_dir = egress ? SG_DIR_EGRESS : SG_DIR_INGRESS;
  __u32 trace_hook = policy_trace_hook(hook);

  // Established-flow short-circuit. The epoch is part of the key, so a
  // rule change moves every later lookup onto keys nobody has written:
  // the flow misses and is evaluated again under the new rules. The
  // entries left behind by the old epoch are unreachable, and the data
  // plane never deletes them. The user-space GC in reconciler.Conntrack
  // drops every entry that is not on the current epoch on its next
  // pass.
  //
  // Do not move the epoch back into the value and compare it here.
  // That form has to delete the stale pair, and both ways of doing so
  // cost more than the verifier allows. Remembering "the entry was
  // stale" and cleaning up at each return keeps a flag live across the
  // whole ACL and SG evaluation, which makes the verifier walk that
  // region twice: pod_ingress went from 364,672 to 704,657 processed
  // instructions. Calling a noinline helper to delete instead pushed
  // pod_egress past the 1,000,000 limit and the program stopped
  // loading. With the epoch in the key this path needs no extra branch
  // at all.
  __u32 epoch = policy_ct_epoch();
  struct policy_ct_key ck =
      policy_ct_build_key(hook, epoch, vpc_id, iph->saddr, iph->daddr,
                          bpf_htons(sport), bpf_htons(dport), proto);
  struct policy_ct_val *pv = bpf_map_lookup_elem(&policy_ct_map, &ck);
  if (pv) {
    pv->last_seen_ns = bpf_ktime_get_ns();
    if (proto == IPPROTO_TCP) {
      __u8 f;
      if (ct_read_tcp_flags(iph, data_end, &f) == 0)
        policy_ct_observe_tcp(&ck, pv, f);
    }
    return 0;
  }

  // First-packet path: emit MISS_CONNTRACK so the timeline shows why
  // we are about to run the layered evaluator instead of taking the
  // CT shortcut. The renderer can be told to suppress these via
  // capture mask if too noisy.
  trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_CONNTRACK,
                         trace_hook, TRACE_SCOPE_VPC, vpc_id, subnet_id, 0);

  // ACL eval first (Subnet boundary), matched against the peer.
  int acl_v = acl_evaluate(acl_id, acl_dir, proto, dport, peer_ip);
  if (acl_v == ACL_VERDICT_DENY)
    return -1;
  if (acl_id != 0)
    trace_emit_policy_pass_l3(skb, trace_id, TRACE_REASON_POLICY_ACL_PASS,
                              trace_hook, TRACE_SCOPE_VPC, vpc_id, subnet_id);

  // SG eval (per-NIC). Skip cleanly when self has no SG attached so
  // the legacy "no enforcement" behaviour is preserved for Pods that
  // sit behind only an ACL (or behind nothing at all).
  struct sg_membership_val *self = sg_membership_lookup(vpc_id, self_ip);
  struct sg_membership_val *peer = sg_membership_lookup(vpc_id, peer_ip);
  int sg_v = SG_VERDICT_PASS;
  if (self != NULL && self->count > 0)
    {
      struct sg_eval_args sea = {
          .peer_ip = peer_ip,
          .dport = dport,
          .direction = sg_dir,
          .proto = proto,
      };
      sg_v = sg_eval(self, peer, &sea);
    }
  if (sg_v == SG_VERDICT_DENY)
    return -3;
  if (self != NULL && self->count > 0)
    trace_emit_policy_pass_l3(skb, trace_id, TRACE_REASON_POLICY_SG_PASS,
                              trace_hook, TRACE_SCOPE_VPC, vpc_id, subnet_id);

  // CT install policy: any enforcing layer (ACL attached OR SG
  // attached) is enough to warrant a CT entry. PASS verdicts still
  // install so the reverse leg — which may be SG-default-deny by AWS
  // rules — short-circuits via CT. Cross-Node flows depend on this:
  // the egress side's local CT carries the reverse entry that the
  // *return* packet hits at this hook on the way back.
  //
  // When neither layer is enforcing, skip CT install to avoid
  // burning map space on flows nobody is policing.
  int acl_enforcing = (acl_id != 0);
  int sg_enforcing = (self != NULL && self->count > 0);
  if (!acl_enforcing && !sg_enforcing)
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
  policy_ct_install(&ck, init_state, init_flags);
  return 1;
}

#endif // JUNEAU_BPF_POLICY_H
