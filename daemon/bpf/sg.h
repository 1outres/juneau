// SecurityGroup evaluation helpers for pod_egress / pod_ingress.
//
// Eval semantics:
//
//   * "self" is the local Pod's SG list (looked up from sg_membership_map
//     by (vpc_id, pod_ip)). "peer" is the remote endpoint's SG list (same
//     map, keyed by (vpc_id, peer_ip)). When the peer is outside the VPC
//     (e.g. ClusterIP or external CIDR) the peer lookup misses and only
//     CIDR rules can match it.
//
//   * For each SG attached to self, scan its rules for the requested
//     direction. ALLOW returned by any matching rule short-circuits to
//     ALLOW. If the relevant direction has rules but none match, the
//     verdict is DENY. A direction that declares an empty rule list
//     therefore denies everything, which is what a non-nil empty list
//     means in the CRD.
//
//   * Each direction owns a window of the rule array: ingress is slots
//     [0, MAX_SG_RULES_PER_DIR), egress is the rest. A scan reads only
//     its own window, so one direction can never take slots away from
//     the other.
//
//   * Egress default differs from ingress: when a SG has no egress rules
//     (sg_meta.has_egress_rules == 0) it defaults to ALLOW for that
//     direction. Ingress always denies-by-default. The "any rule observed"
//     boolean from the evaluator lets callers distinguish the two.
//
// The evaluator writes no conntrack state; policy_ct_map is filled by
// apply_policy in policy.h, so the policy decision and the conntrack
// key live in one place.

#ifndef JUNEAU_BPF_SG_H
#define JUNEAU_BPF_SG_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "policy_match.h"

// __juneau_bpf_subprog mirrors the macro in trace.h. Defined locally
// here so sg.h does not have to include trace.h (which would pull
// the trace ringbuf and event maps into every TU that needs SG
// helpers).
#ifndef __juneau_bpf_subprog
#define __juneau_bpf_subprog __attribute__((noinline)) __attribute__((used))
#endif

// _sg_rule_btf_anchor forces clang's BTF generator to emit a full
// STRUCT entry for `struct sg_rule` rather than only the FWD
// declaration that surfaces when the noinline `sg_eval_one_sg`
// subprogram below is the only place that references it. Without
// this, bpf2go fails to load the resulting ELF with
// "type *btf.Fwd: type is unsized" while parsing sg_rules_inner's
// value type. The variable itself is never read at runtime.
const struct sg_rule _sg_rule_btf_anchor;

#ifndef SG_VERDICT_PASS
// SG_VERDICT_PASS is the evaluator's "no SG attached / nothing to do"
// signal. Distinct from ALLOW so callers can decide whether to install
// a CT entry.
#define SG_VERDICT_PASS 2
#endif

// sg_membership_lookup is a thin wrapper used by the rule scanner to
// resolve a peer's SG set. Returns NULL when the peer is not a Juneau
// Pod (e.g. ClusterIP, host IP, external).
static __always_inline struct sg_membership_val *sg_membership_lookup(__u32 vpc_id, __be32 ip) {
  struct sg_membership_key k = {
      .vpc_id = vpc_id,
      .ipv4 = ip,
  };
  return bpf_map_lookup_elem(&sg_membership_map, &k);
}

// sg_peer_sg_set_contains asks "does the peer's SG list include this
// peer_sg_id". peer_sgs may be NULL (peer is not a Pod); in that case
// the answer is no.
static __always_inline int sg_peer_sg_set_contains(const struct sg_membership_val *peer_sgs, __u32 peer_sg_id) {
  if (peer_sgs == NULL)
    return 0;
  __u8 cnt = peer_sgs->count;
  if (cnt > MAX_SGS_PER_NIC)
    cnt = MAX_SGS_PER_NIC;
#pragma unroll
  for (int i = 0; i < MAX_SGS_PER_NIC; i++) {
    if (i >= cnt)
      break;
    if (peer_sgs->sgs[i] == peer_sg_id)
      return 1;
  }
  return 0;
}

// sg_eval_one_sg_args bundles the scalar inputs that sg_eval_one_sg
// needs. BPF subprograms have a 5-register argument limit; bundling
// keeps the call signature within that ceiling once the function is
// promoted out of __always_inline.
//
// base is the first slot of the direction's window. The caller works
// it out because it must be 64 bits wide and 8-byte aligned to stay
// useful: a narrower field is a sub-8-byte stack write, which the
// verifier reads back as STACK_MISC instead of the constant that was
// stored. The scan index would then be an unknown scalar, the loop
// body would be explored once per possible window, and pod_egress
// went from 662,664 to 884,347 processed instructions when we
// computed base here from the __u8 direction field instead.
struct sg_eval_one_sg_args {
  __u64 base;
  __u32 sg_id;
  __be32 peer_ip;
  __u32 max_rules;
  __u16 dport;
  __u8  proto;
};

// sg_eval_one_sg scans the rules of a single SG for the requested
// direction. Returns 1 (ALLOW) on match, 0 otherwise.
//
// max_rules is the rule count this SG holds in the requested
// direction (from sg_meta_val). Capping the loop bound at the live
// rule count instead of MAX_SG_RULES_PER_DIR keeps the verifier
// instruction budget proportional to real ruleset size on the hot
// path; we still bound by MAX_SG_RULES_PER_DIR so the verifier sees a
// fixed maximum.
//
// Marked as a BPF-to-BPF subprogram (noinline): the rule-scan loop
// has a 6-way branch per iteration over MAX_SG_RULES_PER_DIR=8 rules,
// which the verifier explores combinatorially when inlined into
// apply_policy. Promoting the scan to
// a subprogram lets the verifier explore the loop body once per
// program (not per call site × per outer SG iteration), keeping the
// 1M-insn budget intact once trace.h instrumentation expands the
// surrounding host program.
static __juneau_bpf_subprog int
sg_eval_one_sg(const struct sg_eval_one_sg_args *a,
               const struct sg_membership_val *peer_sgs) {
  __u32 sg_id = a->sg_id;
  void *inner = bpf_map_lookup_elem(&sg_rule_table, &sg_id);
  if (!inner)
    return 0;

  __u32 max_rules = a->max_rules;
  if (max_rules > MAX_SG_RULES_PER_DIR)
    max_rules = MAX_SG_RULES_PER_DIR;

  // 64-bit counter for the same reason as acl_evaluate: a 32-bit
  // spill across the helper call degrades to STACK_MISC on kernels
  // without precise sub-8-byte spill tracking, and the verifier then
  // rejects the loop as "infinite loop detected".
  for (__u64 i = 0; i < MAX_SG_RULES_PER_DIR; i++) {
    if (i >= max_rules)
      break;
    __u32 idx = a->base + i;
    struct sg_rule *r = bpf_map_lookup_elem(inner, &idx);
    if (!r)
      break;
    if (!policy_proto_matches(r->proto, a->proto))
      continue;
    if (!policy_port_matches(r->port_lo, r->port_hi, a->dport))
      continue;

    if (r->peer_kind == SG_PEER_KIND_CIDR) {
      if (!policy_cidr_matches(r->peer_v4, r->peer_prefixlen, a->peer_ip))
        continue;
    } else if (r->peer_kind == SG_PEER_KIND_SG) {
      // peer_v4 holds peer_sg_id in host byte order (no IP semantics).
      __u32 peer_sg_id = r->peer_v4;
      if (!sg_peer_sg_set_contains(peer_sgs, peer_sg_id))
        continue;
    } else {
      continue;
    }

    if (r->verdict == SG_VERDICT_ALLOW)
      return 1;
  }
  return 0;
}

// sg_eval_args bundles sg_eval's scalar inputs. Bundling keeps the
// noinline call signature within BPF's 5-register argument limit
// (counting the two struct pointers).
struct sg_eval_args {
  __be32 peer_ip;
  __u16 dport;
  __u8 direction;
  __u8 proto;
};

// sg_eval evaluates self's full SG set for the chosen direction.
// Returns SG_VERDICT_ALLOW, SG_VERDICT_DENY or SG_VERDICT_PASS.
//
//   PASS  : self has no SG attached → no enforcement (legacy behaviour).
//   ALLOW : at least one rule matched.
//   DENY  : direction has rules across self's SGs but none matched.
//
// For egress, when *all* of self's SGs have has_egress_rules == 0 we
// keep the AWS default of "allow all egress" by returning PASS; CT is
// not installed in that case so subsequent flows still see the same
// default behaviour.
//
// Marked as a BPF-to-BPF subprogram (noinline) so its per-iteration
// scratch (sg_meta lookups, the `sg_eval_one_sg_args` struct passed
// to the inner subprogram) lives in its own frame rather than
// inflating apply_policy_X's stack past the 512-byte combined
// call-chain ceiling.
static __juneau_bpf_subprog int sg_eval(const struct sg_membership_val *self,
                                        const struct sg_membership_val *peer_sgs,
                                        const struct sg_eval_args *a) {
  __u8 direction = a->direction;
  __u8 proto = a->proto;
  __u16 dport = a->dport;
  __be32 peer_ip = a->peer_ip;
  // Pod has no SGs attached at all → no enforcement; data plane skips
  // CT installation so we don't pay for state we'd never consult.
  if (self == NULL || self->count == 0)
    return SG_VERDICT_PASS;

  __u8 cnt = self->count;
  if (cnt > MAX_SGS_PER_NIC)
    cnt = MAX_SGS_PER_NIC;


  // Whether ANY of self's SGs declares rules in this direction. If
  // none do, the direction has a default verdict:
  //   * Egress: ALLOW (matches AWS — egress is implicitly allowed when
  //     no SG defines egress rules).
  //   * Ingress: DENY (AWS default for SG-attached interfaces).
  // The "ALLOW because no rules" case still triggers CT installation
  // so the reverse-direction packets find a policy_ct_map entry rather
  // than re-evaluating against an empty ingress ruleset (which would
  // deny).
  bool any_rules = false;

#pragma unroll
  for (int i = 0; i < MAX_SGS_PER_NIC; i++) {
    if (i >= cnt)
      break;
    __u32 sg_id = self->sgs[i];
    struct sg_meta_val *meta = bpf_map_lookup_elem(&sg_meta_map, &sg_id);
    if (!meta)
      continue;

    __u64 base;
    __u32 dir_count;
    bool declared;
    if (direction == SG_DIR_EGRESS) {
      declared = meta->has_egress_rules != 0;
      dir_count = meta->egress_count;
      base = MAX_SG_RULES_PER_DIR;
    } else {
      // Ingress has no has_ingress_rules flag in sg_meta_val and needs
      // none: an SG with no ingress rules already defaults to DENY,
      // which is the verdict an empty ingress list asks for.
      dir_count = meta->ingress_count;
      declared = dir_count > 0;
      base = 0;
    }
    // An SG that does not declare this direction keeps the AWS
    // default; leaving any_rules alone lets another attached SG still
    // own the direction.
    if (!declared)
      continue;
    // Declaring the direction is enough to enforce it, even with zero
    // rules: an empty rule list means deny-all, and a direction that
    // overflows its window is installed with zero rules on purpose.
    // Setting any_rules only after the count check below would send
    // both cases back to the default-allow egress path.
    any_rules = true;
    if (dir_count == 0)
      continue;

    struct sg_eval_one_sg_args one_args = {
        .base = base,
        .sg_id = sg_id,
        .peer_ip = peer_ip,
        .max_rules = dir_count,
        .dport = dport,
        .proto = proto,
    };
    if (sg_eval_one_sg(&one_args, peer_sgs))
      return SG_VERDICT_ALLOW;
  }

  if (!any_rules) {
    // Direction defaults when no attached SG declares rules in this
    // direction:
    //   * Egress: AWS default-allow → PASS.
    //   * Ingress: AWS default-deny.
    // PASS is not "skip the conntrack entry": apply_policy installs one
    // whenever a SG is attached at all, because this hook still has to
    // let the reply back in past its own default-deny ingress.
    if (direction == SG_DIR_EGRESS)
      return SG_VERDICT_PASS;
    return SG_VERDICT_DENY;
  }

  return SG_VERDICT_DENY;
}

#endif // JUNEAU_BPF_SG_H
