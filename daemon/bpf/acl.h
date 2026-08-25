// NetworkACL evaluation helpers.
//
// ACL eval semantics:
//
//   * The acl_id comes from subnet_map.acl_id and selects the
//     per-Subnet ruleset. acl_id == 0 means "no ACL attached"; the
//     evaluator returns ACL_VERDICT_PASS without touching any map.
//
//   * The daemon-side writer pre-sorts the inner array by (direction,
//     priority asc) so the kernel scanner walks slots front-to-back
//     and short-circuits on the first matching rule.
//
//   * has_ingress_rules / has_egress_rules in acl_meta_val choose
//     between default-allow (no rules to match: PASS, no enforcement)
//     and the rule-list mode (no rule matched: terminal DENY).
//
// The evaluator does NOT touch any conntrack table; CT installation is
// the responsibility of apply_policy in policy.h, which combines the
// ACL and SG verdicts into one policy_ct_map entry.

#ifndef JUNEAU_BPF_ACL_H
#define JUNEAU_BPF_ACL_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "policy_match.h"

// __juneau_bpf_subprog mirrors the macro in trace.h. Defined locally
// here so acl.h does not have to include trace.h.
#ifndef __juneau_bpf_subprog
#define __juneau_bpf_subprog __attribute__((noinline)) __attribute__((used))
#endif

// _acl_rule_btf_anchor forces clang to emit a full STRUCT entry for
// `struct acl_rule` rather than the FWD declaration that surfaces
// when the noinline `acl_evaluate` subprogram below is the only
// place that references it. Mirrors _sg_rule_btf_anchor in sg.h.
const struct acl_rule _acl_rule_btf_anchor;

// acl_evaluate scans the inner array for a single ACL against parsed
// packet metadata, returning one of:
//
//   ACL_VERDICT_ALLOW : a rule with verdict=allow matched
//   ACL_VERDICT_DENY  : a rule with verdict=deny matched, OR no rule
//                       matched but the direction is in deny-list
//                       mode (has_*_rules == 1)
//   ACL_VERDICT_PASS  : acl_id == 0 (no ACL attached) OR direction is
//                       in default-allow mode (has_*_rules == 0)
//
// peer_ip is the user-visible 5-tuple peer for this direction:
// daddr on egress, saddr on ingress. The caller resolves that.
//
// Marked as a BPF-to-BPF subprogram (noinline). Inlining
// acl_evaluate into apply_policy_X (now itself a subprogram) made
// the verifier lose precision on the loop counter `i` across the
// per-iteration bpf_map_lookup_elem call, tripping the
// "infinite loop detected" check. Promoting acl_evaluate to its
// own subprogram restores per-iteration tracking.
static __juneau_bpf_subprog int acl_evaluate(__u32 acl_id, __u8 direction,
                                             __u8 proto, __u16 dport,
                                             __be32 peer_ip) {
  if (acl_id == 0)
    return ACL_VERDICT_PASS;

  struct acl_meta_val *meta = bpf_map_lookup_elem(&acl_meta_map, &acl_id);
  if (!meta)
    return ACL_VERDICT_PASS;

  __u8 has_rules = (direction == ACL_DIR_INGRESS) ? meta->has_ingress_rules
                                                  : meta->has_egress_rules;
  if (!has_rules)
    return ACL_VERDICT_PASS;

  void *inner = bpf_map_lookup_elem(&acl_rule_table, &acl_id);
  if (!inner) {
    // Direction wants enforcement but the rule table is missing.
    // Fail closed: a missing inner is "rules not installed yet" and
    // we'd rather drop than admit unconfigured traffic.
    return ACL_VERDICT_DENY;
  }

  // The direction-specific count overcounts when both directions
  // share the rule space (rules are stored interleaved post-sort).
  // Bound by ingress+egress so the verifier sees a fixed maximum.
  __u32 scan_count = meta->ingress_count + meta->egress_count;
  if (scan_count > MAX_RULES_PER_ACL)
    scan_count = MAX_RULES_PER_ACL;

  // The counter is deliberately 64-bit: clang spills it across the
  // per-iteration helper call, and a 32-bit spill of a 64-bit-computed
  // increment degrades to STACK_MISC on kernels that cannot track
  // sub-8-byte spills precisely. The verifier then sees an identical
  // state on every back edge and rejects the program with
  // "infinite loop detected". An 8-byte slot keeps the bounds exact.
  for (__u64 i = 0; i < MAX_RULES_PER_ACL; i++) {
    if (i >= scan_count)
      break;
    __u32 idx = i;
    struct acl_rule *r = bpf_map_lookup_elem(inner, &idx);
    if (!r)
      break;
    if (r->direction != direction)
      continue;
    if (!policy_proto_matches(r->proto, proto))
      continue;
    if (!policy_port_matches(r->port_lo, r->port_hi, dport))
      continue;
    if (!policy_cidr_matches(r->peer_v4, r->prefixlen, peer_ip))
      continue;
    // First match wins because daemon-side ExpandNetworkACL sorted
    // by (direction, priority asc).
    if (r->verdict == ACL_VERDICT_ALLOW)
      return ACL_VERDICT_ALLOW;
    return ACL_VERDICT_DENY;
  }

  // No rule matched. Direction is in rule-list mode (has_rules
  // already gated us above) so we fall to terminal deny.
  return ACL_VERDICT_DENY;
}

#endif // JUNEAU_BPF_ACL_H
