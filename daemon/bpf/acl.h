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
// The evaluator does NOT touch ct_map; CT installation is the
// responsibility of apply_policy_egress / apply_policy_ingress in
// policy.h, which combines ACL and SG verdicts into one CT entry.

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

// ACL scan sentinels — kept distinct from ACL_VERDICT_* (0/1/2) so the
// scan loop can tell "no match, keep scanning" (CONTINUE) and "slot
// empty, stop" (STOP) apart from a real ALLOW/DENY verdict.
#define ACL_SCAN_CONTINUE (-1)
#define ACL_SCAN_STOP     (-2)

// acl_scan_rule evaluates the rule at `idx` and returns ACL_VERDICT_ALLOW
// / _DENY on a match, ACL_SCAN_CONTINUE when the rule does not apply, or
// ACL_SCAN_STOP when the slot is empty.
//
// `idx` is taken BY VALUE. That is the crux of the loop's verifiability:
// the caller must never hand bpf_map_lookup_elem the address of its
// induction variable (&i). Address-taking `i` pins it in memory, so the
// verifier reloads it across the per-iteration map lookup and loses the
// "i strictly increases" invariant — at which point a large enough
// tc_pod_egress trips the verifier's "infinite loop detected" check.
// Passing idx by value keeps `i` in a register (precise across the call)
// and lets clang fully unroll the scan.
static __always_inline int acl_scan_rule(void *inner, __u32 idx,
                                         __u8 direction, __u8 proto,
                                         __u16 dport, __be32 peer_ip) {
  struct acl_rule *r = bpf_map_lookup_elem(inner, &idx);
  if (!r)
    return ACL_SCAN_STOP;
  if (r->direction != direction)
    return ACL_SCAN_CONTINUE;
  if (!policy_proto_matches(r->proto, proto))
    return ACL_SCAN_CONTINUE;
  if (!policy_port_matches(r->port_lo, r->port_hi, dport))
    return ACL_SCAN_CONTINUE;
  if (!policy_cidr_matches(r->peer_v4, r->prefixlen, peer_ip))
    return ACL_SCAN_CONTINUE;
  return (r->verdict == ACL_VERDICT_ALLOW) ? ACL_VERDICT_ALLOW
                                           : ACL_VERDICT_DENY;
}

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

  // acl_scan_rule takes the index by value, so `i` is never
  // address-taken and stays register-resident (precise) across the
  // per-iteration map lookup. That preserves the "i strictly increases"
  // invariant the verifier needs to prove termination — which is what
  // regressed to "infinite loop detected" once tc_pod_egress grew. The
  // loop is intentionally left rolled: unrolling inlines the scan body
  // MAX_RULES_PER_ACL times and blows the 512-byte combined stack.
  for (__u32 i = 0; i < MAX_RULES_PER_ACL; i++) {
    if (i >= scan_count)
      break;
    // First match wins because daemon-side ExpandNetworkACL sorted
    // by (direction, priority asc).
    int v = acl_scan_rule(inner, i, direction, proto, dport, peer_ip);
    if (v == ACL_SCAN_STOP)
      break;
    if (v == ACL_SCAN_CONTINUE)
      continue;
    return v; // ACL_VERDICT_ALLOW or ACL_VERDICT_DENY
  }

  // No rule matched. Direction is in rule-list mode (has_rules
  // already gated us above) so we fall to terminal deny.
  return ACL_VERDICT_DENY;
}

#endif // JUNEAU_BPF_ACL_H
