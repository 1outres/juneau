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
//     verdict is DENY.
//
//   * Egress default differs from ingress: when a SG has no egress rules
//     (sg_meta.has_egress_rules == 0) it defaults to ALLOW for that
//     direction. Ingress always denies-by-default. The "any rule observed"
//     boolean from the evaluator lets callers distinguish the two.
//
// The evaluator does not write to ct_map; CT installation is the
// responsibility of the calling program (pod_egress / pod_ingress) so
// the policy decision and the conntrack key live in one place.

#ifndef JUNEAU_BPF_SG_H
#define JUNEAU_BPF_SG_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

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

static __always_inline int sg_proto_matches(__u8 rule_proto, __u8 pkt_proto) {
  if (rule_proto == SG_PROTO_ANY)
    return 1;
  return rule_proto == pkt_proto;
}

static __always_inline int sg_port_matches(__u16 lo, __u16 hi, __u16 dport) {
  if (lo == 0 && hi == 0xFFFF)
    return 1;
  return dport >= lo && dport <= hi;
}

// sg_cidr_matches takes both addresses in network byte order and a
// prefix length in host order. A prefixlen of 0 matches every address.
static __always_inline int sg_cidr_matches(__be32 base_be, __u8 prefixlen, __be32 addr_be) {
  if (prefixlen == 0)
    return 1;
  if (prefixlen > 32)
    return 0;
  __u32 mask = bpf_htonl((__u32)0xFFFFFFFF << (32 - prefixlen));
  return (base_be & mask) == (addr_be & mask);
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

// sg_eval_one_sg scans the rules of a single SG for the requested
// direction. Returns 1 (ALLOW) on match, 0 otherwise.
//
// max_rules is the actual rule count for this SG (from sg_meta_val).
// Capping the loop bound at the live rule count instead of
// MAX_RULES_PER_SG keeps the verifier instruction budget proportional
// to real ruleset size on the hot path; we still bound by
// MAX_RULES_PER_SG so the verifier sees a fixed maximum.
static __always_inline int sg_eval_one_sg(__u32 sg_id, __u8 direction,
                                          __u8 proto, __u16 dport,
                                          __be32 peer_ip,
                                          const struct sg_membership_val *peer_sgs,
                                          __u32 max_rules) {
  void *inner = bpf_map_lookup_elem(&sg_rule_table, &sg_id);
  if (!inner)
    return 0;

  if (max_rules > MAX_RULES_PER_SG)
    max_rules = MAX_RULES_PER_SG;

  for (__u32 i = 0; i < MAX_RULES_PER_SG; i++) {
    if (i >= max_rules)
      break;
    struct sg_rule *r = bpf_map_lookup_elem(inner, &i);
    if (!r)
      break;
    if (r->direction != direction)
      continue;
    if (!sg_proto_matches(r->proto, proto))
      continue;
    if (!sg_port_matches(r->port_lo, r->port_hi, dport))
      continue;

    if (r->peer_kind == SG_PEER_KIND_CIDR) {
      if (!sg_cidr_matches(r->peer_v4, r->peer_prefixlen, peer_ip))
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
static __always_inline int sg_eval(const struct sg_membership_val *self,
                                   __u8 direction,
                                   __u8 proto, __u16 dport,
                                   __be32 peer_ip,
                                   const struct sg_membership_val *peer_sgs) {
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
  // so the reverse-direction packets find a SG_PASS entry rather than
  // re-evaluating against an empty ingress ruleset (which would deny).
  bool any_rules = false;

#pragma unroll
  for (int i = 0; i < MAX_SGS_PER_NIC; i++) {
    if (i >= cnt)
      break;
    __u32 sg_id = self->sgs[i];
    struct sg_meta_val *meta = bpf_map_lookup_elem(&sg_meta_map, &sg_id);
    if (!meta)
      continue;

    __u32 dir_count;
    if (direction == SG_DIR_EGRESS) {
      if (!meta->has_egress_rules) {
        // SG keeps the AWS default-allow egress behaviour. Do NOT set
        // any_rules; another attached SG may still own egress rules.
        continue;
      }
      dir_count = meta->egress_count;
      if (dir_count == 0)
        continue;
    } else {
      dir_count = meta->ingress_count;
      if (dir_count == 0)
        continue;
    }
    // The direction-specific count overcounts when both directions
    // share the rule space (which they do: rules are stored
    // interleaved). We bound the scan by ingress+egress to be safe.
    __u32 scan_count = meta->ingress_count + meta->egress_count;
    any_rules = true;

    if (sg_eval_one_sg(sg_id, direction, proto, dport, peer_ip, peer_sgs, scan_count))
      return SG_VERDICT_ALLOW;
  }

  if (!any_rules) {
    // Direction defaults when no attached SG declares rules in this
    // direction:
    //   * Egress: AWS default-allow → PASS (no CT install needed; the
    //     receiver-side ingress eval takes responsibility for the
    //     forward leg, and the receiver-side ALLOW will install CT
    //     covering both directions).
    //   * Ingress: AWS default-deny.
    if (direction == SG_DIR_EGRESS)
      return SG_VERDICT_PASS;
    return SG_VERDICT_DENY;
  }

  return SG_VERDICT_DENY;
}

#endif // JUNEAU_BPF_SG_H
