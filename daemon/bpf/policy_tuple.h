// What the policy stage matches on, and how it is recovered when the
// packet alone does not carry it.
//
// The policy stage compares a packet against rules that name a protocol
// and a port range. Reading the protocol always works — it is a field
// of the IPv4 header. Reading the ports does not: only the first
// fragment of a fragmented datagram carries the L4 header, and a
// truncated packet may not carry it at all. Those two cases used to
// leave apply_policy with no ports and no way to say so, and it let the
// packet through.
//
// struct policy_tuple gives the parse a way to say "I could not read
// the ports". The caller settles that case before the evaluation starts
// rather than carrying a flag into it: a flag that stays live across the
// ACL and SG scans makes the verifier walk that whole region twice (see
// the note on the CT epoch in policy.h).
//
// Later fragments are recovered instead of dropped. ipv4_frag_map is
// written when the first fragment goes past this hook, and a later
// fragment of the same datagram reads its ports back out. Cilium's IPv4
// fragment tracking works the same way.

#ifndef JUNEAU_BPF_POLICY_TUPLE_H
#define JUNEAU_BPF_POLICY_TUPLE_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "nat.h"

// __juneau_bpf_subprog mirrors the macro in trace.h. Defined locally
// here so policy_tuple.h does not have to include trace.h.
#ifndef __juneau_bpf_subprog
#define __juneau_bpf_subprog __attribute__((noinline)) __attribute__((used))
#endif

#ifndef IP_MF
#define IP_MF 0x2000
#endif

// POLICY_TUPLE_EXACT: the tuple says what the packet really is. Either
// the ports were read, or the protocol has no ports at all (ICMP, GRE,
// ESP, ...) and sport/dport are 0.
#define POLICY_TUPLE_EXACT    0
// POLICY_TUPLE_DEGRADED: the protocol has ports but this packet does
// not show them. A later fragment, or a packet cut short before its L4
// header.
#define POLICY_TUPLE_DEGRADED 1

// POLICY_FRAG_MAX_AGE_NS bounds how old an ipv4_frag_map entry may be
// and still be believed. Real reassembly finishes in milliseconds, so
// 5 seconds is far more than a live datagram needs. The reason not to
// go higher: the key holds iphdr.id, a 16-bit counter a busy sender
// wraps quickly, so a long-lived entry could hand its ports to an
// unrelated datagram that happened to reuse the id.
#define POLICY_FRAG_MAX_AGE_NS 5000000000ULL

// policy_tuple is what the policy stage matches on.
struct policy_tuple {
  __u16 sport;   // host byte order
  __u16 dport;   // host byte order
  __u8  proto;
  __u8  status;  // POLICY_TUPLE_*
};

// policy_proto_has_ports reports whether a rule that names a port range
// can ever match this protocol. Adding SCTP to the policy stage means
// changing this one predicate and teaching nat_read_l4_ports to read
// its header.
static __always_inline bool policy_proto_has_ports(__u8 proto) {
  return proto == IPPROTO_TCP || proto == IPPROTO_UDP;
}

// policy_frag_is_first reports whether this is the first fragment of a
// fragmented datagram: more fragments follow, and this one starts at
// offset 0, so it is the one carrying the L4 header.
static __always_inline bool policy_frag_is_first(const struct iphdr *iph) {
  __u16 frag_off = bpf_ntohs(iph->frag_off);
  return (frag_off & IP_MF) && (frag_off & IP_OFFSET) == 0;
}

// policy_frag_is_later reports whether this fragment starts past the
// beginning of the datagram. Where the L4 header would be, such a
// packet carries payload.
static __always_inline bool policy_frag_is_later(const struct iphdr *iph) {
  return (bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0;
}

// policy_parse_tuple fills t from the packet. It never fails: a tuple it
// cannot complete comes back POLICY_TUPLE_DEGRADED, and the caller
// decides what that is worth.
static __always_inline void policy_parse_tuple(struct iphdr *iph,
                                               void *data_end,
                                               struct policy_tuple *t) {
  t->sport = 0;
  t->dport = 0;
  t->proto = iph->protocol;
  t->status = POLICY_TUPLE_EXACT;

  if (!policy_proto_has_ports(t->proto))
    return;

  // The offset check comes first because nat_read_l4_ports does not
  // make it: on a later fragment it would read payload bytes and hand
  // them back as ports.
  if (policy_frag_is_later(iph)) {
    t->status = POLICY_TUPLE_DEGRADED;
    return;
  }

  __be16 sport_be, dport_be;
  if (nat_read_l4_ports(iph, data_end, &sport_be, &dport_be) < 0) {
    t->status = POLICY_TUPLE_DEGRADED;
    return;
  }
  t->sport = bpf_ntohs(sport_be);
  t->dport = bpf_ntohs(dport_be);
}

static __always_inline struct ipv4_frag_key
policy_frag_build_key(__u32 vpc_id, const struct iphdr *iph) {
  struct ipv4_frag_key key = {
      .vpc_id = vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .id = iph->id,
      .proto = iph->protocol,
  };
  return key;
}

// policy_frag_record remembers the ports of a first fragment so the
// later fragments of the same datagram can be matched on them.
//
// A protocol without ports has nothing to remember, so it takes no
// slot: its later fragments parse as EXACT and never come looking.
//
// Marked as a BPF-to-BPF subprogram (noinline) so the verifier walks
// the body once instead of at every call site. apply_policy is inlined
// into tc_pod_egress, which is close enough to the 1,000,000
// instruction ceiling that this matters.
static __juneau_bpf_subprog void
policy_frag_record(__u32 vpc_id, const struct iphdr *iph,
                   const struct policy_tuple *t) {
  if (!policy_proto_has_ports(t->proto))
    return;

  struct ipv4_frag_key key = policy_frag_build_key(vpc_id, iph);
  struct ipv4_frag_val val = {
      .sport = bpf_htons(t->sport),
      .dport = bpf_htons(t->dport),
      .last_seen_ns = bpf_ktime_get_ns(),
  };
  bpf_map_update_elem(&ipv4_frag_map, &key, &val, BPF_ANY);
}

// policy_frag_recover fills the ports of a later fragment from the
// first one and puts the tuple back to EXACT. A tuple it cannot fill
// is left DEGRADED for the caller to act on.
//
// noinline for the same reason as policy_frag_record.
static __juneau_bpf_subprog void
policy_frag_recover(__u32 vpc_id, const struct iphdr *iph,
                    struct policy_tuple *t) {
  struct ipv4_frag_key key = policy_frag_build_key(vpc_id, iph);
  struct ipv4_frag_val *val = bpf_map_lookup_elem(&ipv4_frag_map, &key);
  if (!val)
    return;
  if (bpf_ktime_get_ns() - val->last_seen_ns > POLICY_FRAG_MAX_AGE_NS)
    return;

  t->sport = bpf_ntohs(val->sport);
  t->dport = bpf_ntohs(val->dport);
  t->status = POLICY_TUPLE_EXACT;
}

#endif // JUNEAU_BPF_POLICY_TUPLE_H
