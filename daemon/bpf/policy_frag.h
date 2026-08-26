// Fragment memory for the policy stage. See policy_frag_map in maps.h
// for why the table is keyed the way it is.
//
// Only the first fragment of an IP datagram carries the TCP or UDP
// header, so only it can be matched against rules that name a port.
// The first fragment leaves its ports here and every later fragment
// picks them up, which is what lets the policy stage judge a whole
// datagram instead of only its head.
#ifndef JUNEAU_BPF_POLICY_FRAG_H
#define JUNEAU_BPF_POLICY_FRAG_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "nat.h"

// __juneau_bpf_subprog mirrors the macro in trace.h. Defined locally
// here so policy_frag.h does not have to include trace.h.
#ifndef __juneau_bpf_subprog
#define __juneau_bpf_subprog __attribute__((noinline)) __attribute__((used))
#endif

static __always_inline struct policy_frag_key
policy_frag_build_key(__u32 vpc_id, const struct iphdr *iph) {
  struct policy_frag_key key = {
      .scope = vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .ip_id = iph->id,
      .proto = iph->protocol,
  };
  return key;
}

// policy_frag_is_later reports whether the packet starts mid-datagram,
// which is where the L4 header is not.
static __always_inline int policy_frag_is_later(const struct iphdr *iph) {
  return (bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0;
}

// policy_frag_has_more reports whether more fragments of this datagram
// follow, which is what makes the ports worth remembering.
static __always_inline int policy_frag_has_more(const struct iphdr *iph) {
  return (bpf_ntohs(iph->frag_off) & IP_MF) != 0;
}

// policy_frag_resolve_ports reports the ports of the datagram this
// packet belongs to: read from the header when the packet carries one,
// recalled from policy_frag_map when it does not. Returns -1 when
// neither works, which leaves the caller with no tuple to judge.
//
// A BPF-to-BPF subprogram on purpose. The three fragment cases fan out
// into branches, and inlined they made the verifier walk the whole
// rest of tc_pod_egress once per branch: the program went past the
// 1,000,000 instruction limit and stopped loading. In its own frame it
// has a single exit and the caller stays straight-line. The packet
// pointers are re-derived from skb here rather than passed in, which
// is what nat_rewrite_l4_port does for the same reason.
static __juneau_bpf_subprog int policy_frag_resolve_ports(struct __sk_buff *skb,
                                                          __u32 vpc_id,
                                                          __be16 *sport,
                                                          __be16 *dport) {
  struct iphdr *iph = nat_load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = nat_skb_data_end(skb);
  struct policy_frag_key key = policy_frag_build_key(vpc_id, iph);

  if (policy_frag_is_later(iph)) {
    struct policy_frag_val *seen = bpf_map_lookup_elem(&policy_frag_map, &key);
    if (!seen)
      return -1;
    seen->last_seen_ns = bpf_ktime_get_ns();
    *sport = seen->sport;
    *dport = seen->dport;
    return 0;
  }

  if (nat_read_l4_ports(iph, data_end, sport, dport) < 0)
    return -1;

  if (policy_frag_has_more(iph)) {
    struct policy_frag_val val = {
        .sport = *sport,
        .dport = *dport,
        .last_seen_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&policy_frag_map, &key, &val, BPF_ANY);
  }
  return 0;
}

#endif // JUNEAU_BPF_POLICY_FRAG_H
