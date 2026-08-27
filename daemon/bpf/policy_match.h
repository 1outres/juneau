// Generic L3/L4 matching primitives shared between SecurityGroup and
// NetworkACL rule evaluation.
//
// These helpers are pure: they do not touch any BPF map. Callers parse a
// rule and a packet on their side and supply the relevant fields. Keeping
// the matching logic in one place ensures both policy layers (SG, ACL,
// any future kind) agree on edge cases like "prefixlen=0 matches all" or
// "(0, 0xFFFF) is the wildcard port range".

#ifndef JUNEAU_BPF_POLICY_MATCH_H
#define JUNEAU_BPF_POLICY_MATCH_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// POLICY_PROTO_ANY matches any IP protocol. A rule's proto field is 16
// bits wide so the wildcard can live outside the 0..255 range that real
// IP protocol numbers occupy. That is why the sentinel is 0xFFFF and
// not 0: protocol number 0 is HOPOPT, and a rule must be able to name
// it like any other protocol.
#define POLICY_PROTO_ANY 0xFFFF

// POLICY_PORT_ANY_LO / POLICY_PORT_ANY_HI is the inclusive range that
// matches every L4 destination port. Stored in the rule when the user
// did not constrain ports (e.g. protocol=icmp, or protocol=tcp without
// a ports clause).
#define POLICY_PORT_ANY_LO 0
#define POLICY_PORT_ANY_HI 0xFFFF

// policy_proto_matches returns 1 when a rule's protocol field admits a
// packet's IP protocol number, 0 otherwise.
static __always_inline int policy_proto_matches(__u16 rule_proto, __u8 pkt_proto) {
  if (rule_proto == POLICY_PROTO_ANY)
    return 1;
  return rule_proto == pkt_proto;
}

// policy_port_matches returns 1 when a packet port (host byte order) is
// inside the inclusive [lo, hi] range. The wildcard sentinel
// (POLICY_PORT_ANY_LO, POLICY_PORT_ANY_HI) shortcircuits.
static __always_inline int policy_port_matches(__u16 lo, __u16 hi, __u16 port) {
  if (lo == POLICY_PORT_ANY_LO && hi == POLICY_PORT_ANY_HI)
    return 1;
  return port >= lo && port <= hi;
}

// policy_cidr_matches takes both addresses in network byte order and a
// prefix length in host order. A prefixlen of 0 matches every address;
// values >32 are rejected as malformed and never match.
static __always_inline int policy_cidr_matches(__be32 base_be, __u8 prefixlen, __be32 addr_be) {
  if (prefixlen == 0)
    return 1;
  if (prefixlen > 32)
    return 0;
  __u32 mask = bpf_htonl((__u32)0xFFFFFFFF << (32 - prefixlen));
  return (base_be & mask) == (addr_be & mask);
}

#endif // JUNEAU_BPF_POLICY_MATCH_H
