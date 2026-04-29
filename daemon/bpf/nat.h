// Shared NAT helpers used by pod_egress and vxlan_ingress. The functions
// here perform the L3 / L4 rewrites and reload skb pointers between
// helper calls so the BPF verifier can prove pointer validity.
#ifndef JUNEAU_BPF_NAT_H
#define JUNEAU_BPF_NAT_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

#ifndef NAT_TC_ACT_OK
#define NAT_TC_ACT_OK 0
#endif

#ifndef NAT_TC_ACT_SHOT
#define NAT_TC_ACT_SHOT 2
#endif

#ifndef NAT_ETH_ALEN
#define NAT_ETH_ALEN 6
#endif

// skb_data / skb_data_end read the packet bounds via inline asm with a
// direct offset load. LLVM otherwise commons up multiple skb->data reads
// by hoisting "ctx + 76" / "ctx + 80" address computations and then
// dereferencing them — a pattern the BPF verifier rejects with
// "dereference of modified ctx ptr".
static __always_inline void *nat_skb_data(const struct __sk_buff *skb) {
  void *p;
  __asm__ volatile("%[p] = *(u32 *)(%[skb] + %[off])"
                   : [p] "=r"(p)
                   : [skb] "r"(skb),
                     [off] "i"(__builtin_offsetof(struct __sk_buff, data)));
  return p;
}

static __always_inline void *nat_skb_data_end(const struct __sk_buff *skb) {
  void *p;
  __asm__ volatile("%[p] = *(u32 *)(%[skb] + %[off])"
                   : [p] "=r"(p)
                   : [skb] "r"(skb),
                     [off] "i"(__builtin_offsetof(struct __sk_buff, data_end)));
  return p;
}

// nat_load_iph re-derives the IPv4 header pointer from skb->data each
// time. Returns NULL if the packet is too short.
static __always_inline struct iphdr *nat_load_iph(struct __sk_buff *skb) {
  void *data = nat_skb_data(skb);
  void *data_end = nat_skb_data_end(skb);
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return NULL;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return NULL;
  return iph;
}

static __always_inline int nat_read_l4_ports(struct iphdr *iph, void *data_end,
                                             __be16 *sport, __be16 *dport) {
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return -1;

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)iph + ihl * 4;
    if ((void *)(tcp + 1) > data_end)
      return -1;
    *sport = tcp->source;
    *dport = tcp->dest;
    return 0;
  }
  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)iph + ihl * 4;
    if ((void *)(udp + 1) > data_end)
      return -1;
    *sport = udp->source;
    *dport = udp->dest;
    return 0;
  }
  return -1;
}

// nat_update_l4_csum updates the L4 checksum to reflect an L3 (IP)
// address change. Pseudo-header fields (source/dest IP) feed into the L4
// checksum, so any L3 address rewrite must update the L4 csum too.
static __always_inline int nat_update_l4_csum(struct __sk_buff *skb,
                                              struct iphdr *iph,
                                              void *data_end, __be32 old_addr,
                                              __be32 new_addr) {
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return NAT_TC_ACT_SHOT;

  if ((bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0)
    return NAT_TC_ACT_OK;

  __u32 l4_off = sizeof(struct ethhdr) + ihl * 4;

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)iph + ihl * 4;
    if ((void *)(tcp + 1) > data_end)
      return NAT_TC_ACT_SHOT;
    if (bpf_l4_csum_replace(skb,
                            l4_off + __builtin_offsetof(struct tcphdr, check),
                            old_addr, new_addr,
                            BPF_F_PSEUDO_HDR | sizeof(new_addr)) < 0)
      return NAT_TC_ACT_SHOT;
    return NAT_TC_ACT_OK;
  }

  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)iph + ihl * 4;
    if ((void *)(udp + 1) > data_end)
      return NAT_TC_ACT_SHOT;
    if (udp->check == 0)
      return NAT_TC_ACT_OK;
    if (bpf_l4_csum_replace(skb,
                            l4_off + __builtin_offsetof(struct udphdr, check),
                            old_addr, new_addr,
                            BPF_F_PSEUDO_HDR | sizeof(new_addr)) < 0)
      return NAT_TC_ACT_SHOT;
  }

  return NAT_TC_ACT_OK;
}

// nat_rewrite_ipv4_addr rewrites either the source or destination IPv4
// address and refreshes the L3 + L4 checksums. Reloads iph between
// helper calls.
static __always_inline int nat_rewrite_ipv4_addr(struct __sk_buff *skb,
                                                 bool is_source,
                                                 __be32 new_addr) {
  struct iphdr *iph = nat_load_iph(skb);
  if (!iph)
    return -1;

  __be32 old_addr = is_source ? iph->saddr : iph->daddr;
  if (old_addr == new_addr)
    return 0;

  __u32 addr_off =
      sizeof(struct ethhdr) +
      (is_source ? __builtin_offsetof(struct iphdr, saddr)
                 : __builtin_offsetof(struct iphdr, daddr));

  if (bpf_l3_csum_replace(skb,
                          sizeof(struct ethhdr) +
                              __builtin_offsetof(struct iphdr, check),
                          old_addr, new_addr, sizeof(new_addr)) < 0)
    return -1;

  iph = nat_load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = nat_skb_data_end(skb);
  if (nat_update_l4_csum(skb, iph, data_end, old_addr, new_addr) !=
      NAT_TC_ACT_OK)
    return -1;

  if (bpf_skb_store_bytes(skb, addr_off, &new_addr, sizeof(new_addr), 0) < 0)
    return -1;
  return 0;
}

static __always_inline int nat_rewrite_l4_port(struct __sk_buff *skb,
                                               bool is_source,
                                               __be16 new_port) {
  struct iphdr *iph = nat_load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = nat_skb_data_end(skb);

  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return -1;
  __u32 l4_off = sizeof(struct ethhdr) + ihl * 4;

  __be16 old_port;
  __u32 csum_off;
  __u32 port_off;

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)iph + ihl * 4;
    if ((void *)(tcp + 1) > data_end)
      return -1;
    old_port = is_source ? tcp->source : tcp->dest;
    if (old_port == new_port)
      return 0;
    csum_off = l4_off + __builtin_offsetof(struct tcphdr, check);
    port_off = l4_off + (is_source
                            ? __builtin_offsetof(struct tcphdr, source)
                            : __builtin_offsetof(struct tcphdr, dest));
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)iph + ihl * 4;
    if ((void *)(udp + 1) > data_end)
      return -1;
    old_port = is_source ? udp->source : udp->dest;
    if (old_port == new_port)
      return 0;
    csum_off = l4_off + __builtin_offsetof(struct udphdr, check);
    port_off = l4_off + (is_source
                            ? __builtin_offsetof(struct udphdr, source)
                            : __builtin_offsetof(struct udphdr, dest));
    if (udp->check == 0)
      csum_off = 0;
  } else {
    return -1;
  }

  if (csum_off != 0) {
    if (bpf_l4_csum_replace(skb, csum_off, old_port, new_port,
                            sizeof(new_port)) < 0)
      return -1;
  }

  if (bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port), 0) < 0)
    return -1;
  return 0;
}

// nat_apply_napt_in_rewrite performs the reverse rewrite for both
// CT_ACTION_NAPT_IN and CT_ACTION_SVC_NAPT_IN. The rewrite is structurally
// the same: dst is always rewritten back to the original caller; src is
// only rewritten for SVC_NAPT_IN (NAPT_IN sets new_saddr/new_sport=0,
// which the rewrite skips so caller-visible src stays intact).
//
// The function is a *pure rewriter*: it does not touch L2 nor decide
// where to forward the packet next. Callers issue forward_l2 (or any
// other dispatch) themselves, which is what lets the same helper run at
// both eth0 ingress (node_ingress) and juneau_node ingress (pod_egress).
static __always_inline int nat_apply_napt_in_rewrite(struct __sk_buff *skb,
                                                     struct ct_val *cv) {
  if (cv->action == CT_ACTION_SVC_NAPT_IN) {
    if (nat_rewrite_ipv4_addr(skb, /*is_source=*/true, cv->new_saddr) < 0)
      return -1;
    if (nat_rewrite_l4_port(skb, /*is_source=*/true, cv->new_sport) < 0)
      return -1;
  }

  if (nat_rewrite_ipv4_addr(skb, /*is_source=*/false, cv->new_daddr) < 0)
    return -1;
  if (nat_rewrite_l4_port(skb, /*is_source=*/false, cv->new_dport) < 0)
    return -1;
  return 0;
}

#endif // JUNEAU_BPF_NAT_H
