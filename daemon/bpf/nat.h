// Shared NAT helpers used by pod_egress and vxlan_ingress. The functions
// here perform the L3 / L4 rewrites and reload skb pointers between
// helper calls so the BPF verifier can prove pointer validity.
#ifndef JUNEAU_BPF_NAT_H
#define JUNEAU_BPF_NAT_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "ct.h"
#include "maps.h"
#include "trace.h"

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

#ifndef NAT_ICMP_ECHOREPLY
#define NAT_ICMP_ECHOREPLY 0
#endif

#ifndef NAT_ICMP_ECHO
#define NAT_ICMP_ECHO 8
#endif

#ifndef NAT_ICMP_DEST_UNREACH
#define NAT_ICMP_DEST_UNREACH 3
#endif

#ifndef NAT_ICMP_SOURCE_QUENCH
#define NAT_ICMP_SOURCE_QUENCH 4
#endif

#ifndef NAT_ICMP_REDIRECT
#define NAT_ICMP_REDIRECT 5
#endif

#ifndef NAT_ICMP_TIME_EXCEEDED
#define NAT_ICMP_TIME_EXCEEDED 11
#endif

#ifndef NAT_ICMP_PARAMETERPROB
#define NAT_ICMP_PARAMETERPROB 12
#endif

// An ICMP error message carries the 8-byte ICMP header, then a copy of
// the IP header of the packet that caused it, then at least the first
// 8 bytes of that packet's L4 header (RFC 792).
#define NAT_ICMP_QUOTE_L4_BYTES 8

// One's-complement checksum arithmetic, mirroring the kernel's
// csum_add / csum_sub / csum_fold. Values stay in network byte order.
static __always_inline __u32 nat_csum_add(__u32 csum, __u32 addend) {
  csum += addend;
  return csum + (csum < addend);
}

static __always_inline __u32 nat_csum_sub(__u32 csum, __u32 addend) {
  return nat_csum_add(csum, ~addend);
}

static __always_inline __u16 nat_csum_fold(__u32 csum) {
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return (__u16)~csum;
}

// nat_csum16_replace returns the checksum a header carries after `old`
// was replaced by `new` inside the checksummed bytes. 16-bit fields are
// passed zero-extended. Callers that rewrite a field which is covered by
// two checksums at once (an inner header quoted by an outer ICMP error)
// need both the old and the new checksum value, and reading the packet
// back between helper calls is not free, so the value is computed here.
static __always_inline __u16 nat_csum16_replace(__u16 old_csum, __u32 old,
                                                __u32 new) {
  return nat_csum_fold(nat_csum_add(nat_csum_sub(~(__u32)old_csum, old), new));
}

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

// nat_read_icmp_echo_id reads the Identifier of an ICMP Echo Request or
// Echo Reply. Every other ICMP type returns -1: error messages carry no
// Identifier of their own, only a copy of the packet that triggered them.
//
// A later fragment holds payload where the ICMP header would be, and
// those bytes can pass the type check by chance. Rejecting them keeps a
// caller from rewriting payload as if it were an Identifier.
static __always_inline int nat_read_icmp_echo_id(struct iphdr *iph,
                                                 void *data_end, __be16 *id) {
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return -1;
  if (iph->protocol != IPPROTO_ICMP)
    return -1;
  if ((bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0)
    return -1;

  struct icmphdr *icmp = (void *)iph + ihl * 4;
  if ((void *)(icmp + 1) > data_end)
    return -1;
  if (icmp->type != NAT_ICMP_ECHO && icmp->type != NAT_ICMP_ECHOREPLY)
    return -1;

  *id = icmp->un.echo.id;
  return 0;
}

// nat_read_napt_ports reads the fields a NAPT conntrack key is built
// from: the TCP/UDP ports, or the ICMP Echo Identifier reported in both
// slots. An Echo Reply repeats the Identifier the Request carried, so
// putting it in both slots keeps the forward and the reverse key
// symmetric the way a swapped port pair does for TCP and UDP.
//
// Kept apart from nat_read_l4_ports because the LoadBalancer and Service
// paths key on real ports and must keep rejecting ICMP.
static __always_inline int nat_read_napt_ports(struct iphdr *iph,
                                               void *data_end, __be16 *sport,
                                               __be16 *dport) {
  if (iph->protocol == IPPROTO_ICMP) {
    __be16 id;
    if (nat_read_icmp_echo_id(iph, data_end, &id) < 0)
      return -1;
    *sport = id;
    *dport = id;
    return 0;
  }
  return nat_read_l4_ports(iph, data_end, sport, dport);
}

// nat_icmp_is_error reports whether an ICMP type carries a copy of the
// packet that triggered it. Only those types hold a tuple a NAT can
// translate.
static __always_inline bool nat_icmp_is_error(__u8 type) {
  return type == NAT_ICMP_DEST_UNREACH || type == NAT_ICMP_SOURCE_QUENCH ||
         type == NAT_ICMP_REDIRECT || type == NAT_ICMP_TIME_EXCEEDED ||
         type == NAT_ICMP_PARAMETERPROB;
}

// nat_icmp_carries_quote reports whether the packet is an ICMP error
// message, so a caller can tell "no copy to repair" apart from "a copy
// that cannot be repaired". Anything else reads as false: another
// protocol, an Echo, a later fragment, a header the frame is too short
// for.
static __always_inline bool nat_icmp_carries_quote(const struct iphdr *iph,
                                                   void *data_end) {
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return false;
  if (iph->protocol != IPPROTO_ICMP)
    return false;
  if ((bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0)
    return false;

  const struct icmphdr *icmp = (void *)iph + ihl * 4;
  if ((void *)(icmp + 1) > data_end)
    return false;
  return nat_icmp_is_error(icmp->type);
}

// nat_icmp_quote describes the packet copied inside an ICMP error
// message. The offsets are counted from the start of the frame, so the
// rewrite can reach every field with bpf_skb_store_bytes after the
// packet pointers are gone.
struct nat_icmp_quote {
  __u32 icmp_csum_off;  // outer ICMP checksum
  __u32 ip_off;         // copied IP header
  __u32 l4_off;         // copied L4 header
  __u32 l4_csum_off;    // copied L4 checksum, 0 when there is none
  __be32 saddr;
  __be32 daddr;
  __be16 sport;  // Echo Identifier when the copied L4 is ICMP
  __be16 dport;
  __sum16 ip_check;
  __sum16 l4_check;
  __u8 proto;
  __u8 l4_has_pseudo;  // copied L4 checksum covers the IP addresses
};

// nat_read_icmp_quote parses the packet an ICMP error message copies.
// The tuple comes back as it sits on the wire; a NAT caller inverts it,
// because the copied packet travelled the other way.
//
// Both the outer and the copied header are rejected when they carry a
// fragment offset. A later fragment holds payload where a header would
// be, and those bytes can pass a type check by chance.
static __always_inline int nat_read_icmp_quote(struct iphdr *iph,
                                               void *data_end,
                                               struct nat_icmp_quote *q) {
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return -1;
  if (iph->protocol != IPPROTO_ICMP)
    return -1;
  if ((bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0)
    return -1;

  struct icmphdr *icmp = (void *)iph + ihl * 4;
  if ((void *)(icmp + 1) > data_end)
    return -1;
  if (!nat_icmp_is_error(icmp->type))
    return -1;

  struct iphdr *inner = (void *)(icmp + 1);
  if ((void *)(inner + 1) > data_end)
    return -1;
  __u32 inner_ihl = inner->ihl;
  if (inner->version != 4 || inner_ihl < 5)
    return -1;
  if ((bpf_ntohs(inner->frag_off) & IP_OFFSET) != 0)
    return -1;

  void *l4 = (void *)inner + inner_ihl * 4;
  if (l4 + NAT_ICMP_QUOTE_L4_BYTES > data_end)
    return -1;

  __u32 icmp_off = sizeof(struct ethhdr) + ihl * 4;
  __u32 ip_off = icmp_off + sizeof(struct icmphdr);
  __u32 l4_off = ip_off + inner_ihl * 4;

  q->icmp_csum_off = icmp_off + __builtin_offsetof(struct icmphdr, checksum);
  q->ip_off = ip_off;
  q->l4_off = l4_off;
  q->l4_csum_off = 0;
  q->l4_check = 0;
  q->l4_has_pseudo = 0;
  q->saddr = inner->saddr;
  q->daddr = inner->daddr;
  q->ip_check = inner->check;
  q->proto = inner->protocol;

  if (inner->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = l4;
    q->sport = tcp->source;
    q->dport = tcp->dest;
    q->l4_has_pseudo = 1;
    // A sender only has to copy 8 bytes, and the TCP checksum sits at
    // byte 16. Repair it only when the copy reaches that far.
    if (l4 + __builtin_offsetof(struct tcphdr, check) + sizeof(__sum16) <=
        data_end) {
      q->l4_csum_off = l4_off + __builtin_offsetof(struct tcphdr, check);
      q->l4_check = tcp->check;
    }
  } else if (inner->protocol == IPPROTO_UDP) {
    struct udphdr *udp = l4;
    q->sport = udp->source;
    q->dport = udp->dest;
    q->l4_has_pseudo = 1;
    // A zero checksum means the sender left it off.
    if (udp->check != 0) {
      q->l4_csum_off = l4_off + __builtin_offsetof(struct udphdr, check);
      q->l4_check = udp->check;
    }
  } else if (inner->protocol == IPPROTO_ICMP) {
    struct icmphdr *ic = l4;
    if (ic->type != NAT_ICMP_ECHO && ic->type != NAT_ICMP_ECHOREPLY)
      return -1;
    q->sport = ic->un.echo.id;
    q->dport = ic->un.echo.id;
    q->l4_csum_off = l4_off + __builtin_offsetof(struct icmphdr, checksum);
    q->l4_check = ic->checksum;
  } else {
    return -1;
  }

  return 0;
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

// nat_rewrite_l4_port rewrites the source or the destination port. For
// ICMP it rewrites the Echo Identifier instead, ignoring is_source: one
// Identifier stands for both ports (see nat_read_napt_ports).
//
// An ICMP checksum has no pseudo-header, so it covers the Identifier but
// not the IP addresses. That is why this function updates it while
// nat_update_l4_csum, which reacts to an address rewrite, leaves it
// alone.
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
  } else if (iph->protocol == IPPROTO_ICMP) {
    if (nat_read_icmp_echo_id(iph, data_end, &old_port) < 0)
      return -1;
    if (old_port == new_port)
      return 0;
    csum_off = l4_off + __builtin_offsetof(struct icmphdr, checksum);
    port_off = l4_off + __builtin_offsetof(struct icmphdr, un.echo.id);
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

// nat_icmp_quote_rewrite repairs the copy of the original packet that an
// ICMP error message carries, so the host that sent that packet still
// recognises it. Two fields move: the address, and the L4 port (the Echo
// Identifier when the copied packet is an ICMP Echo).
//
// outer_is_source picks the direction. On egress (Pod to internet) the
// NAT writes the outer source address, so the copy needs its destination
// and its destination port; on ingress it is the other way round. The
// copied packet travelled the opposite way, so its field is always the
// mirror of the outer one.
//
// The outer header is a plain L3 rewrite and stays with the caller:
// nat_rewrite_ipv4_addr already leaves an ICMP checksum alone, which is
// what an outer address change needs, because an ICMP checksum has no
// pseudo-header. The outer checksum does cover the whole copy, so every
// word this function changes is folded back into it.
//
// The caller passes the parsed copy instead of letting this function
// re-read it: tc_pod_egress is close enough to the verifier's 512-byte
// combined-stack ceiling that a second struct nat_icmp_quote on the
// frame breaks the load. For the same reason nothing here is skipped
// when a field already holds the value it is about to get: writing the
// same bytes back is harmless, and the extra flag would cost a stack
// slot.
static __always_inline int nat_icmp_quote_rewrite(struct __sk_buff *skb,
                                                  const struct nat_icmp_quote *q,
                                                  bool outer_is_source,
                                                  __be32 new_addr,
                                                  __be16 new_port) {
  __be32 old_addr = outer_is_source ? q->daddr : q->saddr;
  __be16 old_port = outer_is_source ? q->dport : q->sport;

  __u32 addr_off =
      q->ip_off + (outer_is_source ? __builtin_offsetof(struct iphdr, daddr)
                                   : __builtin_offsetof(struct iphdr, saddr));
  __u32 port_off = q->l4_off;
  if (q->proto == IPPROTO_ICMP)
    port_off += __builtin_offsetof(struct icmphdr, un.echo.id);
  else if (outer_is_source)
    port_off += (q->proto == IPPROTO_TCP)
                    ? __builtin_offsetof(struct tcphdr, dest)
                    : __builtin_offsetof(struct udphdr, dest);

  __sum16 new_ip_check = nat_csum16_replace(q->ip_check, old_addr, new_addr);

  // A TCP or UDP checksum covers a pseudo-header holding the addresses;
  // an ICMP checksum does not, so only the Identifier moves it.
  __sum16 new_l4_check = q->l4_check;
  if (q->l4_csum_off != 0) {
    if (q->l4_has_pseudo)
      new_l4_check = nat_csum16_replace(new_l4_check, old_addr, new_addr);
    new_l4_check = nat_csum16_replace(new_l4_check, old_port, new_port);
  }

  // One diff for every word that moves inside the copy.
  // bpf_l4_csum_replace takes such a diff when the field-size bits are 0
  // and `from` is 0, so a single call carries all of them. Separate calls
  // would each hold their own before-value live across a helper call, and
  // this program has no stack left for that.
  __u32 diff = nat_csum_add(nat_csum_sub(0, old_addr), new_addr);
  diff = nat_csum_add(nat_csum_sub(diff, q->ip_check), new_ip_check);
  diff = nat_csum_add(nat_csum_sub(diff, old_port), new_port);
  if (q->l4_csum_off != 0)
    diff = nat_csum_add(nat_csum_sub(diff, q->l4_check), new_l4_check);

  if (bpf_l4_csum_replace(skb, q->icmp_csum_off, 0, diff, 0) < 0)
    return -1;

  if (bpf_skb_store_bytes(skb, addr_off, &new_addr, sizeof(new_addr), 0) < 0)
    return -1;
  if (bpf_skb_store_bytes(skb,
                          q->ip_off + __builtin_offsetof(struct iphdr, check),
                          &new_ip_check, sizeof(new_ip_check), 0) < 0)
    return -1;
  if (bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port), 0) < 0)
    return -1;
  if (q->l4_csum_off != 0) {
    if (bpf_skb_store_bytes(skb, q->l4_csum_off, &new_l4_check,
                            sizeof(new_l4_check), 0) < 0)
      return -1;
  }

  return 0;
}

// nat_icmp_quote_fixup_1to1 is the ICMP-error half of a 1:1 NAT
// (ElasticIP). The caller already knows both addresses, because a 1:1
// NAT maps one address onto one address and translates no port. So
// there is no conntrack lookup here, and the port the rewrite writes
// back is the port the copy already carries.
//
// Return values let the caller keep the three cases apart:
//   1  the packet was an ICMP error message and its copy was repaired
//   0  the packet carries no copy, so the caller rewrites only the
//      outer header, exactly as before
//  -1  the packet is an ICMP error message this NAT cannot repair
//
// -1 covers a copy the parser rejects and a copy naming an address other
// than the one being translated. Such a message either belongs to
// another flow or is forged, and delivering it with an address the
// receiver never used would be a lie the receiver cannot detect, so the
// caller drops it.
//
// Each program wraps this in its own noinline subprogram with
// outer_is_source fixed, rather than calling it inline. Two reasons.
// struct nat_icmp_quote is 32 bytes, and both callers sit close enough
// to the verifier's 512-byte combined-stack ceiling that holding it in
// their own frame breaks the load; a subprogram gives it a frame that
// only exists while the fixup runs. And a constant direction lets every
// branch it selects fold away, which is worth 16 bytes of that frame.
static __always_inline int
nat_icmp_quote_fixup_1to1(struct __sk_buff *skb, bool outer_is_source,
                          __be32 old_addr, __be32 new_addr) {
  struct iphdr *iph = nat_load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = nat_skb_data_end(skb);

  if (!nat_icmp_carries_quote(iph, data_end))
    return 0;

  struct nat_icmp_quote q;
  if (nat_read_icmp_quote(iph, data_end, &q) < 0)
    return -1;

  // The copied packet travelled the other way, so the address this NAT
  // moves sits in the mirrored field.
  if ((outer_is_source ? q.daddr : q.saddr) != old_addr)
    return -1;

  if (nat_icmp_quote_rewrite(skb, &q, outer_is_source, new_addr,
                             outer_is_source ? q.dport : q.sport) < 0)
    return -1;
  return 1;
}

// nat_apply_napt_in_rewrite performs the reverse rewrite for the inbound
// leg of any combined-NAT flow: CT_ACTION_NAPT_IN (NATGateway), and the
// dual-direction rewrites SVC_NAPT_IN (host-network Service backend) and
// SVC_SHARED_IN (shared Service in default Vpc). NAPT_IN only rewrites
// dst; the dual-direction actions also rewrite src so the original caller
// sees a reply from the canonical address (ClusterIP or remote peer).
// new_saddr / new_sport are set to 0 for plain NAPT_IN, where the
// rewrite naturally falls through.
//
// The function is a *pure rewriter*: it does not touch L2 nor decide
// where to forward the packet next. Callers issue forward_l2 (or any
// other dispatch) themselves, which is what lets the same helper run at
// both eth0 ingress (node_ingress) and juneau_node ingress (pod_egress).
static __always_inline int nat_apply_napt_in_rewrite(struct __sk_buff *skb,
                                                     struct ct_val *cv) {
  if (cv->action == CT_ACTION_SVC_NAPT_IN ||
      cv->action == CT_ACTION_SVC_SHARED_IN) {
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

// nat_apply_reverse_snat looks up the conntrack table for the inbound
// packet's 5-tuple. If a SNAT entry exists (which means this is the
// response leg of a Service flow whose forward DNAT was registered on
// this node), the source IP+port are rewritten back to the ClusterIP.
//
// Non-matching packets pass through unchanged. The function returns -1
// only on packet rewrite failures.
//
// Two hooks run it. pod_ingress does it on the veth of the Pod that
// asked, which is where a Subnet flow comes home. An L2Network has no
// pod_ingress on its NICs, so its flows come home through the egress of
// the gateway port instead and l2_gateway runs it there. The hook the
// trace event names is therefore a parameter.
static __always_inline int nat_apply_reverse_snat(struct __sk_buff *skb,
                                                  __u32 vpc_id,
                                                  __u32 subnet_id,
                                                  __u32 hook) {
  struct iphdr *iph = nat_load_iph(skb);
  if (!iph)
    return 0;
  void *data_end = nat_skb_data_end(skb);

  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return 0;

  __be16 sport, dport;
  if (nat_read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return 0;

  struct ct_key ck = {
      .scope = vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (!cv || cv->action != CT_ACTION_SNAT)
    return 0;

  cv->last_seen_ns = bpf_ktime_get_ns();
  __be32 new_saddr = cv->new_saddr;
  __be16 new_sport = cv->new_sport;
  __be32 before_saddr = iph->saddr;
  __be32 before_daddr = iph->daddr;
  __u8   before_proto = iph->protocol;

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  if (nat_rewrite_ipv4_addr(skb, true, new_saddr) < 0)
    return -1;
  if (nat_rewrite_l4_port(skb, true, new_sport) < 0)
    return -1;

  // Trace: reverse SNAT applied. before = (backend Pod IP, caller),
  // after = (Service ClusterIP, caller). The learned tuple lets the
  // pod's network namespace see "from ClusterIP" responses match.
  {
    struct trace_nat_event __ne = {
        .vpc_id = vpc_id,
        .subnet_id = subnet_id,
        .hook = hook,
        .reason = TRACE_REASON_REVERSE_NAT_APPLIED,
        .scope = TRACE_SCOPE_VPC,
        .proto = before_proto,
        .before_saddr = before_saddr,
        .before_daddr = before_daddr,
        .before_sport = sport,
        .before_dport = dport,
        .after_saddr = new_saddr,
        .after_daddr = before_daddr,
        .after_sport = new_sport,
        .after_dport = dport,
    };
    trace_observe_nat(skb, &__ne);
  }

  if (have_tcp_flags)
    ct_observe_tcp(&ck, cv, tcp_flags);
  return 0;
}

#endif // JUNEAU_BPF_NAT_H
