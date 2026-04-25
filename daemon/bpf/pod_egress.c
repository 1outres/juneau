// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "maps.h"

#define ETH_ALEN 6
#define ETH_P_ARP 0x0806
#define ETH_P_IP 0x0800
#define ARPHRD_ETHER 1
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define IP_OFFSET 0x1FFF

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define AF_INET 2

struct arp_payload {
  __u8 sha[ETH_ALEN];
  __be32 spa;
  __u8 tha[ETH_ALEN];
  __be32 tpa;
} __attribute__((packed));

static __always_inline int update_l4_csum(struct __sk_buff *skb,
                                          struct iphdr *iph, void *data_end,
                                          __be32 old_addr, __be32 new_addr) {
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return TC_ACT_SHOT;

  if ((bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0)
    return TC_ACT_OK;

  __u32 l4_off = sizeof(struct ethhdr) + ihl * 4;

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)iph + ihl * 4;
    if ((void *)(tcp + 1) > data_end)
      return TC_ACT_SHOT;

    if (bpf_l4_csum_replace(skb,
                            l4_off + __builtin_offsetof(struct tcphdr, check),
                            old_addr, new_addr,
                            BPF_F_PSEUDO_HDR | sizeof(new_addr)) < 0)
      return TC_ACT_SHOT;

    return TC_ACT_OK;
  }

  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)iph + ihl * 4;
    if ((void *)(udp + 1) > data_end)
      return TC_ACT_SHOT;

    if (udp->check == 0)
      return TC_ACT_OK;

    if (bpf_l4_csum_replace(skb,
                            l4_off + __builtin_offsetof(struct udphdr, check),
                            old_addr, new_addr,
                            BPF_F_PSEUDO_HDR | sizeof(new_addr)) < 0)
      return TC_ACT_SHOT;
  }

  return TC_ACT_OK;
}

static __always_inline int handle_snat(struct __sk_buff *skb,
                                       struct ethhdr *eth, struct iphdr *iph) {
  void *data;
  void *data_end;

  struct ifindex_subnet_key isk = {
      .ifindex = skb->ifindex,
  };
  const struct ifindex_subnet_val *isv =
      bpf_map_lookup_elem(&ifindex_subnet, &isk);
  if (!isv)
    return TC_ACT_SHOT;

  struct nat_inside nk = {
      .subnet_id = isv->subnet_id,
      .addr = bpf_ntohl(iph->saddr),
  };
  const struct nat_outside *nv = bpf_map_lookup_elem(&nat_snat_map, &nk);
  if (!nv)
    return TC_ACT_SHOT;

  __be32 old_addr = iph->saddr;
  __be32 new_addr = bpf_htonl(nv->addr);

  if (bpf_l3_csum_replace(skb,
                          sizeof(struct ethhdr) +
                              __builtin_offsetof(struct iphdr, check),
                          old_addr, new_addr, sizeof(new_addr)) < 0)
    return TC_ACT_SHOT;

  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;

  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  int csum_ret = update_l4_csum(skb, iph, data_end, old_addr, new_addr);
  if (csum_ret != TC_ACT_OK)
    return csum_ret;

  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;

  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  if (bpf_skb_store_bytes(skb,
                          sizeof(struct ethhdr) +
                              __builtin_offsetof(struct iphdr, saddr),
                          &new_addr, sizeof(new_addr), 0) < 0)
    return TC_ACT_SHOT;

  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;

  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  // Resolve next-hop at runtime via kernel FIB + neighbor table. Fixing the
  // MAC to the default gateway at daemon start breaks paths where the actual
  // next-hop differs (BGP-learned peers, multi-uplink, L2-adjacent peers).
  //
  // Use an ingress-style lookup (no BPF_FIB_LOOKUP_OUTPUT): the OUTPUT flag
  // would pin oif to our pod-veth ifindex, against which no route exists.
  // Ingress-style lets the kernel pick the right egress iface from the FIB.
  struct bpf_fib_lookup fib_params = {};
  fib_params.family = AF_INET;
  fib_params.l4_protocol = iph->protocol;
  fib_params.ipv4_dst = iph->daddr;
  fib_params.ifindex = skb->ifindex;

  long rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
  if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
    // Neighbor not yet resolved: hand off to kernel to trigger ARP.
    return TC_ACT_OK;
  }
  if (rc != BPF_FIB_LKUP_RET_SUCCESS)
    return TC_ACT_SHOT;

  if (bpf_skb_store_bytes(skb, __builtin_offsetof(struct ethhdr, h_dest),
                          fib_params.dmac, ETH_ALEN, 0) < 0)
    return TC_ACT_SHOT;

  if (bpf_skb_store_bytes(skb, __builtin_offsetof(struct ethhdr, h_source),
                          fib_params.smac, ETH_ALEN, 0) < 0)
    return TC_ACT_SHOT;

  return bpf_redirect(fib_params.ifindex, 0);
}

static __always_inline int handle_arp(struct __sk_buff *skb, void *data_end,
                                      struct ethhdr *eth, __u32 subnet_id,
                                      const struct subnet_val *subnet) {
  struct arphdr *arp = (void *)(eth + 1);
  if ((void *)(arp + 1) > data_end)
    return TC_ACT_SHOT;

  if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER))
    return TC_ACT_SHOT;
  if (arp->ar_pro != bpf_htons(ETH_P_IP))
    return TC_ACT_SHOT;
  if (arp->ar_hln != ETH_ALEN || arp->ar_pln != 4)
    return TC_ACT_SHOT;
  if (arp->ar_op != bpf_htons(ARPOP_REQUEST))
    return TC_ACT_SHOT;

  struct arp_payload *payload = (void *)(arp + 1);
  if ((void *)(payload + 1) > data_end)
    return TC_ACT_SHOT;

  __u32 tpa = bpf_ntohl(payload->tpa);
  __u32 gw_addr = subnet->gw_addr;
  __u32 mask = subnet->mask;

  if ((tpa & mask) != (gw_addr & mask))
    return TC_ACT_SHOT;

  __u8 responder_mac[ETH_ALEN];
  if (subnet_id == 1) {
    __builtin_memcpy(responder_mac, subnet->gw_mac, ETH_ALEN);
  } else {
    if (tpa == gw_addr) {
      __builtin_memcpy(responder_mac, subnet->gw_mac, ETH_ALEN);
    } else {
      struct arp_table_key ak = {
          .subnet_id = subnet_id,
          .ipaddr = tpa,
      };
      const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
      if (!av)
        return TC_ACT_SHOT;
      __builtin_memcpy(responder_mac, av->mac, ETH_ALEN);
    }
  }

  __u8 requester_mac[ETH_ALEN];
  __builtin_memcpy(requester_mac, eth->h_source, ETH_ALEN);
  __be32 requester_ip = payload->spa;
  __be32 target_ip = payload->tpa;

  __builtin_memcpy(eth->h_dest, requester_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, responder_mac, ETH_ALEN);

  arp->ar_op = bpf_htons(ARPOP_REPLY);
  __builtin_memcpy(payload->tha, requester_mac, ETH_ALEN);
  payload->tpa = requester_ip;
  __builtin_memcpy(payload->sha, responder_mac, ETH_ALEN);
  payload->spa = target_ip;

  return bpf_redirect(skb->ifindex, 0);
}

static __always_inline int forward_l2(struct __sk_buff *skb, struct ethhdr *eth,
                                      __u32 subnet_id) {
  struct fdb_key fk = {};
  fk.subnet_id = subnet_id;
  __builtin_memcpy(fk.mac, eth->h_dest, ETH_ALEN);
  const struct fdb_val *fv = bpf_map_lookup_elem(&fdb, &fk);
  if (!fv)
    return TC_ACT_SHOT;

  if (fv->ifindex != 0)
    return bpf_redirect(fv->ifindex, 0);

  __u32 vx_key = 0;
  const __u32 *vx_if = bpf_map_lookup_elem(&vxlan_ifindex, &vx_key);
  if (!vx_if)
    return TC_ACT_SHOT;

  struct bpf_tunnel_key tkey = {};
  tkey.remote_ipv4 = fv->vtep_ip;
  tkey.tunnel_id = subnet_id;
  tkey.tunnel_ttl = 64;
  tkey.tunnel_tos = 0;

  if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0)
    return TC_ACT_SHOT;

  return bpf_redirect(*vx_if, 0);
}

// Read TCP/UDP source and destination ports. Returns 0 on success, -1 on
// malformed packet. Ports remain in network byte order.
static __always_inline int read_l4_ports(struct iphdr *iph, void *data_end,
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

// rewrite_ipv4_addr rewrites either the source or destination IPv4 address
// in the packet, refreshes both the L3 checksum and the L4 pseudo-header
// portion of the L4 checksum, and re-validates the eth/iphdr pointers
// after the kernel may have reallocated the linear buffer.
static __always_inline int rewrite_ipv4_addr(struct __sk_buff *skb,
                                             bool is_source,
                                             __be32 new_addr,
                                             struct ethhdr **eth_p,
                                             struct iphdr **iph_p,
                                             void **data_end_p) {
  struct iphdr *iph = *iph_p;
  void *data_end = *data_end_p;

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

  int rc = update_l4_csum(skb, iph, data_end, old_addr, new_addr);
  if (rc != TC_ACT_OK)
    return -1;

  if (bpf_skb_store_bytes(skb, addr_off, &new_addr, sizeof(new_addr), 0) < 0)
    return -1;

  void *data = (void *)(long)skb->data;
  *data_end_p = (void *)(long)skb->data_end;
  *eth_p = data;
  if ((void *)(*eth_p + 1) > *data_end_p)
    return -1;
  *iph_p = (struct iphdr *)((void *)(*eth_p) + sizeof(struct ethhdr));
  if ((void *)(*iph_p + 1) > *data_end_p)
    return -1;
  return 0;
}

// rewrite_l4_port rewrites either the source or destination L4 port for
// TCP/UDP packets and updates the L4 checksum. Pointers are re-validated
// because bpf_skb_store_bytes can shift the linear buffer.
static __always_inline int rewrite_l4_port(struct __sk_buff *skb,
                                           bool is_source, __be16 new_port,
                                           struct ethhdr **eth_p,
                                           struct iphdr **iph_p,
                                           void **data_end_p) {
  struct iphdr *iph = *iph_p;
  void *data_end = *data_end_p;

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
    if (bpf_l4_csum_replace(skb, csum_off, old_port, new_port, sizeof(new_port)) <
        0)
      return -1;
  }

  if (bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port), 0) < 0)
    return -1;

  void *data = (void *)(long)skb->data;
  *data_end_p = (void *)(long)skb->data_end;
  *eth_p = data;
  if ((void *)(*eth_p + 1) > *data_end_p)
    return -1;
  *iph_p = (struct iphdr *)((void *)(*eth_p) + sizeof(struct ethhdr));
  if ((void *)(*iph_p + 1) > *data_end_p)
    return -1;
  return 0;
}

// hash_tuple folds a 5-tuple into a 32-bit value used to spread requests
// evenly across backends. Mixing constants are arbitrary; the only
// requirement is decent diffusion of low-order bits.
static __always_inline __u32 hash_tuple(__be32 saddr, __be32 daddr,
                                        __be16 sport, __be16 dport,
                                        __u8 proto) {
  __u32 h = bpf_ntohl(saddr);
  h ^= bpf_ntohl(daddr) * 0x9e3779b1;
  h ^= ((__u32)bpf_ntohs(sport) << 16) | bpf_ntohs(dport);
  h ^= (__u32)proto * 0x85ebca6b;
  h ^= h >> 16;
  return h;
}

// dispatch_after_dnat does the second FIB lookup that finds the route to
// the chosen backend and forwards the (already DNAT'd) packet onward.
// Service entries are not expected here — if the second lookup itself
// resolves to SERVICE we treat it as a configuration error and drop.
static __always_inline int dispatch_after_dnat(struct __sk_buff *skb,
                                               struct ethhdr *eth,
                                               struct iphdr *iph,
                                               __u32 table_id, __be32 dst_be) {
  __u32 tid = table_id;
  void *fib_inner_map = bpf_map_lookup_elem(&fib_map, &tid);
  if (!fib_inner_map)
    return TC_ACT_SHOT;

  struct fib_key fkey = {
      .prefixlen = 32,
      .dst = dst_be,
  };
  const struct fib_val *fv = bpf_map_lookup_elem(fib_inner_map, &fkey);
  if (!fv)
    return TC_ACT_SHOT;

  if (fv->type == FIB_ROUTE_TYPE_CONNECTED) {
    struct arp_table_key ak = {
        .subnet_id = fv->subnet_id,
        .ipaddr = bpf_ntohl(dst_be),
    };
    const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
    if (!av)
      return TC_ACT_SHOT;
    __builtin_memcpy(eth->h_dest, av->mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);
    return forward_l2(skb, eth, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_ENDPOINT) {
    __builtin_memcpy(eth->h_dest, fv->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);
    return forward_l2(skb, eth, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_INTERNET_GATEWAY)
    return handle_snat(skb, eth, iph);

  return TC_ACT_SHOT;
}

// handle_service performs the Service DNAT path. It enforces VPC ownership
// (caller and Service owner must share a Vpc), picks a backend by hashing
// the 5-tuple, installs forward and reverse CT entries, rewrites the
// destination IP+port to the backend, and continues with a second FIB
// lookup so the rewritten packet can find a normal CONNECTED/ENDPOINT
// route to the backend Pod.
static __always_inline int
handle_service(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph,
               const struct subnet_val *subnet) {
  void *data_end = (void *)(long)skb->data_end;

  __be16 sport, dport;
  if (read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return TC_ACT_SHOT;

  struct service_key sk = {
      .cluster_ip = bpf_ntohl(iph->daddr),
      .port = bpf_ntohs(dport),
      .proto = iph->protocol,
  };
  const struct service_val *sv = bpf_map_lookup_elem(&service_map, &sk);
  if (!sv)
    return TC_ACT_SHOT;
  if (sv->owner_vpc_id != subnet->vpc_id)
    return TC_ACT_SHOT;
  if (sv->backend_count == 0)
    return TC_ACT_SHOT;

  __u32 idx = hash_tuple(iph->saddr, iph->daddr, sport, dport, iph->protocol) %
              sv->backend_count;

  struct backend_key bk = {
      .cluster_ip = sk.cluster_ip,
      .port = sk.port,
      .proto = sk.proto,
      .index = idx,
  };
  const struct backend_val *bv = bpf_map_lookup_elem(&backend_map, &bk);
  if (!bv)
    return TC_ACT_SHOT;

  __be32 backend_addr_be = bpf_htonl(bv->backend_ip);
  __be16 backend_port_be = bpf_htons(bv->backend_port);

  __u64 now = bpf_ktime_get_ns();

  // Forward CT entry: caller -> ClusterIP keyed tuple, action=DNAT.
  struct ct_key fwd_key = {
      .vpc_id = subnet->vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val fwd_val = {
      .new_saddr = iph->saddr,
      .new_daddr = backend_addr_be,
      .new_sport = sport,
      .new_dport = backend_port_be,
      .backend_subnet_id = bv->backend_subnet_id,
      .action = CT_ACTION_DNAT,
      .last_seen_ns = now,
  };
  bpf_map_update_elem(&ct_map, &fwd_key, &fwd_val, BPF_ANY);

  // Reverse CT entry: backend -> caller keyed tuple, action=SNAT. Used by
  // the backend's pod_egress on the response leg to restore the ClusterIP.
  struct ct_key rev_key = {
      .vpc_id = subnet->vpc_id,
      .saddr = backend_addr_be,
      .daddr = iph->saddr,
      .sport = backend_port_be,
      .dport = sport,
      .proto = iph->protocol,
  };
  struct ct_val rev_val = {
      .new_saddr = iph->daddr,
      .new_daddr = iph->saddr,
      .new_sport = dport,
      .new_dport = sport,
      .backend_subnet_id = 0,
      .action = CT_ACTION_SNAT,
      .last_seen_ns = now,
  };
  bpf_map_update_elem(&ct_map, &rev_key, &rev_val, BPF_ANY);

  if (rewrite_ipv4_addr(skb, /*is_source=*/false, backend_addr_be, &eth, &iph,
                        &data_end) < 0)
    return TC_ACT_SHOT;
  if (rewrite_l4_port(skb, /*is_source=*/false, backend_port_be, &eth, &iph,
                      &data_end) < 0)
    return TC_ACT_SHOT;

  return dispatch_after_dnat(skb, eth, iph, subnet->table_id, backend_addr_be);
}

// apply_ct rewrites packet headers based on a CT entry: forward direction
// applies DNAT (rewrites destination), reverse direction applies SNAT
// (rewrites source). On success returns the destination IP that should be
// used for the subsequent FIB lookup.
static __always_inline int apply_ct(struct __sk_buff *skb,
                                    const struct ct_val *cv,
                                    struct ethhdr **eth_p,
                                    struct iphdr **iph_p, void **data_end_p,
                                    __be32 *next_dst_be) {
  if (cv->action == CT_ACTION_DNAT) {
    if (rewrite_ipv4_addr(skb, false, cv->new_daddr, eth_p, iph_p, data_end_p) < 0)
      return -1;
    if (rewrite_l4_port(skb, false, cv->new_dport, eth_p, iph_p, data_end_p) < 0)
      return -1;
    *next_dst_be = cv->new_daddr;
    return 0;
  }
  if (cv->action == CT_ACTION_SNAT) {
    if (rewrite_ipv4_addr(skb, true, cv->new_saddr, eth_p, iph_p, data_end_p) < 0)
      return -1;
    if (rewrite_l4_port(skb, true, cv->new_sport, eth_p, iph_p, data_end_p) < 0)
      return -1;
    *next_dst_be = (*iph_p)->daddr;
    return 0;
  }
  return -1;
}

static __always_inline int handle_l3(struct __sk_buff *skb, struct ethhdr *eth,
                                     const struct subnet_val *subnet) {
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  // Always probe ct_map first. A hit means we are either continuing an
  // established Service flow (forward/DNAT) or carrying a backend's
  // response (reverse/SNAT); both pre-empt the regular FIB path so the
  // packet leaves with addresses the peer already negotiated.
  __be16 sport_pkt = 0, dport_pkt = 0;
  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
    if (read_l4_ports(iph, data_end, &sport_pkt, &dport_pkt) == 0) {
      struct ct_key ck = {
          .vpc_id = subnet->vpc_id,
          .saddr = iph->saddr,
          .daddr = iph->daddr,
          .sport = sport_pkt,
          .dport = dport_pkt,
          .proto = iph->protocol,
      };
      struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
      if (cv) {
        cv->last_seen_ns = bpf_ktime_get_ns();
        __be32 next_dst_be = iph->daddr;
        if (apply_ct(skb, cv, &eth, &iph, &data_end, &next_dst_be) < 0)
          return TC_ACT_SHOT;
        return dispatch_after_dnat(skb, eth, iph, subnet->table_id,
                                   next_dst_be);
      }
    }
  }

  __u32 dst_be = iph->daddr; // keep network order for LPM trie

  __u32 tid = subnet->table_id;
  void *fib_inner_map = bpf_map_lookup_elem(&fib_map, &tid);
  if (!fib_inner_map)
    return TC_ACT_SHOT;

  struct fib_key fkey = {
      .prefixlen = 32,
      .dst = dst_be,
  };
  const struct fib_val *fv = bpf_map_lookup_elem(fib_inner_map, &fkey);
  if (!fv)
    return TC_ACT_SHOT;

  if (fv->type == FIB_ROUTE_TYPE_CONNECTED) {
    struct arp_table_key ak = {
        .subnet_id = fv->subnet_id,
        .ipaddr = bpf_ntohl(dst_be),
    };
    const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
    if (!av)
      return TC_ACT_SHOT;

    __builtin_memcpy(eth->h_dest, av->mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);

    return forward_l2(skb, eth, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_ENDPOINT) {
    __builtin_memcpy(eth->h_dest, fv->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);

    return forward_l2(skb, eth, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_INTERNET_GATEWAY)
    return handle_snat(skb, eth, iph);

  if (fv->type == FIB_ROUTE_TYPE_SERVICE)
    return handle_service(skb, eth, iph, subnet);

  return TC_ACT_SHOT;
}

static __always_inline int handle_l2(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  struct ifindex_subnet_key key = {
      .ifindex = skb->ifindex,
  };
  const struct ifindex_subnet_val *val =
      bpf_map_lookup_elem(&ifindex_subnet, &key);
  if (!val)
    return TC_ACT_SHOT;

  struct subnet_key skey = {
      .subnet_id = val->subnet_id,
  };
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &skey);
  if (!subnet)
    return TC_ACT_SHOT;

  __u16 h_proto = bpf_ntohs(eth->h_proto);
  if (h_proto == ETH_P_ARP)
    return handle_arp(skb, data_end, eth, val->subnet_id, subnet);

  if (val->subnet_id == 1) {
    __u32 host_key = 0;
    const struct host_iface_val *host =
        bpf_map_lookup_elem(&host_iface, &host_key);
    if (!host)
      return TC_ACT_SHOT;
    return bpf_redirect(host->ifindex, 0);
  }

  // subnet_id != 1
  bool is_gw = true;
#pragma unroll
  for (int i = 0; i < ETH_ALEN; i++) {
    if (eth->h_dest[i] != subnet->gw_mac[i]) {
      is_gw = false;
      break;
    }
  }
  if (is_gw)
    return handle_l3(skb, eth, subnet);

  return forward_l2(skb, eth, val->subnet_id);
}

SEC("tc")
int tc_pod_egress(struct __sk_buff *skb) { return handle_l2(skb); }

char __license[] SEC("license") = "Dual MIT/GPL";
