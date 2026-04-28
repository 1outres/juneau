// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "ct.h"
#include "maps.h"
#include "nat.h"

#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define IP_OFFSET 0x1FFF

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

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

static __always_inline int update_l4_csum(struct __sk_buff *skb, struct iphdr *iph,
                                          void *data_end, __be32 old_addr,
                                          __be32 new_addr) {
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

static __always_inline int handle_dnat(struct __sk_buff *skb, struct ethhdr *eth,
                                       struct iphdr *iph,
                                       const struct nat_inside *nat) {
  void *data;
  void *data_end;

  struct subnet_key sk = {
      .subnet_id = nat->subnet_id,
  };
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &sk);
  if (!subnet)
    return TC_ACT_SHOT;

  __be32 old_addr = iph->daddr;
  __be32 new_addr = bpf_htonl(nat->addr);

  struct arp_table_key ak = {
      .subnet_id = nat->subnet_id,
      .ipaddr = nat->addr,
  };
  const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
  if (!av)
    return TC_ACT_SHOT;

  __u8 dst_mac[ETH_ALEN];
  __u8 src_mac[ETH_ALEN];
  __builtin_memcpy(dst_mac, av->mac, ETH_ALEN);
  __builtin_memcpy(src_mac, subnet->gw_mac, ETH_ALEN);

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

  iph->daddr = new_addr;

  __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

  return forward_l2(skb, eth, nat->subnet_id);
}

// handle_napt_in is the reverse-NAPT path: a packet inbound on the
// underlay matched a host_napt_ip / alloc_port pair (NAPT_IN), or a
// node-underlay-IP / alloc_port pair (SVC_NAPT_IN). Both share the same
// shape: rewrite to the recorded tuple, then fdb-forward to the
// originating Pod's Subnet.
//
// NAPT_IN only rewrites daddr/dport (saddr/sport unchanged). SVC_NAPT_IN
// also rewrites saddr/sport so the Pod sees the original ClusterIP as
// the response source. The cv->new_saddr / cv->new_sport fields are
// 0 for NAPT_IN to make the rewrite a no-op there.
static __always_inline int handle_napt_in(struct __sk_buff *skb,
                                          struct ethhdr *eth, struct iphdr *iph,
                                          struct ct_val *cv,
                                          struct ct_key *ck) {
  void *data_end = nat_skb_data_end(skb);

  struct subnet_key sk = {.subnet_id = cv->next_subnet_id};
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &sk);
  if (!subnet)
    return TC_ACT_SHOT;

  struct arp_table_key ak = {
      .subnet_id = cv->next_subnet_id,
      .ipaddr = bpf_ntohl(cv->new_daddr),
  };
  const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
  if (!av)
    return TC_ACT_SHOT;

  __u8 dst_mac[ETH_ALEN];
  __u8 src_mac[ETH_ALEN];
  __builtin_memcpy(dst_mac, av->mac, ETH_ALEN);
  __builtin_memcpy(src_mac, subnet->gw_mac, ETH_ALEN);

  __be32 new_saddr = cv->new_saddr;
  __be16 new_sport = cv->new_sport;
  __be32 new_daddr = cv->new_daddr;
  __be16 new_dport = cv->new_dport;
  __u8 action = cv->action;

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  cv->last_seen_ns = bpf_ktime_get_ns();

  if (action == CT_ACTION_SVC_NAPT_IN) {
    if (nat_rewrite_ipv4_addr(skb, /*is_source=*/true, new_saddr) < 0)
      return TC_ACT_SHOT;
    if (nat_rewrite_l4_port(skb, /*is_source=*/true, new_sport) < 0)
      return TC_ACT_SHOT;
  }

  if (nat_rewrite_ipv4_addr(skb, /*is_source=*/false, new_daddr) < 0)
    return TC_ACT_SHOT;
  if (nat_rewrite_l4_port(skb, /*is_source=*/false, new_dport) < 0)
    return TC_ACT_SHOT;

  if (have_tcp_flags) {
    struct ct_val *cv2 = bpf_map_lookup_elem(&ct_map, ck);
    if (cv2)
      ct_observe_tcp(ck, cv2, tcp_flags);
  }

  // Re-derive packet pointers and rewrite L2.
  void *data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

  return forward_l2(skb, eth, cv->next_subnet_id);
}

static __always_inline int handle_l3(struct __sk_buff *skb, struct ethhdr *eth) {
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  // Packets destined to this node's underlay IP may be the response
  // leg of a host-network Service NAPT flow (CT_ACTION_SVC_NAPT_IN).
  // Try a SVC_NAPT_IN match first; on miss, fall through to the
  // bgp_address_pools / NAPT_IN / ElasticIP path so deployments where
  // host_napt_ip and the node's underlay IP coincide (single-NIC
  // bare-metal advertising the node IP via BGP, etc.) still recover
  // their existing NAPT_IN flows.
  __u32 underlay_key = 0;
  const __u32 *underlay_ip =
      bpf_map_lookup_elem(&host_underlay, &underlay_key);
  if (underlay_ip && *underlay_ip != 0 && iph->daddr == *underlay_ip) {
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
      __be16 sport, dport;
      if (nat_read_l4_ports(iph, data_end, &sport, &dport) == 0) {
        struct ct_key ck = {
            .scope = CT_SCOPE_HOST,
            .saddr = iph->saddr,
            .daddr = iph->daddr,
            .sport = sport,
            .dport = dport,
            .proto = iph->protocol,
        };
        struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
        if (cv && cv->action == CT_ACTION_SVC_NAPT_IN)
          return handle_napt_in(skb, eth, iph, cv, &ck);
      }
    }
    // Fall through to bgp_address_pools below.
  }

  struct bgp_address_pools_key bgp_key = {
      .prefixlen = 32,
      .addr = iph->daddr,
  };
  const __u8 *bgp_val = bpf_map_lookup_elem(&bgp_address_pools, &bgp_key);
  if (!bgp_val || *bgp_val == 0)
    return TC_ACT_OK;

  // First try NAPT reverse: ct_map keyed on (HOST, src=internet,
  // dst=host_napt_ip, sport=remote, dport=alloc_port). Fall through to
  // ElasticIP 1:1 NAT (nat_dnat_map) if no NAPT entry exists.
  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
    __be16 sport, dport;
    if (nat_read_l4_ports(iph, data_end, &sport, &dport) == 0) {
      struct ct_key ck = {
          .scope = CT_SCOPE_HOST,
          .saddr = iph->saddr,
          .daddr = iph->daddr,
          .sport = sport,
          .dport = dport,
          .proto = iph->protocol,
      };
      struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
      if (cv && cv->action == CT_ACTION_NAPT_IN)
        return handle_napt_in(skb, eth, iph, cv, &ck);
    }
  }

  struct nat_outside nk = {
      .addr = bpf_ntohl(iph->daddr),
  };
  const struct nat_inside *nv = bpf_map_lookup_elem(&nat_dnat_map, &nk);
  if (!nv)
    return TC_ACT_SHOT;

  return handle_dnat(skb, eth, iph, nv);
}

static __always_inline int handle_l2(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  return handle_l3(skb, eth);
}

SEC("tc")
int tc_node_ingress(struct __sk_buff *skb) { return handle_l2(skb); }

char __license[] SEC("license") = "Dual MIT/GPL";
