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

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct arp_payload {
  __u8 sha[ETH_ALEN];
  __be32 spa;
  __u8 tha[ETH_ALEN];
  __be32 tpa;
} __attribute__((packed));

static __always_inline int handle_arp(struct __sk_buff *skb, void *data_end,
                                      struct ethhdr *eth,
                                      const struct ifindex_subnet_val *val) {
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
  __u32 gw_addr = val->gw_addr;
  __u32 mask = val->mask;

  if ((tpa & mask) != (gw_addr & mask))
    return TC_ACT_SHOT;

  __u8 responder_mac[ETH_ALEN];
  if (val->subnet_id == 1) {
    __builtin_memcpy(responder_mac, val->gw_mac, ETH_ALEN);
  } else {
    if (tpa == gw_addr) {
      __builtin_memcpy(responder_mac, val->gw_mac, ETH_ALEN);
    } else {
      struct arp_table_key ak = {
          .subnet_id = val->subnet_id,
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

static __always_inline int handle_l3(struct __sk_buff *skb, struct ethhdr *eth,
                                     const struct ifindex_subnet_val *val) {
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  __u32 dst = bpf_ntohl(iph->daddr);

  __u32 sid = val->subnet_id;
  void *fib_inner_map = bpf_map_lookup_elem(&fib_map, &sid);
  if (!fib_inner_map)
    return TC_ACT_SHOT;

  struct fib_key fkey = {
      .prefixlen = 32,
      .dst = dst,
  };
  const struct fib_val *fv = bpf_map_lookup_elem(fib_inner_map, &fkey);
  if (!fv)
    return TC_ACT_SHOT;

  bool has_dmac = false;
#pragma unroll
  for (int i = 0; i < ETH_ALEN; i++) {
    if (fv->dmac[i]) {
      has_dmac = true;
      break;
    }
  }

  __u8 dmac[ETH_ALEN];
  if (has_dmac) {
    __builtin_memcpy(dmac, fv->dmac, ETH_ALEN);
  } else {
    struct arp_table_key ak = {
        .subnet_id = fv->subnet_id,
        .ipaddr = dst,
    };
    const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
    if (!av)
      return TC_ACT_SHOT;
    __builtin_memcpy(dmac, av->mac, ETH_ALEN);
  }

  __builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);

  if (has_dmac)
    return bpf_redirect(fv->oif, 0);

  return forward_l2(skb, eth, fv->subnet_id);
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

  __u16 h_proto = bpf_ntohs(eth->h_proto);
  if (h_proto == ETH_P_ARP)
    return handle_arp(skb, data_end, eth, val);

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
    if (eth->h_dest[i] != val->gw_mac[i]) {
      is_gw = false;
      break;
    }
  }
  if (is_gw)
    return handle_l3(skb, eth, val);

  return forward_l2(skb, eth, val->subnet_id);
}

SEC("tc")
int tc_pod_egress(struct __sk_buff *skb) { return handle_l2(skb); }

char __license[] SEC("license") = "Dual MIT/GPL";
