// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_ALEN 6
#define ETH_P_ARP 0x0806
#define ETH_P_IP 0x0800
#define ARPHRD_ETHER 1
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#ifndef MAX_ARP_TABLE
#define MAX_ARP_TABLE 131072
#endif

#ifndef MAX_FDB
#define MAX_FDB 131072
#endif

struct arp_table_key {
  __u32 subnet_id;
  __u32 ipaddr;
};

struct arp_table_val {
  __u8 mac[6];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ARP_TABLE);
  __type(key, struct arp_table_key);
  __type(value, struct arp_table_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} arp_table SEC(".maps");

struct fdb_key {
  __u32 subnet_id;
  __u8 mac[6];
};

struct fdb_val {
  __u32 ifindex;
  __u32 vtep_ip;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FDB);
  __type(key, struct fdb_key);
  __type(value, struct fdb_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} fdb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32); // vxlan ifindex
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} vxlan_ifindex SEC(".maps");

struct arp_payload {
  __u8 sha[ETH_ALEN];
  __be32 spa;
  __u8 tha[ETH_ALEN];
  __be32 tpa;
} __attribute__((packed));

static __always_inline int handle_arp(struct __sk_buff *skb, void *data_end,
                                      struct ethhdr *eth) {
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

  struct arp_table_key key = {
      .subnet_id = 1,
      .ipaddr = bpf_ntohl(payload->tpa),
  };
  const struct arp_table_val *val = bpf_map_lookup_elem(&arp_table, &key);
  if (!val)
    return TC_ACT_SHOT;

  __u8 requester_mac[ETH_ALEN];
  __builtin_memcpy(requester_mac, eth->h_source, ETH_ALEN);
  __be32 requester_ip = payload->spa;
  __be32 target_ip = payload->tpa;

  __builtin_memcpy(eth->h_dest, requester_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, val->mac, ETH_ALEN);

  arp->ar_op = bpf_htons(ARPOP_REPLY);
  __builtin_memcpy(payload->tha, requester_mac, ETH_ALEN);
  payload->tpa = requester_ip;
  __builtin_memcpy(payload->sha, val->mac, ETH_ALEN);
  payload->spa = target_ip;

  return bpf_redirect(skb->ifindex, 0);
}

static __always_inline int handle_l2(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  __u16 h_proto = bpf_ntohs(eth->h_proto);
  if (h_proto == ETH_P_ARP)
    return handle_arp(skb, data_end, eth);

  struct fdb_key fdb_key = {
      .subnet_id = 1,
  };
  __builtin_memcpy(fdb_key.mac, eth->h_dest, ETH_ALEN);
  const struct fdb_val *fdb_val = bpf_map_lookup_elem(&fdb, &fdb_key);
  if (!fdb_val)
    return TC_ACT_SHOT;

  if (fdb_val->ifindex != 0)
    return bpf_redirect(fdb_val->ifindex, 0);

  __u32 vx_key = 0;
  __u32 *vx_if = bpf_map_lookup_elem(&vxlan_ifindex, &vx_key);
  if (!vx_if)
    return TC_ACT_SHOT;

  struct bpf_tunnel_key tkey = {};
  tkey.remote_ipv4 = bpf_htonl(fdb_val->vtep_ip);
  tkey.tunnel_id = bpf_htonl(1U << 8);
  tkey.tunnel_ttl = 64;
  tkey.tunnel_tos = 0;

  if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0)
    return TC_ACT_SHOT;

  return bpf_redirect(*vx_if, 0);

  return TC_ACT_SHOT;
}

SEC("tc")
int tc_host_egress(struct __sk_buff *skb) { return handle_l2(skb); }

char __license[] SEC("license") = "Dual MIT/GPL";
