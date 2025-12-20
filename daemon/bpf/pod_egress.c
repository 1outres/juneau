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

#ifndef BPF_F_INGRESS
#define BPF_F_INGRESS (1U << 0)
#endif

#ifndef MAX_IF_SUBNET
#define MAX_IF_SUBNET 32768
#endif

struct ifindex_subnet_key {
  __u32 ifindex;
};

struct ifindex_subnet_val {
  __u32 subnet_id;
  __u8 gw_mac[6];
  __u32 gw_addr;
  __u32 mask;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_IF_SUBNET);
  __type(key, struct ifindex_subnet_key);
  __type(value, struct ifindex_subnet_val);
} ifindex_subnet SEC(".maps");

struct arp_payload {
  __u8 sha[ETH_ALEN];
  __be32 spa;
  __u8 tha[ETH_ALEN];
  __be32 tpa;
} __attribute__((packed));

static __always_inline int handle_arp(struct __sk_buff *skb, void *data_end,
                                      struct ethhdr *eth) {
    struct arphdr *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end) {
        bpf_printk("pod_egress: drop arp hdr oob");
        return TC_ACT_SHOT;
    }

    if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER)) {
        bpf_printk("pod_egress: drop arp hrd");
        return TC_ACT_SHOT;
    }
    if (arp->ar_pro != bpf_htons(ETH_P_IP)) {
        bpf_printk("pod_egress: drop arp pro");
        return TC_ACT_SHOT;
    }
    if (arp->ar_hln != ETH_ALEN || arp->ar_pln != 4) {
        bpf_printk("pod_egress: drop arp hlen/plen");
        return TC_ACT_SHOT;
    }
    if (arp->ar_op != bpf_htons(ARPOP_REQUEST)) {
        bpf_printk("pod_egress: drop arp op");
        return TC_ACT_SHOT;
    }

    struct arp_payload *payload = (void *)(arp + 1);
    if ((void *)(payload + 1) > data_end) {
        bpf_printk("pod_egress: drop arp payload oob");
        return TC_ACT_SHOT;
    }

    struct ifindex_subnet_key key = {
        .ifindex = skb->ifindex,
    };
    struct ifindex_subnet_val *val = bpf_map_lookup_elem(&ifindex_subnet, &key);
    if (!val) {
        bpf_printk("pod_egress: drop no map entry");
        return TC_ACT_SHOT;
    }

    __u32 tpa = bpf_ntohl(payload->tpa);
    __u32 gw_addr = val->gw_addr;
    __u32 mask = val->mask;

    if ((tpa & mask) != (gw_addr & mask)) {
        __u32 tpa_raw = payload->tpa;
        __u32 tpa_masked = tpa & mask;
        __u32 gw_masked = gw_addr & mask;
        bpf_printk("pod_egress: drop tpa out of range if=%d", skb->ifindex);
        bpf_printk("pod_egress: tpa_raw=%x tpa=%x", tpa_raw, tpa);
        bpf_printk("pod_egress: gw=%x mask=%x", gw_addr, mask);
        bpf_printk("pod_egress: tpa&m=%x gw&m=%x", tpa_masked, gw_masked);
        return TC_ACT_SHOT;
    }
    if (val->subnet_id != 1) {
        bpf_printk("pod_egress: drop subnet_id != 1");
        return TC_ACT_SHOT;
    }

  __u8 requester_mac[ETH_ALEN];
  __builtin_memcpy(requester_mac, eth->h_source, ETH_ALEN);
  __be32 requester_ip = payload->spa;
  __be32 target_ip = payload->tpa;

  __builtin_memcpy(eth->h_dest, requester_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, val->gw_mac, ETH_ALEN);

  arp->ar_op = bpf_htons(ARPOP_REPLY);
  __builtin_memcpy(payload->tha, requester_mac, ETH_ALEN);
  payload->tpa = requester_ip;
  __builtin_memcpy(payload->sha, val->gw_mac, ETH_ALEN);
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

  return TC_ACT_SHOT;
}

SEC("tc")
int tc_pod_egress(struct __sk_buff *skb) { return handle_l2(skb); }

char __license[] SEC("license") = "Dual MIT/GPL";
