// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_ALEN 6
#define ETH_P_ARP 0x0806

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct host_iface_val {
  __u32 ifindex;
  __u8 mac[6];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct host_iface_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} host_iface SEC(".maps");

static __always_inline int tc_vxlan_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  struct bpf_tunnel_key tkey = {};
  if (bpf_skb_get_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0)
    return TC_ACT_SHOT;

  __u32 subnet_id = bpf_ntohl(tkey.tunnel_id) >> 8;
  if (subnet_id != 1)
    return TC_ACT_SHOT;

  __u32 host_key = 0;
  struct host_iface_val *host = bpf_map_lookup_elem(&host_iface, &host_key);
  if (!host)
    return TC_ACT_SHOT;

  __builtin_memcpy(eth->h_dest, host->mac, ETH_ALEN);

  return bpf_redirect(host->ifindex, 0);
}

SEC("tc")
int tc_vxlan_ingress_entry(struct __sk_buff *skb) {
  return tc_vxlan_ingress(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";

