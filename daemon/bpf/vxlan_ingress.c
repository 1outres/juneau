// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_ALEN 6
#define ETH_P_ARP 0x0806

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#ifndef MAX_FDB
#define MAX_FDB 131072
#endif

struct host_iface_val {
  __u32 ifindex;
  __u8 mac[6];
};

struct fdb_key {
  __u32 subnet_id;
  __u8 mac[6];
};

struct fdb_val {
  __u32 ifindex;
  __u32 vtep_ip;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct host_iface_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} host_iface SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FDB);
  __type(key, struct fdb_key);
  __type(value, struct fdb_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} fdb SEC(".maps");

static __always_inline int tc_vxlan_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  struct bpf_tunnel_key tkey = {};
  if (bpf_skb_get_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0)
    return TC_ACT_SHOT;

  __u32 subnet_id = tkey.tunnel_id & 0xFFFFFF;
  if (subnet_id == 1) {
    __u32 host_key = 0;
    const struct host_iface_val *host =
        bpf_map_lookup_elem(&host_iface, &host_key);
    if (!host)
      return TC_ACT_SHOT;

    __builtin_memcpy(eth->h_dest, host->mac, ETH_ALEN);

    return bpf_redirect(host->ifindex, 0);
  }

  struct fdb_key fk = {
      .subnet_id = subnet_id,
  };
  __builtin_memcpy(fk.mac, eth->h_dest, ETH_ALEN);
  const struct fdb_val *fv = bpf_map_lookup_elem(&fdb, &fk);
  if (!fv)
    return TC_ACT_SHOT;

  if (fv->ifindex != 0)
    return bpf_redirect(fv->ifindex, 0);

  return TC_ACT_SHOT;
}

SEC("tc")
int tc_vxlan_ingress_entry(struct __sk_buff *skb) {
  return tc_vxlan_ingress(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
