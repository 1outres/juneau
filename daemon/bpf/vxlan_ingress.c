// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

#define ETH_ALEN 6

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

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

  // Service reverse SNAT lives in pod_ingress, attached to the
  // destination Pod's veth egress. vxlan_ingress just decapsulates and
  // hands the packet to fdb-driven forwarding. The default Subnet (VNI
  // 1) is no longer special-cased: its gw_mac is a cluster-wide LAA and
  // its Pods participate in the standard fdb path like any other Subnet.
  struct fdb_key fk = {};
  fk.subnet_id = subnet_id;
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
