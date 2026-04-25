// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "maps.h"
#include "nat.h"

#define ETH_ALEN 6
#define ETH_P_ARP 0x0806
#define ETH_P_IP 0x0800

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// apply_reverse_snat looks up the conntrack table for the inbound
// packet's 5-tuple and, if a SNAT entry is found (which means this is the
// response leg of a Service flow whose forward DNAT happened on this
// node), rewrites the source IP+port to the original ClusterIP. Without
// this step, the response would carry the backend Pod's address and the
// caller's TCP stack would reject it.
static __always_inline int apply_reverse_snat(struct __sk_buff *skb,
                                              __u32 vpc_id) {
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
      .vpc_id = vpc_id,
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

  if (nat_rewrite_ipv4_addr(skb, true, new_saddr) < 0)
    return -1;
  if (nat_rewrite_l4_port(skb, true, new_sport) < 0)
    return -1;
  return 0;
}

static __always_inline int tc_vxlan_ingress(struct __sk_buff *skb) {
  void *data = nat_skb_data(skb);
  void *data_end = nat_skb_data_end(skb);

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

  // For non-default subnets, apply reverse SNAT for Service flows whose
  // conntrack entry lives on this node. The forward DNAT happened on the
  // caller's pod_egress on this same node; the corresponding reverse
  // entry was registered at the same time. When the backend's response
  // arrives via VXLAN we patch the source addr/port so the caller sees
  // the ClusterIP it originally connected to.
  __u16 h_proto = bpf_ntohs(eth->h_proto);
  if (h_proto == ETH_P_IP) {
    struct subnet_key skey = {.subnet_id = subnet_id};
    const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &skey);
    if (subnet) {
      if (apply_reverse_snat(skb, subnet->vpc_id) < 0)
        return TC_ACT_SHOT;

      // Refresh local pointers because nat_rewrite_* may have shifted
      // skb->data internally.
      data = nat_skb_data(skb);
      data_end = nat_skb_data_end(skb);
      eth = data;
      if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;
    }
  }

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
