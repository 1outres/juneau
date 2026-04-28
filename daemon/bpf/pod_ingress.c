// go:build ignore
//
// pod_ingress is attached to the egress side of each Pod's host-side veth
// peer (i.e. packets destined for the Pod). It applies any reverse SNAT
// recorded in conntrack so that responses to Service requests carry the
// original ClusterIP rather than the backend Pod IP. Forward DNAT lives
// in pod_egress; the two programs together cover the symmetric NAT pair.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "ct.h"
#include "maps.h"
#include "nat.h"

#define ETH_P_IP 0x0800

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// apply_reverse_snat looks up the conntrack table for the inbound
// packet's 5-tuple. If a SNAT entry exists (which means this is the
// response leg of a Service flow whose forward DNAT was registered on
// this node), the source IP+port are rewritten back to the ClusterIP.
//
// Non-matching packets pass through unchanged. The function returns -1
// only on packet rewrite failures.
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

  if (have_tcp_flags)
    ct_observe_tcp(&ck, cv, tcp_flags);
  return 0;
}

static __always_inline int handle(struct __sk_buff *skb) {
  void *data = nat_skb_data(skb);
  void *data_end = nat_skb_data_end(skb);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  // Resolve the receiving Pod's Subnet (and thus VPC) so the conntrack
  // key matches the forward entry installed by pod_egress on this node.
  struct ifindex_subnet_key isk = {.ifindex = skb->ifindex};
  const struct ifindex_subnet_val *isv =
      bpf_map_lookup_elem(&ifindex_subnet, &isk);
  if (!isv)
    return TC_ACT_OK;

  struct subnet_key sk = {.subnet_id = isv->subnet_id};
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &sk);
  if (!subnet)
    return TC_ACT_OK;

  if (apply_reverse_snat(skb, subnet->vpc_id) < 0)
    return TC_ACT_SHOT;

  return TC_ACT_OK;
}

SEC("tc")
int tc_pod_ingress(struct __sk_buff *skb) { return handle(skb); }

char __license[] SEC("license") = "Dual MIT/GPL";
