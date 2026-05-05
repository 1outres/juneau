// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "ct.h"
#include "maps.h"
#include "nat.h"
#include "trace.h"

#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define IP_OFFSET 0x1FFF

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

static __always_inline int forward_l2(struct __sk_buff *skb, struct ethhdr *eth,
                                      __u32 subnet_id, __u32 trace_id) {
  struct fdb_key fk = {};
  fk.subnet_id = subnet_id;
  __builtin_memcpy(fk.mac, eth->h_dest, ETH_ALEN);
  const struct fdb_val *fv = bpf_map_lookup_elem(&fdb, &fk);
  if (!fv) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_FDB,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           subnet_id, subnet_id);
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                       subnet_id);
    return TC_ACT_SHOT;
  }

  if (fv->ifindex != 0) {
    trace_emit_redirect_l3(skb, trace_id, TRACE_REASON_REDIRECT_IFINDEX,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           subnet_id, fv->ifindex);
    return bpf_redirect(fv->ifindex, 0);
  }

  __u32 vx_key = 0;
  const __u32 *vx_if = bpf_map_lookup_elem(&vxlan_ifindex, &vx_key);
  if (!vx_if) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_FDB,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           subnet_id, 0);
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                       subnet_id);
    return TC_ACT_SHOT;
  }

  struct bpf_tunnel_key tkey = {};
  tkey.remote_ipv4 = fv->vtep_ip;
  tkey.tunnel_id = subnet_id;
  tkey.tunnel_ttl = 64;
  tkey.tunnel_tos = 0;

  if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0) {
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                       subnet_id);
    return TC_ACT_SHOT;
  }

  trace_emit_redirect_l3(skb, trace_id, TRACE_REASON_REDIRECT_VXLAN,
                         TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                         subnet_id, *vx_if);
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
                                       const struct nat_inside *nat,
                                       __u32 trace_id) {
  void *data;
  void *data_end;

  struct subnet_key sk = {
      .subnet_id = nat->subnet_id,
  };
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &sk);
  if (!subnet) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_SUBNET,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           nat->subnet_id, nat->subnet_id);
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                       nat->subnet_id);
    return TC_ACT_SHOT;
  }

  __be32 old_addr = iph->daddr;
  __be32 new_addr = bpf_htonl(nat->addr);
  __be32 saddr = iph->saddr;
  __u8 proto = iph->protocol;
  __be16 sport = 0, dport = 0;
  data_end = nat_skb_data_end(skb);
  trace_read_l4_ports(iph, data_end, &sport, &dport);

  struct arp_table_key ak = {
      .subnet_id = nat->subnet_id,
      .ipaddr = nat->addr,
  };
  const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
  if (!av) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_ARP,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           nat->subnet_id, nat->addr);
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                       nat->subnet_id);
    return TC_ACT_SHOT;
  }

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

  // Trace: 1:1 (ElasticIP) DNAT applied. before = (remote, EIP),
  // after = (remote, Pod IP).
  if (trace_id != 0) {
    struct trace_emit_args a = {0};
    a.trace_id = trace_id;
    a.reason = TRACE_REASON_DNAT_APPLIED;
    a.hook = TRACE_HOOK_NODE_INGRESS;
    a.ifindex = skb->ifindex;
    a.subnet_id = nat->subnet_id;
    a.scope = TRACE_SCOPE_HOST;
    a.proto = proto;
    a.verdict = TRACE_VERDICT_OK;
    a.saddr = saddr;
    a.daddr = old_addr;
    a.sport = sport;
    a.dport = dport;
    a.saddr2 = saddr;
    a.daddr2 = new_addr;
    a.sport2 = sport;
    a.dport2 = dport;
    trace_emit_full(&a);

    // Learn the post-NAT tuple under the destination Subnet's
    // VPC scope so subsequent VPC-scoped hooks (vxlan_ingress on
    // remote nodes / pod_ingress on this node) match. We don't
    // know the VPC ID here without an extra subnet_map lookup —
    // and we already have `subnet` above. Use subnet->vpc_id.
    struct trace_tuple_key ak = trace_make_key(
        TRACE_SCOPE_VPC, subnet->vpc_id, proto, saddr, new_addr, 0, dport);
    trace_learn_tuple(trace_id, &ak);
  }

  return forward_l2(skb, eth, nat->subnet_id, trace_id);
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
                                          struct ct_key *ck,
                                          __u32 trace_id) {
  void *data_end = nat_skb_data_end(skb);

  struct subnet_key sk = {.subnet_id = cv->next_subnet_id};
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &sk);
  if (!subnet) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_SUBNET,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           cv->next_subnet_id, cv->next_subnet_id);
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                       cv->next_subnet_id);
    return TC_ACT_SHOT;
  }

  struct arp_table_key ak = {
      .subnet_id = cv->next_subnet_id,
      .ipaddr = bpf_ntohl(cv->new_daddr),
  };
  const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
  if (!av) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_ARP,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           cv->next_subnet_id, bpf_ntohl(cv->new_daddr));
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                       cv->next_subnet_id);
    return TC_ACT_SHOT;
  }

  __u8 dst_mac[ETH_ALEN];
  __u8 src_mac[ETH_ALEN];
  __builtin_memcpy(dst_mac, av->mac, ETH_ALEN);
  __builtin_memcpy(src_mac, subnet->gw_mac, ETH_ALEN);

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  cv->last_seen_ns = bpf_ktime_get_ns();

  // Capture before/after tuple for the trace event.
  __be32 before_saddr = iph->saddr;
  __be32 before_daddr = iph->daddr;
  __be16 before_sport = ck->sport;
  __be16 before_dport = ck->dport;
  __u8   nat_proto    = iph->protocol;
  __be32 after_saddr  = cv->new_saddr ? cv->new_saddr : before_saddr;
  __be32 after_daddr  = cv->new_daddr;
  __be16 after_sport  = cv->new_sport ? cv->new_sport : before_sport;
  __be16 after_dport  = cv->new_dport ? cv->new_dport : before_dport;

  if (nat_apply_napt_in_rewrite(skb, cv) < 0)
    return TC_ACT_SHOT;

  // Trace: NAPT_IN reverse rewrite (or SVC_NAPT_IN).
  if (trace_id != 0) {
    struct trace_nat_event __ne = {
        .vpc_id = subnet->vpc_id,
        .subnet_id = cv->next_subnet_id,
        .hook = TRACE_HOOK_NODE_INGRESS,
        .reason = TRACE_REASON_REVERSE_NAT_APPLIED,
        .scope = TRACE_SCOPE_HOST,
        .proto = nat_proto,
        .before_saddr = before_saddr,
        .before_daddr = before_daddr,
        .before_sport = before_sport,
        .before_dport = before_dport,
        .after_saddr = after_saddr,
        .after_daddr = after_daddr,
        .after_sport = after_sport,
        .after_dport = after_dport,
    };
    trace_observe_nat(skb, &__ne);
  }

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

  return forward_l2(skb, eth, cv->next_subnet_id, trace_id);
}

static __always_inline int handle_l3(struct __sk_buff *skb, struct ethhdr *eth,
                                     __u32 trace_id) {
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
          return handle_napt_in(skb, eth, iph, cv, &ck, trace_id);
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
        return handle_napt_in(skb, eth, iph, cv, &ck, trace_id);
    }
  }

  struct nat_outside nk = {
      .addr = bpf_ntohl(iph->daddr),
  };
  const struct nat_inside *nv = bpf_map_lookup_elem(&nat_dnat_map, &nk);
  if (!nv) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_FIB_ROUTE,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0, 0,
                           bpf_ntohl(iph->daddr));
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0, 0);
    return TC_ACT_SHOT;
  }

  return handle_dnat(skb, eth, iph, nv, trace_id);
}

static __always_inline int handle_l2(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  // Hook-entry trace event. node_ingress sees pre-decap underlay
  // packets — the tuple is host-scoped (no vpc_id available yet);
  // VPC scope is added on the inner program (vxlan_ingress) after
  // tunnel decap.
  __u32 __trace_id = 0;
  {
    struct trace_hook_ctx __ctx = {
        .reason = TRACE_REASON_ENTER_NODE_INGRESS,
        .hook = TRACE_HOOK_NODE_INGRESS,
        .scope = TRACE_SCOPE_HOST,
    };
    __trace_id = trace_classify_and_emit_enter(skb, &__ctx);
  }

  return handle_l3(skb, eth, __trace_id);
}

SEC("tc")
int tc_node_ingress(struct __sk_buff *skb) {
  // See tc_pod_egress for why this anchor exists.
  (void)trace_is_active();
  return handle_l2(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
