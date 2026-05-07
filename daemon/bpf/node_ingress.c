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

#define AF_INET 2

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
// napt_in_subprog handles the reverse leg of both SVC_NAPT_IN (Service
// host-network backend reply) and NAPT_IN (NATGateway reply) flows.
// The two paths share identical body; the caller in handle_l3 only
// differs in WHICH map lookups guard the dispatch (host_underlay vs
// bgp_address_pools). The subprogram re-derives eth / iph / ct_key
// from skb to keep its arg count within BPF's 5-register ceiling.
//
// Compiled as a noinline subprogram so its 100+ bytes of stack
// (subnet_key, arp_table_key, dst_mac, src_mac, trace_nat_event,
// locals) live in their own frame instead of bloating tc_node_ingress.
// Without this, the inlined contribution pushed the combined call
// chain that runs through lb_forward_subprog past the kernel's
// 512-byte ceiling.
static __juneau_bpf_subprog int
napt_in_subprog(struct __sk_buff *skb, __u32 trace_id) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return TC_ACT_SHOT;

  __be16 sport, dport;
  if (nat_read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return TC_ACT_SHOT;

  struct ct_key ck = {
      .scope = CT_SCOPE_HOST,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (!cv ||
      (cv->action != CT_ACTION_SVC_NAPT_IN && cv->action != CT_ACTION_NAPT_IN))
    return TC_ACT_SHOT;

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
  __be16 before_sport = ck.sport;
  __be16 before_dport = ck.dport;
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
    struct ct_val *cv2 = bpf_map_lookup_elem(&ct_map, &ck);
    if (cv2)
      ct_observe_tcp(&ck, cv2, tcp_flags);
  }

  // Re-derive packet pointers and rewrite L2.
  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

  return forward_l2(skb, eth, cv->next_subnet_id, trace_id);
}

// lb_napt_in_subprog is the reverse leg of a Service.type=LoadBalancer
// flow: a backend Pod's reply has been routed (via the underlay) back
// to this node's underlay IP and matched the LB_IN ct_map entry the
// forward leg installed. We rewrite saddr (→ VIP), daddr (→ original
// external client), sport (→ LB port) and dport (→ original client
// port), then hand the packet to the kernel's main FIB so it leaves
// via the upstream router. fdb-style forwarding is not applicable
// here because the destination is outside the cluster fabric.
//
// Compiled as a noinline BPF-to-BPF subprogram (see __juneau_bpf_subprog
// in trace.h). Inlining all of LB forward + reverse paths into
// tc_node_ingress overflowed the verifier's branch-merge precision and
// caused "invalid size of register spill" once the function exceeded
// ~4k instructions. Subprograms get their own stack frame and verifier
// state, so the ctx() spill confusion goes away. Args are kept within
// the BPF 5-register limit (R1-R5) by re-deriving eth / iph / ct_key
// from skb instead of taking them from the caller — callers in
// handle_l3 already validated all of these on the parent program's
// stack but the work is cheap and keeps the subprogram boundary clean.
static __juneau_bpf_subprog int
lb_napt_in_subprog(struct __sk_buff *skb, __u32 trace_id) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return TC_ACT_SHOT;

  __be16 sport, dport;
  if (nat_read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return TC_ACT_SHOT;

  struct ct_key ck = {
      .scope = CT_SCOPE_HOST,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (!cv || cv->action != CT_ACTION_LB_IN)
    return TC_ACT_SHOT;

  __be32 before_saddr = iph->saddr;
  __be32 before_daddr = iph->daddr;
  __be16 before_sport = ck.sport;
  __be16 before_dport = ck.dport;
  __u8 nat_proto = iph->protocol;
  __be32 after_saddr = cv->new_saddr;
  __be32 after_daddr = cv->new_daddr;
  __be16 after_sport = cv->new_sport;
  __be16 after_dport = cv->new_dport;

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, nat_skb_data_end(skb), &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  cv->last_seen_ns = bpf_ktime_get_ns();

  if (nat_apply_napt_in_rewrite(skb, cv) < 0)
    return TC_ACT_SHOT;

  if (trace_id != 0) {
    struct trace_nat_event __ne = {
        .vpc_id = 0,
        .subnet_id = 0,
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
    struct ct_val *cv2 = bpf_map_lookup_elem(&ct_map, &ck);
    if (cv2)
      ct_observe_tcp(&ck, cv2, tcp_flags);
  }

  // Re-derive packet pointers; the rewrites above mutated skb in place
  // and the kernel FIB lookup needs a fresh iph.
  struct iphdr *new_iph = nat_load_iph(skb);
  if (!new_iph)
    return TC_ACT_SHOT;

  // Hand to the kernel FIB to reach the external client over the
  // upstream-facing interface. BPF_FIB_LKUP_RET_NO_NEIGH means the
  // kernel will need to ARP for the next-hop; TC_ACT_OK lets the
  // host stack handle that synchronously rather than dropping.
  struct bpf_fib_lookup fib_params = {};
  fib_params.family = AF_INET;
  fib_params.l4_protocol = new_iph->protocol;
  fib_params.ipv4_dst = new_iph->daddr;
  fib_params.ifindex = skb->ifindex;

  long rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
  if (rc == BPF_FIB_LKUP_RET_NO_NEIGH)
    return TC_ACT_OK;
  if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0, 0);
    return TC_ACT_SHOT;
  }

  if (bpf_skb_store_bytes(skb, __builtin_offsetof(struct ethhdr, h_dest),
                          fib_params.dmac, ETH_ALEN, 0) < 0)
    return TC_ACT_SHOT;
  if (bpf_skb_store_bytes(skb, __builtin_offsetof(struct ethhdr, h_source),
                          fib_params.smac, ETH_ALEN, 0) < 0)
    return TC_ACT_SHOT;

  if (trace_id != 0) {
    trace_emit_redirect_l3(skb, trace_id, TRACE_REASON_REDIRECT_IFINDEX,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           0, fib_params.ifindex);
  }
  return bpf_redirect(fib_params.ifindex, 0);
}

// LB_PORT_PROBE_LIMIT bounds the linear-probe loop used to claim a
// previously-unused source port for the LB SNAT rewrite. Mirrors the
// NAPT_PROBE_LIMIT in pod_egress.c — 8 attempts is plenty for normal
// connection rates while keeping the verifier instruction budget low.
#define LB_PORT_PROBE_LIMIT 8

// hash_lb_tuple mixes the 5-tuple into a 32-bit value used both as the
// backend index seed and the source-port probe seed. The bit-mixing is
// the same Murmur-style finaliser pod_egress uses; we duplicate it here
// rather than pull pod_egress.c into the include graph (the two
// programs are intentionally compiled independently).
static __always_inline __u32 hash_lb_tuple(__be32 saddr, __be32 daddr,
                                            __be16 sport, __be16 dport,
                                            __u8 proto) {
  __u32 h = bpf_ntohl(saddr) ^ bpf_ntohl(daddr) ^
            ((__u32)bpf_ntohs(sport) << 16) ^ (__u32)bpf_ntohs(dport) ^
            ((__u32)proto << 24);
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

static __always_inline __u32 lb_rotate_left(__u32 x, __u32 r) {
  return (x << r) | (x >> (32 - r));
}

// lb_forward_subprog implements the forward leg of a Service.type=LoadBalancer
// flow. The packet has already been classified as a known LB VIP (hit
// in service_map with SVC_FLAG_LOAD_BALANCER set) by the caller. We
// pick a backend by hashing the 5-tuple, allocate a previously-unused
// source port via NAPT-style linear probing of the reverse CT key,
// install paired forward (LB_OUT) and reverse (LB_IN) ct_map entries
// in the HOST scope, then rewrite both the destination (→ backend Pod)
// and the source (→ this node's underlay IP at the alloc_port) before
// forwarding via fdb to the backend's Subnet (local Pod or
// VXLAN-tunnelled remote Pod).
//
// The reverse leg's reply addresses NodeA_underlay; on Node A's
// node_ingress the LB_IN match in the existing host_underlay branch
// reverses the rewrites and bpf_redirects out to the upstream router.
//
// LB v1 deliberately ignores SVC_FLAG_HAS_ACL: the per-Vpc consumer
// ACL is meaningless for external traffic that has no caller VPC.
// HOST_LOCAL / HOST_REMOTE backends are out of scope for LB v1; only
// Pod-backed Services are accepted (host-network LB delivery would
// need a different SNAT path and is not yet wired).
//
// Compiled as a noinline BPF-to-BPF subprogram for the same reason as
// lb_napt_in_subprog above. Args are limited to skb + trace_id; eth /
// iph / service_key / service_val / sport / dport are re-derived
// inside, which is cheap (a few packet header reads + one map lookup)
// and keeps the call site within BPF's 5-register limit.
static __juneau_bpf_subprog int
lb_forward_subprog(struct __sk_buff *skb, __u32 trace_id) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return TC_ACT_SHOT;

  __be16 sport, dport;
  if (nat_read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return TC_ACT_SHOT;

  struct service_key sk = {
      .cluster_ip = bpf_ntohl(iph->daddr),
      .port = bpf_ntohs(dport),
      .proto = iph->protocol,
  };
  const struct service_val *sv = bpf_map_lookup_elem(&service_map, &sk);
  if (!sv || !(sv->flags & SVC_FLAG_LOAD_BALANCER))
    return TC_ACT_SHOT;

  if (sv->backend_count == 0)
    return TC_ACT_SHOT;

  // Resolve this node's underlay IP — used as the SNAT source so the
  // reverse leg routes back to this very node regardless of which Pod
  // (and thus which backend Node) the request was DNAT'd to.
  __u32 underlay_key = 0;
  const __u32 *underlay_ip_p =
      bpf_map_lookup_elem(&host_underlay, &underlay_key);
  if (!underlay_ip_p || *underlay_ip_p == 0)
    return TC_ACT_SHOT;
  __be32 node_underlay_ip = *underlay_ip_p;

  // Stateless 5-tuple backend selection. LB does not honour
  // sessionAffinity=ClientIP in v1 — adding it requires extending
  // service_affinity_map writes here too, which is straightforward
  // but increases verifier load; defer to a follow-up.
  __u32 idx = hash_lb_tuple(iph->saddr, iph->daddr, sport, dport,
                             iph->protocol) %
              sv->backend_count;

  struct backend_key bk = {
      .cluster_ip = sk.cluster_ip,
      .port = sk.port,
      .proto = sk.proto,
      .index = idx,
  };
  const struct backend_val *bv = bpf_map_lookup_elem(&backend_map, &bk);
  if (!bv) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_BACKEND,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           0, idx);
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0, 0);
    return TC_ACT_SHOT;
  }

  // Host-network backends are not currently supported by the LB path.
  // They would need their own SNAT scheme (Node IP can't double as
  // both the LB SNAT source and the kernel-routed dst on the local
  // Node) — out of scope for v1.
  if (bv->kind != BACKEND_KIND_POD ||
      bv->backend_subnet_id == BACKEND_SUBNET_ID_UNDERLAY)
    return TC_ACT_SHOT;

  __be32 backend_addr_be = bpf_htonl(bv->backend_ip);
  __be16 backend_port_be = bpf_htons(bv->backend_port);
  __be32 client_saddr = iph->saddr;
  __be32 vip_be = iph->daddr;

  __u8 init_flags = 0;
  __u8 init_state = CT_STATE_ESTABLISHED;
  if (iph->protocol == IPPROTO_TCP) {
    __u8 f;
    if (ct_read_tcp_flags(iph, nat_skb_data_end(skb), &f) == 0) {
      init_flags = f & TCP_FLAG_TRACKED;
      init_state = ct_initial_state_for_syn(f);
    }
  }

  __u64 now = bpf_ktime_get_ns();

  // Forward CT key: (HOST, client, VIP, sport, lb_port). Action=LB_OUT
  // — though node_ingress doesn't itself look up CT_ACTION_LB_OUT
  // entries on subsequent packets (service_map remains the entry
  // point), the forward CT entry is still useful as a flow record for
  // GC / observability and for keeping per-flow state symmetric with
  // SVC_NAPT_OUT.
  struct ct_key fwd_key = {
      .scope = CT_SCOPE_HOST,
      .saddr = client_saddr,
      .daddr = vip_be,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };

  // If we've already seen this client tuple before, reuse the same
  // alloc_port so retransmits land on the same reverse CT entry. This
  // mirrors handle_service_host_remote.
  struct ct_val *existing = bpf_map_lookup_elem(&ct_map, &fwd_key);
  __be16 alloc_port = 0;
  if (existing && existing->action == CT_ACTION_LB_OUT) {
    existing->last_seen_ns = now;
    alloc_port = existing->new_sport;
  } else {
    __u32 seed = hash_lb_tuple(client_saddr, vip_be, sport, dport,
                                iph->protocol);
    bool installed = false;

    // Intentionally NOT unrolled: ct_key/ct_val are block-locals on the
    // subprogram's stack and unrolling forces the compiler to allocate
    // a fresh slot per iteration, which over LB_PORT_PROBE_LIMIT
    // iterations pushes the combined call-chain stack past the kernel's
    // 512-byte ceiling. The kernel's bounded-loop support (5.3+)
    // verifies the compact form fine.
    for (int i = 0; i < LB_PORT_PROBE_LIMIT; i++) {
      __u32 candidate_host = 1024 + ((seed + i) % (65536 - 1024));
      __be16 candidate = bpf_htons((__u16)candidate_host);

      struct ct_key rev_key = {
          .scope = CT_SCOPE_HOST,
          .saddr = backend_addr_be,
          .daddr = node_underlay_ip,
          .sport = backend_port_be,
          .dport = candidate,
          .proto = iph->protocol,
      };
      struct ct_val rev_val = {
          .new_saddr = vip_be,
          .new_daddr = client_saddr,
          .new_sport = dport,
          .new_dport = sport,
          .next_subnet_id = 0,
          .action = CT_ACTION_LB_IN,
          .state = init_state,
          .flags_seen = 0,
          .last_seen_ns = now,
      };
      long rc =
          bpf_map_update_elem(&ct_map, &rev_key, &rev_val, BPF_NOEXIST);
      if (rc == 0) {
        alloc_port = candidate;
        installed = true;
        break;
      }
      seed = lb_rotate_left(seed + 0x9e3779b1, 7);
    }
    if (!installed)
      return TC_ACT_SHOT;

    struct ct_val fwd_val = {
        .new_saddr = node_underlay_ip,
        .new_daddr = backend_addr_be,
        .new_sport = alloc_port,
        .new_dport = backend_port_be,
        .next_subnet_id = bv->backend_subnet_id,
        .action = CT_ACTION_LB_OUT,
        .state = init_state,
        .flags_seen = init_flags,
        .last_seen_ns = now,
    };
    bpf_map_update_elem(&ct_map, &fwd_key, &fwd_val, BPF_ANY);
  }

  // Resolve backend Pod's MAC via arp_table and the backend Subnet's
  // gw_mac via subnet_map so the L2 rewrite can land on the right
  // veth (or be encap-tunnelled to a remote Node by forward_l2).
  struct subnet_key bsk = {.subnet_id = bv->backend_subnet_id};
  const struct subnet_val *backend_subnet =
      bpf_map_lookup_elem(&subnet_map, &bsk);
  if (!backend_subnet) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_SUBNET,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           bv->backend_subnet_id, bv->backend_subnet_id);
    return TC_ACT_SHOT;
  }

  struct arp_table_key bak = {
      .subnet_id = bv->backend_subnet_id,
      .ipaddr = bv->backend_ip,
  };
  const struct arp_table_val *bav = bpf_map_lookup_elem(&arp_table, &bak);
  if (!bav) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_ARP,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           bv->backend_subnet_id, bv->backend_ip);
    return TC_ACT_SHOT;
  }

  __u8 dst_mac[ETH_ALEN];
  __u8 src_mac[ETH_ALEN];
  __builtin_memcpy(dst_mac, bav->mac, ETH_ALEN);
  __builtin_memcpy(src_mac, backend_subnet->gw_mac, ETH_ALEN);

  __be32 before_saddr = client_saddr;
  __be32 before_daddr = vip_be;
  __be16 before_sport = sport;
  __be16 before_dport = dport;
  __u8 nat_proto = iph->protocol;

  if (nat_rewrite_ipv4_addr(skb, /*is_source=*/true, node_underlay_ip) < 0)
    return TC_ACT_SHOT;
  if (nat_rewrite_l4_port(skb, /*is_source=*/true, alloc_port) < 0)
    return TC_ACT_SHOT;
  if (nat_rewrite_ipv4_addr(skb, /*is_source=*/false, backend_addr_be) < 0)
    return TC_ACT_SHOT;
  if (nat_rewrite_l4_port(skb, /*is_source=*/false, backend_port_be) < 0)
    return TC_ACT_SHOT;

  // Re-derive packet pointers; the helpers above mutate skb in place
  // and our cached eth/iph pointers are no longer valid.
  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

  // Trace: LB DNAT+SNAT applied. Both addresses change so we encode
  // the full before/after tuple.
  if (trace_id != 0) {
    struct trace_nat_event __ne = {
        .vpc_id = backend_subnet->vpc_id,
        .subnet_id = bv->backend_subnet_id,
        .hook = TRACE_HOOK_NODE_INGRESS,
        .reason = TRACE_REASON_DNAT_APPLIED,
        .scope = TRACE_SCOPE_HOST,
        .proto = nat_proto,
        .before_saddr = before_saddr,
        .before_daddr = before_daddr,
        .before_sport = before_sport,
        .before_dport = before_dport,
        .after_saddr = node_underlay_ip,
        .after_daddr = backend_addr_be,
        .after_sport = alloc_port,
        .after_dport = backend_port_be,
    };
    trace_observe_nat(skb, &__ne);
  }

  return forward_l2(skb, eth, bv->backend_subnet_id, trace_id);
}

static __always_inline int handle_l3(struct __sk_buff *skb, struct ethhdr *eth,
                                     __u32 trace_id) {
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  // Packets destined to this node's underlay IP may be the response
  // leg of a host-network Service NAPT flow (CT_ACTION_SVC_NAPT_IN),
  // a NATGateway NAPT flow (CT_ACTION_NAPT_IN with the host_napt_ip
  // collapsed onto the underlay IP), or a Service.type=LoadBalancer
  // reverse leg (CT_ACTION_LB_IN). Try the CT match first; on miss,
  // fall through to bgp_address_pools so deployments where
  // host_napt_ip and the node's underlay IP coincide still recover
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
          return napt_in_subprog(skb, trace_id);
        if (cv && cv->action == CT_ACTION_LB_IN)
          return lb_napt_in_subprog(skb, trace_id);
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
        return napt_in_subprog(skb, trace_id);
    }

    // Service.type=LoadBalancer entry point: the VIP lives inside an
    // advertised AddressPool prefix so we got past bgp_address_pools.
    // Look it up in service_map; only entries flagged LOAD_BALANCER
    // accept external traffic — ClusterIP / externalIPs entries
    // sharing the same map must not.
    struct service_key sk = {
        .cluster_ip = bpf_ntohl(iph->daddr),
        .port = bpf_ntohs(dport),
        .proto = iph->protocol,
    };
    const struct service_val *sv = bpf_map_lookup_elem(&service_map, &sk);
    if (sv && (sv->flags & SVC_FLAG_LOAD_BALANCER))
      return lb_forward_subprog(skb, trace_id);
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
