// Service.type=LoadBalancer shared data-plane logic.
//
// Both node_ingress (external traffic landing on the underlay via BGP-
// ECMP) and vxlan_ingress (cross-Node owner redirection: a non-owner
// Node forwarded an LB packet to its Maglev-elected owner over VXLAN
// with VNI_UNDERLAY) need the same forward-leg behaviour: pick a
// backend, allocate a unique source port, install paired CT entries,
// rewrite L3/L4, and dispatch via fdb. Putting the logic in a header
// lets each program compilation unit inline its own copy — eBPF
// programs are compiled independently and cannot link to shared
// object files.
//
// PR-4-β intentionally moves the existing implementation verbatim
// (only the function name changes from `lb_forward_subprog` to
// `lb_forward`). Owner resolution is exposed as a stub here that
// always returns 0 ("no owner"); PR-4-δ replaces the body with a
// Maglev slot-table lookup against `lb_owner_table`, and PR-4-ε wires
// the redirect path in node_ingress / vxlan_ingress.
#ifndef JUNEAU_BPF_LB_H
#define JUNEAU_BPF_LB_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "ct.h"
#include "forward.h"
#include "maps.h"
#include "nat.h"
#include "trace.h"

#ifndef __juneau_bpf_subprog
#define __juneau_bpf_subprog __attribute__((noinline)) __attribute__((used))
#endif

#ifndef LB_ETH_ALEN
#define LB_ETH_ALEN 6
#endif

#ifndef LB_TC_ACT_SHOT
#define LB_TC_ACT_SHOT 2
#endif

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

// lb_resolve_owner returns the underlay IPv4 (network byte order) of
// the Node responsible for handling the supplied 5-tuple's flow under
// the cluster's current Maglev slot table, or 0 when no owner has been
// programmed (table not yet populated, or the slot is empty during a
// reconciler convergence).
//
// PR-4-β stub: always returns 0. Callers MUST treat 0 as "self / fall
// through to the local LB forward path", which preserves the original
// (always-self) behaviour until PR-4-δ replaces this body with a real
// `lb_owner_table` lookup against the BPF map populated by the
// LBOwner reconciler.
//
// Lookup signature, once implemented:
//   slot = hash_lb_tuple(saddr, daddr, sport, dport, proto) %
//          MAX_LB_OWNER_TABLE
//   owner_ip = lb_owner_table[slot]
//
// The lookup is intentionally kept identical to the backend-selection
// hash so a single hash computation per packet covers both the slot
// pick and (for owner-resident flows) the backend pick.
static __always_inline __be32 lb_resolve_owner(__be32 saddr, __be32 daddr,
                                                __be16 sport, __be16 dport,
                                                __u8 proto) {
  (void)saddr;
  (void)daddr;
  (void)sport;
  (void)dport;
  (void)proto;
  return 0;
}

// lb_forward implements the forward leg of a Service.type=LoadBalancer
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
// Compiled as a noinline BPF-to-BPF subprogram: inlining all of the LB
// forward + reverse paths into a single tc_* entry overflowed the
// verifier's branch-merge precision and caused "invalid size of
// register spill" once the function exceeded ~4k instructions.
// Subprograms get their own stack frame and verifier state, so the
// ctx() spill confusion goes away. Args are kept within the BPF
// 5-register limit (R1-R5) by re-deriving eth / iph / service_key /
// service_val / sport / dport from skb instead of taking them from
// the caller — callers in handle_l3 already validated all of these on
// the parent program's stack but the work is cheap and keeps the
// subprogram boundary clean.
static __juneau_bpf_subprog int
lb_forward(struct __sk_buff *skb, __u32 trace_id) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return LB_TC_ACT_SHOT;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return LB_TC_ACT_SHOT;
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return LB_TC_ACT_SHOT;

  __be16 sport, dport;
  if (nat_read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return LB_TC_ACT_SHOT;

  struct service_key sk = {
      .cluster_ip = bpf_ntohl(iph->daddr),
      .port = bpf_ntohs(dport),
      .proto = iph->protocol,
  };
  const struct service_val *sv = bpf_map_lookup_elem(&service_map, &sk);
  if (!sv || !(sv->flags & SVC_FLAG_LOAD_BALANCER))
    return LB_TC_ACT_SHOT;

  if (sv->backend_count == 0)
    return LB_TC_ACT_SHOT;

  // Resolve this node's underlay IP — used as the SNAT source so the
  // reverse leg routes back to this very node regardless of which Pod
  // (and thus which backend Node) the request was DNAT'd to.
  __u32 underlay_key = 0;
  const __u32 *underlay_ip_p =
      bpf_map_lookup_elem(&host_underlay, &underlay_key);
  if (!underlay_ip_p || *underlay_ip_p == 0)
    return LB_TC_ACT_SHOT;
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
    return LB_TC_ACT_SHOT;
  }

  // Host-network backends are not currently supported by the LB path.
  // They would need their own SNAT scheme (Node IP can't double as
  // both the LB SNAT source and the kernel-routed dst on the local
  // Node) — out of scope for v1.
  if (bv->kind != BACKEND_KIND_POD ||
      bv->backend_subnet_id == BACKEND_SUBNET_ID_UNDERLAY)
    return LB_TC_ACT_SHOT;

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
      return LB_TC_ACT_SHOT;

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
    return LB_TC_ACT_SHOT;
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
    return LB_TC_ACT_SHOT;
  }

  __u8 dst_mac[LB_ETH_ALEN];
  __u8 src_mac[LB_ETH_ALEN];
  __builtin_memcpy(dst_mac, bav->mac, LB_ETH_ALEN);
  __builtin_memcpy(src_mac, backend_subnet->gw_mac, LB_ETH_ALEN);

  __be32 before_saddr = client_saddr;
  __be32 before_daddr = vip_be;
  __be16 before_sport = sport;
  __be16 before_dport = dport;
  __u8 nat_proto = iph->protocol;

  if (nat_rewrite_ipv4_addr(skb, /*is_source=*/true, node_underlay_ip) < 0)
    return LB_TC_ACT_SHOT;
  if (nat_rewrite_l4_port(skb, /*is_source=*/true, alloc_port) < 0)
    return LB_TC_ACT_SHOT;
  if (nat_rewrite_ipv4_addr(skb, /*is_source=*/false, backend_addr_be) < 0)
    return LB_TC_ACT_SHOT;
  if (nat_rewrite_l4_port(skb, /*is_source=*/false, backend_port_be) < 0)
    return LB_TC_ACT_SHOT;

  // Re-derive packet pointers; the helpers above mutate skb in place
  // and our cached eth/iph pointers are no longer valid.
  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  eth = data;
  if ((void *)(eth + 1) > data_end)
    return LB_TC_ACT_SHOT;

  __builtin_memcpy(eth->h_dest, dst_mac, LB_ETH_ALEN);
  __builtin_memcpy(eth->h_source, src_mac, LB_ETH_ALEN);

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

#endif // JUNEAU_BPF_LB_H
