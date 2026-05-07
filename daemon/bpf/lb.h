// Service LoadBalancer (type=LoadBalancer) data-plane helpers.
//
// The Phase 7 LoadBalancer surface is intentionally separate from the
// existing ClusterIP service path:
//   * lb_service_map / lb_backend_map are dedicated maps written by
//     the userspace LoadBalancer reconciler;
//   * CT_ACTION_LB_DNAT / CT_ACTION_LB_REV_NAT mark the forward and
//     reverse legs in the shared ct_map;
//   * source-preserving design: the external client IP is never
//     rewritten on the forward leg and is restored on the reverse
//     leg by saddr/sport rewrite.
//
// Includes maps.h, ct.h, nat.h transitively.
#ifndef JUNEAU_BPF_LB_H
#define JUNEAU_BPF_LB_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "ct.h"
#include "maps.h"
#include "nat.h"

// lb_select_backend chooses a backend index deterministically from
// the 5-tuple. Connection stability is provided by ct_map (the chosen
// index is captured in the forward CT entry on the SYN), so the hash
// only needs to be a stable function of the tuple — no Maglev / etc.
// is required for Phase 7.
static __always_inline __u32 lb_select_backend(__be32 saddr, __be32 daddr,
                                               __be16 sport, __be16 dport,
                                               __u8 proto, __u32 backend_count) {
  if (backend_count == 0)
    return 0;
  __u32 h = bpf_ntohl(saddr);
  h = h * 31 + bpf_ntohl(daddr);
  h = h * 31 + (__u32)bpf_ntohs(sport);
  h = h * 31 + (__u32)bpf_ntohs(dport);
  h = h * 31 + (__u32)proto;
  return h % backend_count;
}

// lb_lookup_service is a thin wrapper around bpf_map_lookup_elem on
// lb_service_map. Returns the value or NULL.
static __always_inline struct lb_service_val *
lb_lookup_service(__be32 vip, __u16 port_host, __u8 proto) {
  struct lb_service_key key = {
      .vip = vip,
      .port = port_host,
      .proto = proto,
  };
  return bpf_map_lookup_elem(&lb_service_map, &key);
}

// lb_lookup_backend reads lb_backend_map for a particular index.
// Returns the value or NULL when the index does not exist (race
// against a concurrent reconcile that shrunk backend_count).
static __always_inline struct lb_backend_val *
lb_lookup_backend(__be32 vip, __u16 port_host, __u8 proto, __u32 index) {
  struct lb_backend_key bkey = {
      .vip = vip,
      .port = port_host,
      .proto = proto,
      .index = index,
  };
  return bpf_map_lookup_elem(&lb_backend_map, &bkey);
}

// lb_install_ct installs a paired CT entry set for the LB flow.
//
//   * fwd: scope=CT_SCOPE_HOST, key=(client → VIP), action=LB_DNAT
//          rewrite: daddr=backend_ip, dport=backend_port,
//          next_subnet_id=backend's Subnet (for forward_l2 dispatch).
//   * rev: scope=backend_vpc_id, key=(backend → client),
//          action=LB_REV_NAT, rewrite: saddr=VIP, sport=svc_port,
//          next_subnet_id=0 (no L2 redispatch — the host stack /
//          underlay handles it).
//
// Uses BPF_NOEXIST to avoid clobbering an existing entry installed
// by a concurrent SYN; the existing entry is correct because the
// backend selection is deterministic on the tuple.
static __always_inline void lb_install_ct(__be32 client_addr, __be32 vip,
                                          __be16 client_port, __be16 svc_port,
                                          __be32 backend_addr, __be16 backend_port,
                                          __u8 proto, __u32 backend_subnet_id,
                                          __u32 backend_vpc_id) {
  __u64 now = bpf_ktime_get_ns();

  struct ct_key fwd_key = {
      .scope = CT_SCOPE_HOST,
      .saddr = client_addr,
      .daddr = vip,
      .sport = client_port,
      .dport = svc_port,
      .proto = proto,
  };
  struct ct_val fwd_val = {
      .new_saddr = client_addr,
      .new_daddr = backend_addr,
      .new_sport = client_port,
      .new_dport = backend_port,
      .next_subnet_id = backend_subnet_id,
      .action = CT_ACTION_LB_DNAT,
      .state = CT_STATE_NEW,
      .flags_seen = 0,
      .last_seen_ns = now,
  };
  bpf_map_update_elem(&ct_map, &fwd_key, &fwd_val, BPF_NOEXIST);

  struct ct_key rev_key = {
      .scope = backend_vpc_id,
      .saddr = backend_addr,
      .daddr = client_addr,
      .sport = backend_port,
      .dport = client_port,
      .proto = proto,
  };
  struct ct_val rev_val = {
      .new_saddr = vip,
      .new_daddr = client_addr,
      .new_sport = svc_port,
      .new_dport = client_port,
      .next_subnet_id = 0,
      .action = CT_ACTION_LB_REV_NAT,
      .state = CT_STATE_NEW,
      .flags_seen = 0,
      .last_seen_ns = now,
  };
  bpf_map_update_elem(&ct_map, &rev_key, &rev_val, BPF_NOEXIST);
}

#endif // JUNEAU_BPF_LB_H
