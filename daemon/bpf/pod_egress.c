// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "arp.h"
#include "ct.h"
#include "lb.h"
#include "maps.h"
#include "nat.h"
#include "sg.h"
#include "policy.h"
#include "trace.h"

// uapi/linux/if_packet.h pkt_type values. vmlinux.h does not export
// these as enums, and we only need PACKET_HOST so define it locally.
#ifndef PACKET_HOST
#define PACKET_HOST 0
#endif

#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define IP_OFFSET 0x1FFF

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define AF_INET 2

// Per-CPU scratch slot for transient trace_nat_event allocations
// inside __juneau_bpf_subprog helpers. Subprograms have an
// independent stack frame and the chain `tc_pod_egress → subprog`
// must stay under the 512-byte combined-stack ceiling; hosting the
// 36-byte trace_nat_event off-stack keeps that headroom intact. One
// entry is enough because each invocation runs to completion before
// the same CPU can reenter the program (BPF tasks do not preempt).
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct trace_nat_event);
} pod_egress_nat_scratch SEC(".maps");

// Per-CPU scratch for the Service lookup/backend trace_emit_args. A
// 56-byte struct on tc_pod_egress's stack pushed the deepest call
// chains (tc_pod_egress → classify / policy subprograms) past the
// 512-byte combined-stack ceiling on kernel 6.12. Staging it in a
// per-CPU slot keeps it out of the host program's frame. Mirrors
// pod_egress_nat_scratch.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct trace_emit_args);
} pod_egress_emit_scratch SEC(".maps");

// Service-related helpers (load_iph, read_l4_ports, rewrite_ipv4_addr,
// rewrite_l4_port, update_l4_csum) live in nat.h so vxlan_ingress.c can
// share them. The aliases below keep the local call sites in this file
// short.
#define load_iph nat_load_iph
#define read_l4_ports nat_read_l4_ports
#define read_napt_ports nat_read_napt_ports
#define rewrite_ipv4_addr nat_rewrite_ipv4_addr
#define rewrite_l4_port nat_rewrite_l4_port
#define skb_data_end nat_skb_data_end

// forward_via_host_fib hands the packet to the host network stack: it
// resolves the next hop with a kernel FIB lookup, writes the resolved
// MAC pair, and redirects to the egress interface. Callers that already
// finished their rewrite and target something outside every VPC end
// here. On success out_ifindex receives the egress interface, so a
// caller can name it in a trace event without repeating the lookup.
//
// The lookup is ingress-style (no BPF_FIB_LOOKUP_OUTPUT): the OUTPUT
// flag would pin oif to the Pod veth ifindex, against which no route
// exists. Ingress-style lets the kernel pick the egress interface from
// the FIB. Resolving at runtime also keeps BGP-learned peers,
// multi-uplink hosts and L2-adjacent peers working, which fixing the MAC
// to the default gateway at daemon start would not.
//
// When the route is known but the neighbor is not resolved yet, the
// packet leaves through bpf_redirect_neigh() instead. That hands it to
// the kernel neighbor subsystem, which sends the ARP request and holds
// the packet until the reply arrives. Returning TC_ACT_OK here would
// not work: the Pod addressed the frame to the synthetic Subnet gateway
// MAC, so skb->pkt_type is PACKET_OTHERHOST and ip_rcv_core drops the
// packet before routing. No ARP would ever be sent and the flow would
// never recover.
static __juneau_bpf_subprog int forward_via_host_fib(struct __sk_buff *skb,
                                                     __u32 *out_ifindex) {
  struct iphdr *iph = load_iph(skb);
  if (!iph)
    return TC_ACT_SHOT;

  struct bpf_fib_lookup fib_params = {};
  fib_params.family = AF_INET;
  fib_params.l4_protocol = iph->protocol;
  fib_params.ipv4_dst = iph->daddr;
  fib_params.ifindex = skb->ifindex;

  long rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
  if (rc != BPF_FIB_LKUP_RET_SUCCESS && rc != BPF_FIB_LKUP_RET_NO_NEIGH)
    return TC_ACT_SHOT;

  *out_ifindex = fib_params.ifindex;

  if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
    // bpf_fib_lookup overwrites ipv4_dst with the next hop before it
    // looks the neighbor up, so passing it on saves a second route
    // lookup in the kernel.
    struct bpf_redir_neigh nh = {
        .nh_family = AF_INET,
        .ipv4_nh = fib_params.ipv4_dst,
    };
    return bpf_redirect_neigh(fib_params.ifindex, &nh, sizeof(nh), 0);
  }

  if (bpf_skb_store_bytes(skb, __builtin_offsetof(struct ethhdr, h_dest),
                          fib_params.dmac, ETH_ALEN, 0) < 0)
    return TC_ACT_SHOT;
  if (bpf_skb_store_bytes(skb, __builtin_offsetof(struct ethhdr, h_source),
                          fib_params.smac, ETH_ALEN, 0) < 0)
    return TC_ACT_SHOT;

  return bpf_redirect(fib_params.ifindex, 0);
}

static __always_inline int update_l4_csum(struct __sk_buff *skb,
                                          struct iphdr *iph, void *data_end,
                                          __be32 old_addr, __be32 new_addr) {
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

// snat_icmp_quote_fixup repairs the copy an outbound ICMP error message
// carries. The outer source is what a 1:1 SNAT translates, so the copy
// needs its destination repaired. See nat_icmp_quote_fixup_1to1 for the
// return values and for why this is a subprogram.
static __juneau_bpf_subprog int snat_icmp_quote_fixup(struct __sk_buff *skb,
                                                      __be32 old_addr,
                                                      __be32 new_addr) {
  return nat_icmp_quote_fixup_1to1(skb, /*outer_is_source=*/true, old_addr,
                                   new_addr);
}

static __always_inline int handle_snat(struct __sk_buff *skb,
                                       struct ethhdr *eth, struct iphdr *iph) {
  void *data;
  void *data_end;

  struct ifindex_subnet_key isk = {
      .ifindex = skb->ifindex,
  };
  const struct ifindex_subnet_val *isv =
      bpf_map_lookup_elem(&ifindex_subnet, &isk);
  if (!isv)
    return TC_ACT_SHOT;

  struct nat_inside nk = {
      .subnet_id = isv->subnet_id,
      .addr = bpf_ntohl(iph->saddr),
  };
  const struct nat_outside *nv = bpf_map_lookup_elem(&nat_snat_map, &nk);
  if (!nv)
    return TC_ACT_SHOT;

  __be32 old_addr = iph->saddr;
  __be32 new_addr = bpf_htonl(nv->addr);

  // An ICMP error message the Pod raises quotes the packet the peer
  // sent, so the Pod's address sits in the quoted destination. The peer
  // finds the socket to report to from that quoted tuple alone, which is
  // why the outer rewrite below is not enough.
  int icmp_rc = snat_icmp_quote_fixup(skb, old_addr, new_addr);
  if (icmp_rc < 0)
    return TC_ACT_SHOT;
  bool icmp_error = icmp_rc > 0;

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

  if (bpf_skb_store_bytes(skb,
                          sizeof(struct ethhdr) +
                              __builtin_offsetof(struct iphdr, saddr),
                          &new_addr, sizeof(new_addr), 0) < 0)
    return TC_ACT_SHOT;

  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;

  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  // Trace: 1:1 SNAT applied (ElasticIP egress). Reads ports best-
  // effort; for ICMP they stay 0.
  {
    __be16 sport = 0, dport = 0;
    trace_read_l4_ports(iph, data_end, &sport, &dport);
    struct trace_nat_event __ne = {
        .vpc_id = isv->subnet_id ? 0 : 0,  // unknown; lookup uses subnet_id below
        .subnet_id = isv->subnet_id,
        .hook = TRACE_HOOK_POD_EGRESS,
        .reason = icmp_error ? TRACE_REASON_ICMP_ERROR_TRANSLATED
                             : TRACE_REASON_SNAT_APPLIED,
        .scope = TRACE_SCOPE_HOST,
        .proto = iph->protocol,
        .before_saddr = old_addr,
        .before_daddr = iph->daddr,
        .before_sport = sport,
        .before_dport = dport,
        .after_saddr = new_addr,
        .after_daddr = iph->daddr,
        .after_sport = sport,
        .after_dport = dport,
    };
    trace_observe_nat(skb, &__ne);
  }

  __u32 egress_ifindex = 0;
  return forward_via_host_fib(skb, &egress_ifindex);
}

static __always_inline int handle_arp(struct __sk_buff *skb, void *data_end,
                                      struct ethhdr *eth, __u32 subnet_id,
                                      const struct subnet_val *subnet) {
  struct arp_request req;
  if (arp_parse_request(data_end, eth, &req) != 0)
    return TC_ACT_SHOT;

  __u32 gw_addr = subnet->gw_addr;
  __u32 mask = subnet->mask;

  if ((req.target_addr & mask) != (gw_addr & mask))
    return TC_ACT_SHOT;

  __u8 responder_mac[ETH_ALEN];
  if (req.target_addr == gw_addr) {
    __builtin_memcpy(responder_mac, subnet->gw_mac, ETH_ALEN);
  } else {
    struct arp_table_key ak = {
        .subnet_id = subnet_id,
        .ipaddr = req.target_addr,
    };
    const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
    if (!av)
      return TC_ACT_SHOT;
    __builtin_memcpy(responder_mac, av->mac, ETH_ALEN);
  }

  arp_rewrite_to_reply(eth, &req, responder_mac);
  return bpf_redirect(skb->ifindex, 0);
}

static __always_inline int forward_l2(struct __sk_buff *skb, struct ethhdr *eth,
                                      __u32 vpc_id, __u32 subnet_id) {
  // Re-derive trace_id at this site rather than threading through the
  // call chain. Cheap when no session is active (single map lookup).
  // Earlier this passed vpc_id=0 which silently missed the trace tuple
  // (registered with the source Pod's vpc_id), suppressing every
  // FDB / REDIRECT / DROP emit on the success path.
  __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, vpc_id);
  struct fdb_key fk = {};
  fk.subnet_id = subnet_id;
  __builtin_memcpy(fk.mac, eth->h_dest, ETH_ALEN);
  const struct fdb_val *fv = bpf_map_lookup_elem(&fdb, &fk);
  if (!fv) {
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_FDB,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id,
                           subnet_id, subnet_id);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id,
                       subnet_id);
    return TC_ACT_SHOT;
  }

  if (fv->ifindex != 0) {
    trace_emit_redirect_l3(skb, __tid, TRACE_REASON_REDIRECT_IFINDEX,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id,
                           subnet_id, fv->ifindex);
    return bpf_redirect(fv->ifindex, 0);
  }

  __u32 vx_key = 0;
  const __u32 *vx_if = bpf_map_lookup_elem(&vxlan_ifindex, &vx_key);
  if (!vx_if) {
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id,
                       subnet_id);
    return TC_ACT_SHOT;
  }

  struct bpf_tunnel_key tkey = {};
  tkey.remote_ipv4 = fv->vtep_ip;
  tkey.tunnel_id = subnet_id;
  tkey.tunnel_ttl = 64;
  tkey.tunnel_tos = 0;

  if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0) {
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id,
                       subnet_id);
    return TC_ACT_SHOT;
  }

  trace_emit_redirect_l3(skb, __tid, TRACE_REASON_REDIRECT_VXLAN,
                         TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id,
                         subnet_id, *vx_if);
  return bpf_redirect(*vx_if, 0);
}

// hash_tuple folds a 5-tuple into a 32-bit value used to spread requests
// evenly across backends. Mixing constants are arbitrary; the only
// requirement is decent diffusion of low-order bits.
static __always_inline __u32 hash_tuple(__be32 saddr, __be32 daddr,
                                        __be16 sport, __be16 dport,
                                        __u8 proto) {
  __u32 h = bpf_ntohl(saddr);
  h ^= bpf_ntohl(daddr) * 0x9e3779b1;
  h ^= ((__u32)bpf_ntohs(sport) << 16) | bpf_ntohs(dport);
  h ^= (__u32)proto * 0x85ebca6b;
  h ^= h >> 16;
  return h;
}

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000ULL
#endif

// select_backend_index is the single decision point for "given a
// Service hit, which backend index should this packet go to". It
// always defaults to the stateless 5-tuple hash; when
// SVC_FLAG_AFFINITY_CLIENT_IP is set on the Service it consults
// service_affinity_map for a sticky decision keyed by caller IP.
//
// Stale or out-of-range cached entries are silently re-selected:
// - backend_gen mismatch: backend set was rewritten; index may now
//   point past the new backend_count or to a different Pod.
// - backend_index >= backend_count: same as above, defensive bound.
// - expires_at_ns elapsed: timeout, refresh on next hit.
//
// On a hit the entry's expiry is refreshed (sliding window) so a
// chatty client keeps its sticky binding across the timeout. On a
// miss we install a fresh entry with the freshly-chosen index. LRU
// eviction is acceptable: a re-derivation produces a backend index,
// possibly different, but never references a freed slot thanks to
// the gen + bound checks.
static __always_inline __u32
select_backend_index(struct iphdr *iph, __be16 sport, __be16 dport,
                     const struct service_key *sk,
                     const struct service_val *sv, __u64 now) {
  __u32 idx = hash_tuple(iph->saddr, iph->daddr, sport, dport, iph->protocol) %
              sv->backend_count;

  if (!(sv->flags & SVC_FLAG_AFFINITY_CLIENT_IP) || sv->affinity_sec == 0)
    return idx;

  struct service_affinity_key ak = {
      .cluster_ip = sk->cluster_ip,
      .port = sk->port,
      .proto = sk->proto,
      .client_ip = bpf_ntohl(iph->saddr),
  };
  __u64 ttl_ns = (__u64)sv->affinity_sec * NSEC_PER_SEC;
  struct service_affinity_val *cached =
      bpf_map_lookup_elem(&service_affinity_map, &ak);
  if (cached && cached->backend_gen == sv->gen &&
      cached->backend_index < sv->backend_count &&
      cached->expires_at_ns > now) {
    cached->expires_at_ns = now + ttl_ns;
    return cached->backend_index;
  }

  struct service_affinity_val fresh = {
      .backend_index = idx,
      .backend_gen = sv->gen,
      .expires_at_ns = now + ttl_ns,
  };
  bpf_map_update_elem(&service_affinity_map, &ak, &fresh, BPF_ANY);
  return idx;
}

// NAPT_PROBE_LIMIT bounds the linear-probe loop used to claim a
// previously-unused alloc_port. Higher values lower the probability of
// a failed allocation under heavy port pressure but cost verifier
// instructions; 8 strikes a balance similar to cilium's snat_v4 path.
#define NAPT_PROBE_LIMIT 8

// rotate_left mixes a 32-bit value during port probe re-derivation.
static __always_inline __u32 napt_rotate_left(__u32 x, __u32 r) {
  return (x << r) | (x >> (32 - r));
}

// dispatch_after_dnat does the second FIB lookup that finds the route to
// the chosen backend and forwards the (already DNAT'd) packet onward.
// Service entries are not expected here — if the second lookup itself
// resolves to SERVICE we treat it as a configuration error and drop.
static __always_inline int dispatch_after_dnat(struct __sk_buff *skb,
                                               struct ethhdr *eth,
                                               struct iphdr *iph,
                                               __u32 vpc_id, __u32 table_id,
                                               __be32 dst_be) {
  __u32 tid = table_id;
  void *fib_inner_map = bpf_map_lookup_elem(&fib_map, &tid);
  if (!fib_inner_map) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, vpc_id);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_FIB_TABLE,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                           vpc_id, 0, tid);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id, 0);
    return TC_ACT_SHOT;
  }

  struct fib_key fkey = {
      .prefixlen = 32,
      .dst = dst_be,
  };
  const struct fib_val *fv = bpf_map_lookup_elem(fib_inner_map, &fkey);
  if (!fv) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, vpc_id);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_FIB_ROUTE,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                           vpc_id, 0, bpf_ntohl(dst_be));
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id, 0);
    return TC_ACT_SHOT;
  }

  if (fv->type == FIB_ROUTE_TYPE_CONNECTED ||
      fv->type == FIB_ROUTE_TYPE_PEERING) {
    struct arp_table_key ak = {
        .subnet_id = fv->subnet_id,
        .ipaddr = bpf_ntohl(dst_be),
    };
    const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
    if (!av)
      return TC_ACT_SHOT;
    __builtin_memcpy(eth->h_dest, av->mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);
    return forward_l2(skb, eth, vpc_id, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_ENDPOINT) {
    __builtin_memcpy(eth->h_dest, fv->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);
    return forward_l2(skb, eth, vpc_id, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_INTERNET_GATEWAY)
    return handle_snat(skb, eth, iph);

  return TC_ACT_SHOT;
}

// handle_service_host_local dispatches a Service flow whose chosen
// backend is host-network on *this* node (e.g. the local kube-apiserver
// when the caller Pod happens to be co-located on the control plane).
// SNAT would rewrite src=NodeIP making the reply (NodeIP→NodeIP) loop
// through lo where no BPF reverse hook lives, so the local path skips
// SNAT entirely: only DNAT to the backend's host IP+port. The packet
// is then handed to the kernel (TC_ACT_OK) which delivers it to the
// local socket. The reply leaves the host stack toward PodIP, crosses
// juneau_node_h → juneau_node, and is reverse-rewritten by pod_egress
// itself (apply_conntrack_svc_napt_in).
static __always_inline int
handle_service_host_local(struct __sk_buff *skb, struct ethhdr *eth,
                          struct iphdr *iph, const struct subnet_val *subnet,
                          const struct backend_val *bv) {
  void *data_end = skb_data_end(skb);

  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return TC_ACT_SHOT;

  __be16 sport, dport;
  if (read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return TC_ACT_SHOT;

  // Resolve this Pod's Subnet ID via ifindex_subnet so the reverse CT
  // entry can fdb-forward the response back to the originating Pod.
  struct ifindex_subnet_key isk = {.ifindex = skb->ifindex};
  const struct ifindex_subnet_val *isv =
      bpf_map_lookup_elem(&ifindex_subnet, &isk);
  if (!isv)
    return TC_ACT_SHOT;
  __u32 pod_subnet_id = isv->subnet_id;

  __be32 backend_addr_be = bpf_htonl(bv->backend_ip);
  __be16 backend_port_be = bpf_htons(bv->backend_port);
  __be32 cluster_ip_be = iph->daddr;
  __be32 pod_ip_be = iph->saddr;

  __u8 init_state = CT_STATE_ESTABLISHED;
  if (iph->protocol == IPPROTO_TCP) {
    __u8 f;
    if (ct_read_tcp_flags(iph, data_end, &f) == 0)
      init_state = ct_initial_state_for_syn(f);
  }

  __u64 now = bpf_ktime_get_ns();

  // No forward CT entry: an action=CT_ACTION_DNAT entry would short-
  // circuit subsequent packets through apply_conntrack_dnat →
  // dispatch_after_dnat, which then looks up dst=NodeIP in fib_map and
  // SHOTs because the node's own IP isn't in the user-space FIB. Re-
  // running handle_service per packet is cheap (a backend_map lookup
  // and one BPF_ANY rewrite of the reverse CT) and keeps this path
  // symmetric with the kernel's local-deliver semantics.

  // Reverse CT entry keyed on what apiserver replies with on the way
  // back to the Pod: (HOST, BackendIP, PodIP, BackendPort, sport, proto).
  // pod_egress on juneau_node ingress reads this when the host stack
  // routes the reply over the juneau_node_h → juneau_node veth.
  struct ct_key rev_key = {
      .scope = CT_SCOPE_HOST,
      .saddr = backend_addr_be,
      .daddr = pod_ip_be,
      .sport = backend_port_be,
      .dport = sport,
      .proto = iph->protocol,
  };
  struct ct_val rev_val = {
      .new_saddr = cluster_ip_be,
      .new_daddr = pod_ip_be,
      .new_sport = dport,
      .new_dport = sport,
      .next_subnet_id = pod_subnet_id,
      .action = CT_ACTION_SVC_NAPT_IN,
      .state = init_state,
      .flags_seen = 0,
      .last_seen_ns = now,
  };
  bpf_map_update_elem(&ct_map, &rev_key, &rev_val, BPF_ANY);

  __u8 nat_proto_local = iph->protocol;

  // DNAT only — leave src=PodIP intact so the reply naturally targets
  // PodIP, which the host stack already has a connected route for via
  // juneau_node_h.
  if (rewrite_ipv4_addr(skb, /*is_source=*/false, backend_addr_be) < 0)
    return TC_ACT_SHOT;
  if (rewrite_l4_port(skb, /*is_source=*/false, backend_port_be) < 0)
    return TC_ACT_SHOT;

  // Trace: host-network Service DNAT (local backend variant). DNAT
  // only — src is unchanged.
  {
    struct trace_nat_event __ne = {
        .vpc_id = subnet->vpc_id,
        .subnet_id = pod_subnet_id,
        .hook = TRACE_HOOK_POD_EGRESS,
        .reason = TRACE_REASON_DNAT_APPLIED,
        .scope = TRACE_SCOPE_VPC,
        .proto = nat_proto_local,
        .before_saddr = pod_ip_be,
        .before_daddr = cluster_ip_be,
        .before_sport = sport,
        .before_dport = dport,
        .after_saddr = pod_ip_be,
        .after_daddr = backend_addr_be,
        .after_sport = sport,
        .after_dport = backend_port_be,
    };
    trace_observe_nat(skb, &__ne);
  }

  // The Pod sent the original packet to its default-gateway MAC
  // (subnet gw_mac); eth_type_trans on the host-side veth therefore
  // tags skb->pkt_type=PACKET_OTHERHOST. After DNAT to a local IP the
  // kernel's ip_rcv_core would drop with reason=OTHERHOST unless we
  // reset pkt_type, since ip_rcv looks at pkt_type before re-deriving
  // it from the dst MAC.
  if (bpf_skb_change_type(skb, PACKET_HOST) < 0)
    return TC_ACT_SHOT;

  // Hand to the kernel — dst is now NodeIP which is RTN_LOCAL on this
  // node, so the kernel's local input path dispatches to the listening
  // socket. The packet enters the kernel via the Pod's host-side veth,
  // but src=PodIP is only reverse-routable through juneau_node_h.
  // bootstrap sets rp_filter=0 on `all` and per-Pod veth so this
  // asymmetric path survives the reverse-path check; juneau_node has
  // accept_local=1 for the reply leg (src=NodeIP=local).
  return TC_ACT_OK;
}

// handle_service_host_remote dispatches a Service flow whose chosen
// backend lives on the underlay (no Pod / no NetworkInterface). The
// packet is rewritten so dst becomes the backend's host IP and src
// becomes this node's underlay IP — letting the kernel route the flow
// over the underlay as if it originated from the local host. CT
// entries record the full 5-tuple translation so the response can be
// reversed by node_ingress.
static __always_inline int
handle_service_host_remote(struct __sk_buff *skb, struct ethhdr *eth,
                           struct iphdr *iph,
                           const struct subnet_val *subnet,
                           const struct backend_val *bv) {
  void *data_end = skb_data_end(skb);

  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return TC_ACT_SHOT;

  __be16 sport, dport;
  if (read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return TC_ACT_SHOT;

  __u32 underlay_key = 0;
  const __u32 *underlay_ip = bpf_map_lookup_elem(&host_underlay, &underlay_key);
  if (!underlay_ip || *underlay_ip == 0)
    return TC_ACT_SHOT;
  __be32 node_underlay_ip = *underlay_ip;

  // Resolve this Pod's Subnet ID via ifindex_subnet so the reverse CT
  // entry can fdb-forward the response back to the originating Pod.
  struct ifindex_subnet_key isk = {.ifindex = skb->ifindex};
  const struct ifindex_subnet_val *isv =
      bpf_map_lookup_elem(&ifindex_subnet, &isk);
  if (!isv)
    return TC_ACT_SHOT;
  __u32 pod_subnet_id = isv->subnet_id;

  __be32 backend_addr_be = bpf_htonl(bv->backend_ip);
  __be16 backend_port_be = bpf_htons(bv->backend_port);
  __be32 cluster_ip_be = iph->daddr;

  __u8 init_flags = 0;
  __u8 init_state = CT_STATE_ESTABLISHED;
  if (iph->protocol == IPPROTO_TCP) {
    __u8 f;
    if (ct_read_tcp_flags(iph, data_end, &f) == 0) {
      init_flags = f & TCP_FLAG_TRACKED;
      init_state = ct_initial_state_for_syn(f);
    }
  }

  __u64 now = bpf_ktime_get_ns();

  struct ct_key fwd_key = {
      .scope = subnet->vpc_id,
      .saddr = iph->saddr,
      .daddr = cluster_ip_be,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };

  struct ct_val *existing = bpf_map_lookup_elem(&ct_map, &fwd_key);
  __be16 alloc_port = 0;
  if (existing && existing->action == CT_ACTION_SVC_NAPT_OUT) {
    existing->last_seen_ns = now;
    alloc_port = existing->new_sport;
  } else {
    __u32 seed = hash_tuple(iph->saddr, cluster_ip_be, sport, dport,
                            iph->protocol);
    bool installed = false;

#pragma unroll
    for (int i = 0; i < NAPT_PROBE_LIMIT; i++) {
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
          .new_saddr = cluster_ip_be,
          .new_daddr = iph->saddr,
          .new_sport = dport,
          .new_dport = sport,
          .next_subnet_id = pod_subnet_id,
          .action = CT_ACTION_SVC_NAPT_IN,
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
      seed = napt_rotate_left(seed + 0x9e3779b1, 7);
    }
    if (!installed)
      return TC_ACT_SHOT;

    struct ct_val fwd_val = {
        .new_saddr = node_underlay_ip,
        .new_daddr = backend_addr_be,
        .new_sport = alloc_port,
        .new_dport = backend_port_be,
        .next_subnet_id = 0,
        .action = CT_ACTION_SVC_NAPT_OUT,
        .state = init_state,
        .flags_seen = init_flags,
        .last_seen_ns = now,
    };
    bpf_map_update_elem(&ct_map, &fwd_key, &fwd_val, BPF_ANY);
  }

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  __be32 hr_pod_ip_be = iph->saddr;
  __u8   hr_proto = iph->protocol;

  if (rewrite_ipv4_addr(skb, /*is_source=*/true, node_underlay_ip) < 0)
    return TC_ACT_SHOT;
  if (rewrite_l4_port(skb, /*is_source=*/true, alloc_port) < 0)
    return TC_ACT_SHOT;
  if (rewrite_ipv4_addr(skb, /*is_source=*/false, backend_addr_be) < 0)
    return TC_ACT_SHOT;
  if (rewrite_l4_port(skb, /*is_source=*/false, backend_port_be) < 0)
    return TC_ACT_SHOT;

  // Trace: host-network Service NAPT (remote backend variant).
  // Combined SNAT+DNAT: src rewrites to node's underlay IP +
  // alloc_port, dst rewrites to the backend host IP.
  {
    struct trace_nat_event __ne = {
        .vpc_id = subnet->vpc_id,
        .subnet_id = pod_subnet_id,
        .hook = TRACE_HOOK_POD_EGRESS,
        .reason = TRACE_REASON_SNAT_APPLIED,
        .scope = TRACE_SCOPE_VPC,
        .proto = hr_proto,
        .before_saddr = hr_pod_ip_be,
        .before_daddr = cluster_ip_be,
        .before_sport = sport,
        .before_dport = dport,
        .after_saddr = node_underlay_ip,
        .after_daddr = backend_addr_be,
        .after_sport = alloc_port,
        .after_dport = backend_port_be,
    };
    trace_observe_nat(skb, &__ne);
  }

  if (have_tcp_flags) {
    struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &fwd_key);
    if (cv)
      ct_observe_tcp(&fwd_key, cv, tcp_flags);
  }

  // Hand to kernel FIB to reach the backend host IP via the underlay.
  __u32 egress_ifindex = 0;
  return forward_via_host_fib(skb, &egress_ifindex);
}

// handle_service_shared dispatches a cross-Vpc shared-Service flow.
// The caller lives in a Vpc that has spec.service.consume=true (or is
// the same Vpc as the backend); the backend lives in the provider
// Vpc (the Vpc whose spec.service.provider.natSourceSubnet anchors
// this Node's SNAT IP). We rewrite the packet with both DNAT (dst →
// backend Pod) and SNAT (src → this Node's SNAT IP for the provider
// Vpc, allocated to a previously-unused source port to keep reverse
// CT keys unique across concurrent callers), record forward and
// reverse ct_map entries, and dispatch through dispatch_after_dnat
// against the backend's Subnet so the rewritten packet flows over the
// provider Vpc's fabric.
static __always_inline int
handle_service_shared(struct __sk_buff *skb, struct iphdr *iph,
                      const struct subnet_val *caller_subnet,
                      const struct backend_val *bv, __be16 sport, __be16 dport,
                      __u8 init_state, __u8 init_flags) {
  void *data_end = skb_data_end(skb);
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return TC_ACT_SHOT;

  // Resolve the backend's Subnet → Vpc up front: the provider Vpc id
  // keys both the SNAT IP table and the reverse CT entry, and the
  // dispatch step also needs the Subnet's table_id. Doing the lookup
  // once here keeps the verifier happy on hot-path reuse.
  struct subnet_key backend_sk = {.subnet_id = bv->backend_subnet_id};
  const struct subnet_val *backend_subnet =
      bpf_map_lookup_elem(&subnet_map, &backend_sk);
  if (!backend_subnet)
    return TC_ACT_SHOT;
  __u32 provider_vpc_id = backend_subnet->vpc_id;

  // Resolve this Node's SNAT IP for the provider Vpc. service_nat_ip
  // is keyed by provider vpc_id and populated by the daemon from
  // local ServiceNATAttachment.status.assignedIP entries; a missing
  // or zero value means the attachment is not yet ready.
  const __u32 *snat_ip_be =
      bpf_map_lookup_elem(&service_nat_ip, &provider_vpc_id);
  if (!snat_ip_be || *snat_ip_be == 0)
    return TC_ACT_SHOT;
  __be32 snat_ip = *snat_ip_be;

  // Resolve the caller Pod's Subnet ID via ifindex_subnet so the reverse
  // entry can fdb-forward the reply back to the caller. caller_subnet
  // gives us vpc_id but not subnet_id, which is what the reverse
  // dispatch needs.
  struct ifindex_subnet_key isk = {.ifindex = skb->ifindex};
  const struct ifindex_subnet_val *isv =
      bpf_map_lookup_elem(&ifindex_subnet, &isk);
  if (!isv)
    return TC_ACT_SHOT;
  __u32 caller_subnet_id = isv->subnet_id;

  __be32 backend_addr_be = bpf_htonl(bv->backend_ip);
  __be16 backend_port_be = bpf_htons(bv->backend_port);
  __be32 cluster_ip_be = iph->daddr;
  __be32 pod_ip_be = iph->saddr;

  __u64 now = bpf_ktime_get_ns();
  __u32 caller_vpc_id = caller_subnet->vpc_id;

  // Forward CT key (caller's Vpc-scoped 5-tuple before rewrite). Reuse a
  // pre-existing allocation when the same flow re-enters this hook.
  struct ct_key fwd_key = {
      .scope = caller_vpc_id,
      .saddr = pod_ip_be,
      .daddr = cluster_ip_be,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val *existing = bpf_map_lookup_elem(&ct_map, &fwd_key);
  __be16 alloc_port = 0;
  if (existing && existing->action == CT_ACTION_SVC_SHARED_OUT) {
    existing->last_seen_ns = now;
    alloc_port = existing->new_sport;
  } else {
    // Linear-probe port allocation under the SNAT IP. Seed with the
    // 5-tuple hash so initial candidates spread across the port space.
    __u32 seed =
        hash_tuple(pod_ip_be, cluster_ip_be, sport, dport, iph->protocol);
    bool installed = false;

#pragma unroll
    for (int i = 0; i < NAPT_PROBE_LIMIT; i++) {
      __u32 candidate_host = 1024 + ((seed + i) % (65536 - 1024));
      __be16 candidate = bpf_htons((__u16)candidate_host);

      // The reverse entry lives in the provider Vpc's keyspace,
      // matching what the backend's pod_egress / our vxlan_ingress
      // will look up on the reply leg.
      struct ct_key rev_key = {
          .scope = provider_vpc_id,
          .saddr = backend_addr_be,
          .daddr = snat_ip,
          .sport = backend_port_be,
          .dport = candidate,
          .proto = iph->protocol,
      };

      struct ct_val rev_val = {
          .new_saddr = cluster_ip_be,
          .new_daddr = pod_ip_be,
          .new_sport = dport,
          .new_dport = sport,
          .next_subnet_id = caller_subnet_id,
          .action = CT_ACTION_SVC_SHARED_IN,
          .state = init_state,
          .flags_seen = 0,
          .last_seen_ns = now,
      };
      long rc = bpf_map_update_elem(&ct_map, &rev_key, &rev_val, BPF_NOEXIST);
      if (rc == 0) {
        alloc_port = candidate;
        installed = true;
        break;
      }
      seed = napt_rotate_left(seed + 0x9e3779b1, 7);
    }

    if (!installed)
      return TC_ACT_SHOT;

    struct ct_val fwd_val = {
        .new_saddr = snat_ip,
        .new_daddr = backend_addr_be,
        .new_sport = alloc_port,
        .new_dport = backend_port_be,
        .next_subnet_id = bv->backend_subnet_id,
        .action = CT_ACTION_SVC_SHARED_OUT,
        .state = init_state,
        .flags_seen = init_flags,
        .last_seen_ns = now,
    };
    bpf_map_update_elem(&ct_map, &fwd_key, &fwd_val, BPF_ANY);
  }

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  __u8 nat_proto = iph->protocol;

  if (rewrite_ipv4_addr(skb, /*is_source=*/true, snat_ip) < 0)
    return TC_ACT_SHOT;
  if (rewrite_l4_port(skb, /*is_source=*/true, alloc_port) < 0)
    return TC_ACT_SHOT;
  if (rewrite_ipv4_addr(skb, /*is_source=*/false, backend_addr_be) < 0)
    return TC_ACT_SHOT;
  if (rewrite_l4_port(skb, /*is_source=*/false, backend_port_be) < 0)
    return TC_ACT_SHOT;

  // Trace: shared-Service combined SNAT+DNAT applied. before is the
  // caller's view (Pod IP → ClusterIP); after is the backend's view
  // (SNAT IP → backend Pod IP).
  {
    struct trace_nat_event __ne = {
        .vpc_id = caller_vpc_id,
        .subnet_id = bv->backend_subnet_id,
        .hook = TRACE_HOOK_POD_EGRESS,
        .reason = TRACE_REASON_SNAT_APPLIED,
        .scope = TRACE_SCOPE_VPC,
        .proto = nat_proto,
        .before_saddr = pod_ip_be,
        .before_daddr = cluster_ip_be,
        .before_sport = sport,
        .before_dport = dport,
        .after_saddr = snat_ip,
        .after_daddr = backend_addr_be,
        .after_sport = alloc_port,
        .after_dport = backend_port_be,
    };
    trace_observe_nat(skb, &__ne);
  }

  if (have_tcp_flags) {
    struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &fwd_key);
    if (cv)
      ct_observe_tcp(&fwd_key, cv, tcp_flags);
  }

  struct iphdr *new_iph = load_iph(skb);
  if (!new_iph)
    return TC_ACT_SHOT;
  struct ethhdr *new_eth =
      (struct ethhdr *)((void *)new_iph - sizeof(struct ethhdr));

  // Dispatch in the *backend's* Vpc routing table so the rewritten
  // packet finds the connected route to the backend Pod.
  return dispatch_after_dnat(skb, new_eth, new_iph, provider_vpc_id,
                             backend_subnet->table_id, backend_addr_be);
}

// handle_service performs the Service DNAT path. It enforces VPC ownership
// (caller and Service owner must share a Vpc), picks a backend by hashing
// the 5-tuple, installs forward and reverse CT entries, rewrites the
// destination IP+port to the backend, and continues with a second FIB
// lookup so the rewritten packet can find a normal CONNECTED/ENDPOINT
// route to the backend Pod.
//
// via_endpoint_pool is set when the FIB matched FIB_ROUTE_TYPE_VPC_ENDPOINT,
// i.e. the destination is a VpcEndpoint VIP and not a ClusterIP yet. Only
// then do we pay for the vpc_endpoint_map lookup that resolves it.
static __always_inline int
handle_service(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph,
               const struct subnet_val *subnet, bool via_endpoint_pool) {
  void *data_end = skb_data_end(skb);

  __be16 sport, dport;
  if (read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return TC_ACT_SHOT;

  struct service_key sk = {
      .cluster_ip = bpf_ntohl(iph->daddr),
      .port = bpf_ntohs(dport),
      .proto = iph->protocol,
  };
  if (via_endpoint_pool) {
    struct vpc_endpoint_key vek = {
        .vpc_id = subnet->vpc_id,
        .address = sk.cluster_ip,
        .port = sk.port,
        .proto = sk.proto,
    };
    const struct vpc_endpoint_val *vev =
        bpf_map_lookup_elem(&vpc_endpoint_map, &vek);
    if (!vev) {
      __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, subnet->vpc_id);
      trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_VPC_ENDPOINT,
                             TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                             subnet->vpc_id, 0, sk.cluster_ip);
      trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                         subnet->vpc_id, 0);
      return TC_ACT_SHOT;
    }
    sk.cluster_ip = vev->cluster_ip;
  }

  const struct service_val *sv = bpf_map_lookup_elem(&service_map, &sk);
  if (!sv) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, subnet->vpc_id);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_SERVICE,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                           subnet->vpc_id, 0, sk.cluster_ip);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                       subnet->vpc_id, 0);
    return TC_ACT_SHOT;
  }
  // Cross-Vpc access is only allowed for Services explicitly opted in to
  // the shared path. caller_vpc != owner_vpc otherwise drops, preserving
  // the strict per-Vpc isolation that ordinary Services rely on.
  //
  // via_endpoint_pool skips that drop because the control plane already
  // approved this exact exposure: the daemon only writes a
  // vpc_endpoint_map entry for a VpcEndpoint whose ServiceAccepted
  // condition is True, and the pool route that leads here is only
  // installed in the Vpc that owns the pool. Without both halves of that
  // chain the skip would be an isolation hole.
  bool is_shared = (sv->flags & SVC_FLAG_SHARED) != 0;
  if (sv->owner_vpc_id != subnet->vpc_id && !is_shared && !via_endpoint_pool)
    return TC_ACT_SHOT;
  // Per-Service consumer ACL: when SVC_FLAG_HAS_ACL is set, only the
  // (cluster_ip, port, proto, caller_vpc_id) tuples explicitly
  // present in service_acl_map are admitted. Absent flag → every
  // consume-enabled Vpc is admitted by default. Same-Vpc callers
  // always pass; the ACL applies only to the cross-Vpc shared path.
  //
  // via_endpoint_pool skips the ACL for the same reason it skips the
  // ownership check above: the VpcEndpoint is itself the per-Vpc grant,
  // so the caller was already named when the entry was programmed.
  if (!via_endpoint_pool && is_shared && sv->owner_vpc_id != subnet->vpc_id &&
      (sv->flags & SVC_FLAG_HAS_ACL)) {
    struct service_acl_key ak = {
        .cluster_ip = sk.cluster_ip,
        .port = sk.port,
        .proto = sk.proto,
        .caller_vpc_id = subnet->vpc_id,
    };
    if (!bpf_map_lookup_elem(&service_acl_map, &ak))
      return TC_ACT_SHOT;
  }
  if (sv->backend_count == 0)
    return TC_ACT_SHOT;

  __u64 svc_now = bpf_ktime_get_ns();
  __u32 idx = select_backend_index(iph, sport, dport, &sk, sv, svc_now);

  struct backend_key bk = {
      .cluster_ip = sk.cluster_ip,
      .port = sk.port,
      .proto = sk.proto,
      .index = idx,
  };
  const struct backend_val *bv = bpf_map_lookup_elem(&backend_map, &bk);
  if (!bv) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, subnet->vpc_id);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_BACKEND,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                           subnet->vpc_id, 0, idx);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                       subnet->vpc_id, 0);
    return TC_ACT_SHOT;
  }

  // Trace: service lookup hit + backend selected. The two emits give
  // operators a clear "the service exists; backend N (kind X) was
  // chosen" stop in the timeline before any rewrite happens.
  {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, subnet->vpc_id);
    if (__tid != 0) {
      __u32 __ez = 0;
      struct trace_emit_args *a =
          bpf_map_lookup_elem(&pod_egress_emit_scratch, &__ez);
      if (a) {
        __builtin_memset(a, 0, sizeof(*a));
        a->trace_id = __tid;
        a->reason = TRACE_REASON_SERVICE_LOOKUP_HIT;
        a->hook = TRACE_HOOK_POD_EGRESS;
        a->ifindex = skb->ifindex;
        a->vpc_id = subnet->vpc_id;
        a->scope = TRACE_SCOPE_VPC;
        a->proto = iph->protocol;
        a->verdict = TRACE_VERDICT_OK;
        a->direction = TRACE_DIR_REQUEST;
        a->saddr = iph->saddr;
        a->daddr = iph->daddr;
        a->sport = sport;
        a->dport = dport;
        a->aux1 = sv->owner_vpc_id;
        a->aux2 = sv->backend_count;
        trace_emit_full(a);

        // Reuse the scratch slot for the second emit.
        a->reason = TRACE_REASON_SERVICE_BACKEND_SELECTED;
        a->aux1 = idx;
        a->aux2 = bv->backend_subnet_id;
        trace_emit_full(a);
      }
    }
  }

  // bv->kind is set by the user-space Service reconciler. POD (=0) is
  // also the value old reconcilers leave behind, so we additionally
  // honour the legacy backend_subnet_id == BACKEND_SUBNET_ID_UNDERLAY
  // sentinel for backwards compat — but a reconciler that knows about
  // kind always sets HOST_REMOTE / HOST_LOCAL explicitly.
  if (bv->kind == BACKEND_KIND_HOST_LOCAL)
    return handle_service_host_local(skb, eth, iph, subnet, bv);
  if (bv->kind == BACKEND_KIND_HOST_REMOTE ||
      (bv->kind == BACKEND_KIND_POD &&
       bv->backend_subnet_id == BACKEND_SUBNET_ID_UNDERLAY))
    return handle_service_host_remote(skb, eth, iph, subnet, bv);

  __be32 backend_addr_be = bpf_htonl(bv->backend_ip);
  __be16 backend_port_be = bpf_htons(bv->backend_port);

  // Reuse svc_now from select_backend_index above. Re-reading the clock
  // here would only cost a helper call and risks ct_val.last_seen_ns
  // disagreeing with the affinity entry by a few nanoseconds.
  __u64 now = svc_now;

  // Seed state from the SYN flag of the packet that triggers entry
  // creation. Mid-flow installs (no SYN) jump directly to ESTABLISHED to
  // avoid sitting in NEW until GC reaps them.
  __u8 init_flags = 0;
  __u8 init_state = CT_STATE_ESTABLISHED;
  if (iph->protocol == IPPROTO_TCP) {
    __u8 f;
    if (ct_read_tcp_flags(iph, data_end, &f) == 0) {
      init_flags = f & TCP_FLAG_TRACKED;
      init_state = ct_initial_state_for_syn(f);
    }
  }

  // Cross-Vpc shared-Service path: caller and Service owner differ but
  // the Service is annotated for sharing. Apply DNAT+SNAT through the
  // shared NAT IP so the backend can route the reply back to the
  // originating Node.
  if (sv->owner_vpc_id != subnet->vpc_id) {
    return handle_service_shared(skb, iph, subnet, bv, sport, dport,
                                 init_state, init_flags);
  }

  // Forward CT entry: caller -> ClusterIP keyed tuple, action=DNAT.
  struct ct_key fwd_key = {
      .scope = subnet->vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val fwd_val = {
      .new_saddr = iph->saddr,
      .new_daddr = backend_addr_be,
      .new_sport = sport,
      .new_dport = backend_port_be,
      .next_subnet_id = bv->backend_subnet_id,
      .action = CT_ACTION_DNAT,
      .state = init_state,
      .flags_seen = init_flags,
      .last_seen_ns = now,
  };
  bpf_map_update_elem(&ct_map, &fwd_key, &fwd_val, BPF_ANY);

  // Reverse CT entry: backend -> caller keyed tuple, action=SNAT. Used by
  // the backend's pod_egress on the response leg to restore the ClusterIP.
  struct ct_key rev_key = {
      .scope = subnet->vpc_id,
      .saddr = backend_addr_be,
      .daddr = iph->saddr,
      .sport = backend_port_be,
      .dport = sport,
      .proto = iph->protocol,
  };
  struct ct_val rev_val = {
      .new_saddr = iph->daddr,
      .new_daddr = iph->saddr,
      .new_sport = dport,
      .new_dport = sport,
      .next_subnet_id = 0,
      .action = CT_ACTION_SNAT,
      .state = init_state,
      .flags_seen = 0,
      .last_seen_ns = now,
  };
  bpf_map_update_elem(&ct_map, &rev_key, &rev_val, BPF_ANY);

  // Capture pre-rewrite tuple values for the trace NAT event below;
  // rewrite_ipv4_addr/rewrite_l4_port mutate skb in place so we
  // cannot rely on iph after they run.
  __be32 __nat_before_saddr = iph->saddr;
  __be32 __nat_before_daddr = iph->daddr;
  __be16 __nat_before_sport = sport;
  __be16 __nat_before_dport = dport;
  __u8 __nat_proto = iph->protocol;

  if (rewrite_ipv4_addr(skb, /*is_source=*/false, backend_addr_be) < 0)
    return TC_ACT_SHOT;
  if (rewrite_l4_port(skb, /*is_source=*/false, backend_port_be) < 0)
    return TC_ACT_SHOT;

  // Trace: emit the DNAT event (carries before/after tuples) and
  // learn the after-tuple locally so subsequent hooks on this node
  // resolve the same trace_id. Cross-node propagation is userspace's
  // job (kubectl forwards LearnTuple to peers via Debug RPC).
  {
    struct trace_nat_event __ne = {
        .vpc_id = subnet->vpc_id,
        .subnet_id = bv->backend_subnet_id,
        .hook = TRACE_HOOK_POD_EGRESS,
        .reason = TRACE_REASON_DNAT_APPLIED,
        .scope = TRACE_SCOPE_VPC,
        .proto = __nat_proto,
        .before_saddr = __nat_before_saddr,
        .before_daddr = __nat_before_daddr,
        .before_sport = __nat_before_sport,
        .before_dport = __nat_before_dport,
        .after_saddr = __nat_before_saddr,
        .after_daddr = backend_addr_be,
        .after_sport = __nat_before_sport,
        .after_dport = backend_port_be,
    };
    trace_observe_nat(skb, &__ne);
  }

  // Re-derive packet pointers after the rewrites; both helpers reload
  // skb->data internally but our local eth/iph were captured before.
  struct iphdr *new_iph = load_iph(skb);
  if (!new_iph)
    return TC_ACT_SHOT;
  struct ethhdr *new_eth =
      (struct ethhdr *)((void *)new_iph - sizeof(struct ethhdr));

  return dispatch_after_dnat(skb, new_eth, new_iph, subnet->vpc_id,
                             subnet->table_id, backend_addr_be);
}

// apply_conntrack_svc_napt_in handles the reply leg of a HOST_LOCAL
// Service flow: apiserver → PodIP packets routed by the host stack via
// the juneau_node_h → juneau_node veth pair surface here at TCX
// ingress. We look up CT in the HOST scope keyed on the apiserver's
// reply tuple; if SVC_NAPT_IN is recorded, rewrite src back to the
// caller's ClusterIP+port and forward to the Pod's veth via fdb.
//
// Returns 1 if the packet was rewritten and dispatched (caller should
// return its result), 0 if no matching entry, -1 on rewrite failure.
static __always_inline int apply_conntrack_svc_napt_in(struct __sk_buff *skb,
                                                       int *out_rc) {
  struct iphdr *iph = load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = skb_data_end(skb);

  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return 0;

  __be16 sport, dport;
  if (read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return 0;

  struct ct_key ck = {
      .scope = CT_SCOPE_HOST,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (!cv || cv->action != CT_ACTION_SVC_NAPT_IN)
    return 0;

  struct subnet_key sk = {.subnet_id = cv->next_subnet_id};
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &sk);
  if (!subnet)
    return -1;

  struct arp_table_key ak = {
      .subnet_id = cv->next_subnet_id,
      .ipaddr = bpf_ntohl(cv->new_daddr),
  };
  const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
  if (!av)
    return -1;

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
  __u32 next_subnet_id = cv->next_subnet_id;

  __be32 before_saddr = iph->saddr;
  __be32 before_daddr = iph->daddr;
  __u8   nat_proto    = iph->protocol;
  __be32 after_saddr  = cv->new_saddr ? cv->new_saddr : before_saddr;
  __be32 after_daddr  = cv->new_daddr;
  __be16 after_sport  = cv->new_sport ? cv->new_sport : sport;
  __be16 after_dport  = cv->new_dport ? cv->new_dport : dport;

  if (nat_apply_napt_in_rewrite(skb, cv) < 0)
    return -1;

  // Trace: SVC_NAPT_IN reverse rewrite — host-network Service reply.
  {
    struct trace_nat_event __ne = {
        .vpc_id = subnet->vpc_id,
        .subnet_id = next_subnet_id,
        .hook = TRACE_HOOK_POD_EGRESS,
        .reason = TRACE_REASON_REVERSE_NAT_APPLIED,
        .scope = TRACE_SCOPE_HOST,
        .proto = nat_proto,
        .before_saddr = before_saddr,
        .before_daddr = before_daddr,
        .before_sport = sport,
        .before_dport = dport,
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

  void *data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;
  __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

  // Reply leg: trace tuples are registered for the forward direction
  // only, so this lookup never claims an active session. Pass 0 to
  // make that intent explicit at the call site.
  *out_rc = forward_l2(skb, eth, 0, next_subnet_id);
  return 1;
}

// apply_conntrack_svc_shared_in handles the same-Node reply leg of a
// shared-Service flow: a default-Vpc backend Pod replies to the SNAT IP
// of the originating Node, and that reply enters the backend Pod's
// veth-peer ingress (this very pod_egress hook). When the originating
// caller is co-located on this Node, the SVC_SHARED_IN ct_val installed
// by handle_service_shared lives in the *same* Node's ct_map; we can
// rewrite both halves and redirect the packet straight to the caller's
// veth without ever touching the VXLAN underlay.
//
// On a different Node, the ct_map lookup misses and this function falls
// through (return 0). The packet then flows out to fdb-driven VXLAN
// forwarding, lands at the originating Node's vxlan_ingress hook, and
// the same SVC_SHARED_IN entry — present on *that* Node's ct_map —
// completes the rewrite there.
//
// Returns 1 if the packet was rewritten and dispatched (caller should
// return *out_rc), 0 on no matching entry, -1 on rewrite failure.
static __always_inline int apply_conntrack_svc_shared_in(struct __sk_buff *skb,
                                                         const struct subnet_val *backend_subnet,
                                                         int *out_rc) {
  struct iphdr *iph = load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = skb_data_end(skb);

  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return 0;

  __be16 sport, dport;
  if (read_l4_ports(iph, data_end, &sport, &dport) < 0)
    return 0;

  // The ct_map entry is keyed by the backend Pod's reply tuple: scope is
  // the backend's Vpc (= default Vpc for shared Services), saddr is the
  // backend Pod IP, daddr is the SNAT IP, dport is the alloc_port chosen
  // when the forward path installed the entry.
  struct ct_key ck = {
      .scope = backend_subnet->vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (!cv || cv->action != CT_ACTION_SVC_SHARED_IN)
    return 0;

  // Resolve the caller-side Subnet so we can rewrite L2 to terminate at
  // the caller Pod's veth.
  struct subnet_key sk = {.subnet_id = cv->next_subnet_id};
  const struct subnet_val *caller_subnet = bpf_map_lookup_elem(&subnet_map, &sk);
  if (!caller_subnet)
    return -1;

  struct arp_table_key ak = {
      .subnet_id = cv->next_subnet_id,
      .ipaddr = bpf_ntohl(cv->new_daddr),
  };
  const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
  if (!av)
    return -1;

  __u8 dst_mac[ETH_ALEN];
  __u8 src_mac[ETH_ALEN];
  __builtin_memcpy(dst_mac, av->mac, ETH_ALEN);
  __builtin_memcpy(src_mac, caller_subnet->gw_mac, ETH_ALEN);

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  cv->last_seen_ns = bpf_ktime_get_ns();
  __u32 next_subnet_id = cv->next_subnet_id;

  __be32 before_saddr = iph->saddr;
  __be32 before_daddr = iph->daddr;
  __u8   nat_proto    = iph->protocol;
  __be32 after_saddr  = cv->new_saddr ? cv->new_saddr : before_saddr;
  __be32 after_daddr  = cv->new_daddr;
  __be16 after_sport  = cv->new_sport ? cv->new_sport : sport;
  __be16 after_dport  = cv->new_dport ? cv->new_dport : dport;

  if (nat_apply_napt_in_rewrite(skb, cv) < 0)
    return -1;

  // Trace: SVC_SHARED_IN reverse rewrite — same-node shared-Service reply.
  {
    struct trace_nat_event __ne = {
        .vpc_id = caller_subnet->vpc_id,
        .subnet_id = next_subnet_id,
        .hook = TRACE_HOOK_POD_EGRESS,
        .reason = TRACE_REASON_REVERSE_NAT_APPLIED,
        .scope = TRACE_SCOPE_VPC,
        .proto = nat_proto,
        .before_saddr = before_saddr,
        .before_daddr = before_daddr,
        .before_sport = sport,
        .before_dport = dport,
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

  void *data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;
  __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

  // Reply leg; see apply_conntrack_svc_napt_in for the rationale.
  *out_rc = forward_l2(skb, eth, 0, next_subnet_id);
  return 1;
}

// apply_conntrack_dnat looks up the conntrack table for the packet's
// 5-tuple and applies forward-direction DNAT if a matching entry exists.
//
// pod_egress only handles forward DNAT (caller -> ClusterIP). The reverse
// SNAT for the response leg lives in pod_ingress, where it can fire for
// both same-node and VXLAN-delivered packets at the destination veth.
// Returns 1 on DNAT applied, 0 on no rewrite, -1 on failure.
static __always_inline int apply_conntrack_dnat(struct __sk_buff *skb,
                                                __u32 vpc_id) {
  struct iphdr *iph = load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = skb_data_end(skb);

  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return 0;

  __be16 sport, dport;
  if (read_l4_ports(iph, data_end, &sport, &dport) < 0)
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
  if (!cv || cv->action != CT_ACTION_DNAT)
    return 0;

  cv->last_seen_ns = bpf_ktime_get_ns();
  __be32 new_daddr = cv->new_daddr;
  __be16 new_dport = cv->new_dport;

  // Capture pre-rewrite tuple for the trace event.
  __be32 before_saddr = iph->saddr;
  __be32 before_daddr = iph->daddr;
  __u8 before_proto = iph->protocol;

  // Read TCP flags before rewriting L4 ports — the rewrite touches bytes
  // adjacent to the flags byte and forces an skb reload. Reading first
  // keeps the verifier happy.
  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  if (rewrite_ipv4_addr(skb, false, new_daddr) < 0)
    return -1;
  if (rewrite_l4_port(skb, false, new_dport) < 0)
    return -1;

  // Trace: cached-path DNAT applied. Emits the same event shape the
  // first-packet handle_service path emits, so the timeline shows the
  // translation across the full flow lifetime — not just the SYN.
  {
    struct trace_nat_event __ne = {
        .vpc_id = vpc_id,
        .subnet_id = cv->next_subnet_id,
        .hook = TRACE_HOOK_POD_EGRESS,
        .reason = TRACE_REASON_DNAT_APPLIED,
        .scope = TRACE_SCOPE_VPC,
        .proto = before_proto,
        .before_saddr = before_saddr,
        .before_daddr = before_daddr,
        .before_sport = sport,
        .before_dport = dport,
        .after_saddr = before_saddr,
        .after_daddr = new_daddr,
        .after_sport = sport,
        .after_dport = new_dport,
    };
    trace_observe_nat(skb, &__ne);
  }

  if (have_tcp_flags)
    ct_observe_tcp(&ck, cv, tcp_flags);
  return 1;
}

// apply_conntrack_lb_rev_nat is the reply leg of an external →
// LoadBalancer-VIP flow. The CT entry was installed at node_ingress
// (forward LB_DNAT pair); this side scopes ct_map by the backend
// Pod's owning Vpc and matches the (PodIP → external client) tuple.
//
// On hit, we rewrite saddr from PodIP to the original VIP and sport
// from the target port to the Service port. The destination tuple is
// preserved so the host stack / underlay routes the reply back to
// the external client unchanged.
//
// Returns 1 on rewrite applied, 0 on no rewrite, -1 on failure.
// noinline subprogram — see apply_conntrack_svc_napt_in for the
// verifier-complexity rationale.
static __juneau_bpf_subprog int apply_conntrack_lb_rev_nat(struct __sk_buff *skb,
                                                           __u32 vpc_id) {
  struct iphdr *iph = load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = skb_data_end(skb);

  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return 0;

  __be16 sport, dport;
  if (read_l4_ports(iph, data_end, &sport, &dport) < 0)
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
  if (!cv || cv->action != CT_ACTION_LB_REV_NAT)
    return 0;

  cv->last_seen_ns = bpf_ktime_get_ns();
  __be32 new_saddr = cv->new_saddr;
  __be16 new_sport = cv->new_sport;

  // Populate the trace event in per-CPU scratch BEFORE rewrite so
  // we can read the BEFORE tuple straight from `ck` instead of
  // snapshotting iph fields into extra stack locals. The actual
  // trace_observe_nat() emit happens at the call site in handle_l2
  // — invoking it from inside this subprogram would build a
  // 3-frame chain (tc_pod_egress → lb_rev_nat → trace_observe_nat)
  // that exceeds the 512-byte combined-stack ceiling.
  __u32 zero = 0;
  struct trace_nat_event *ne =
      bpf_map_lookup_elem(&pod_egress_nat_scratch, &zero);
  if (ne) {
    ne->vpc_id = vpc_id;
    ne->subnet_id = 0;
    ne->hook = TRACE_HOOK_POD_EGRESS;
    ne->reason = TRACE_REASON_REVERSE_NAT_APPLIED;
    ne->scope = TRACE_SCOPE_VPC;
    ne->proto = ck.proto;
    ne->before_saddr = ck.saddr;
    ne->before_daddr = ck.daddr;
    ne->before_sport = sport;
    ne->before_dport = dport;
    ne->after_saddr = new_saddr;
    ne->after_daddr = ck.daddr;
    ne->after_sport = new_sport;
    ne->after_dport = dport;
  }

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  if (rewrite_ipv4_addr(skb, /*is_source=*/true, new_saddr) < 0)
    return -1;
  if (rewrite_l4_port(skb, /*is_source=*/true, new_sport) < 0)
    return -1;

  if (have_tcp_flags)
    ct_observe_tcp(&ck, cv, tcp_flags);

  return 1;
}

// napt_icmp_target carries the source address and port an ICMP error
// message has to leave with, from the lookup subprogram to the rewrite
// subprogram.
struct napt_icmp_target {
  __be32 addr;
  __be16 port;
  __u16 _pad;
};

// napt_icmp_error_match finds the flow an ICMP error message a Pod sends
// towards the internet reports on. The message carries a copy of the
// packet the Pod refused, which is the inbound half of a NAPT flow, so
// inverting that copy names the CT_ACTION_NAPT_OUT entry holding the
// allocation. The error has to leave with the same source address and
// port the flow itself uses, or the peer cannot match it to its own
// socket.
//
// Returns 1 on a match (target is filled and the trace event is staged),
// 0 when the packet is not an ICMP error message, and -1 when it is one
// but no flow claims it.
//
// noinline subprogram: the copy parser is large and tc_pod_egress is the
// program closest to both verifier limits.
static __juneau_bpf_subprog int
napt_icmp_error_match(struct __sk_buff *skb, __u32 vpc_id,
                      struct napt_icmp_target *target) {
  struct iphdr *iph = load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = skb_data_end(skb);

  struct nat_icmp_quote q;
  if (nat_read_icmp_quote(iph, data_end, &q) < 0)
    return 0;

  struct ct_key ck = {
      .scope = vpc_id,
      .saddr = q.daddr,
      .daddr = q.saddr,
      .sport = q.dport,
      .dport = q.sport,
      .proto = q.proto,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (!cv || cv->action != CT_ACTION_NAPT_OUT)
    return -1;

  cv->last_seen_ns = bpf_ktime_get_ns();
  target->addr = cv->new_saddr;
  target->port = cv->new_sport;
  target->_pad = 0;

  // Fill the trace event here so the before-tuple can be read from ck.
  // The emit happens at the call site; see apply_conntrack_lb_rev_nat
  // for the frame-depth reason. proto names the flow the message reports
  // on, not the ICMP message itself, so the tuple resolves against the
  // entry the forward NAPT event left behind.
  __u32 zero = 0;
  struct trace_nat_event *ne =
      bpf_map_lookup_elem(&pod_egress_nat_scratch, &zero);
  if (ne) {
    ne->vpc_id = vpc_id;
    ne->subnet_id = 0;
    ne->hook = TRACE_HOOK_POD_EGRESS;
    ne->reason = TRACE_REASON_ICMP_ERROR_TRANSLATED;
    ne->scope = TRACE_SCOPE_VPC;
    ne->proto = ck.proto;
    ne->before_saddr = ck.saddr;
    ne->before_daddr = ck.daddr;
    ne->before_sport = ck.sport;
    ne->before_dport = ck.dport;
    ne->after_saddr = target->addr;
    ne->after_daddr = ck.daddr;
    ne->after_sport = target->port;
    ne->after_dport = ck.dport;
  }
  return 1;
}

// napt_icmp_error_apply performs the rewrite napt_icmp_error_match
// resolved. It reads the copied packet again instead of reusing that
// parse: the two run as sibling subprograms, so sharing a parse would
// mean nesting one frame inside the other, and tc_pod_egress has no room
// for that.
static __juneau_bpf_subprog int napt_icmp_error_apply(struct __sk_buff *skb,
                                                      __be32 new_saddr,
                                                      __be16 new_sport) {
  struct iphdr *iph = load_iph(skb);
  if (!iph)
    return -1;
  void *data_end = skb_data_end(skb);

  struct nat_icmp_quote q;
  if (nat_read_icmp_quote(iph, data_end, &q) < 0)
    return -1;

  return nat_icmp_quote_rewrite(skb, &q, /*outer_is_source=*/true, new_saddr,
                                new_sport);
}

// handle_napt is the forward NAPT path: it rewrites src IP/port to the
// node's host_napt_ip and an allocated source port, installs both
// forward (NAPT_OUT) and reverse (NAPT_IN) ct_map entries, and then
// hands the packet to the host network stack via a kernel FIB lookup,
// mirroring handle_snat's tail. nat_gateway_id is fib_val.subnet_id
// reinterpreted (FIB_ROUTE_TYPE_NAPT overload).
//
// ICMP Echo takes the same path with the Identifier standing in for the
// port pair. An ICMP error message has no tuple of its own and goes
// through napt_icmp_error_match; every other ICMP type is dropped.
static __always_inline int handle_napt(struct __sk_buff *skb,
                                       struct ethhdr *eth, struct iphdr *iph,
                                       const struct subnet_val *subnet,
                                       __u32 nat_gateway_id) {
  void *data_end = skb_data_end(skb);
  bool is_icmp = iph->protocol == IPPROTO_ICMP;
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP && !is_icmp)
    return TC_ACT_SHOT;

  __u32 caller_vpc_id = subnet->vpc_id;

  if (is_icmp) {
    struct napt_icmp_target icmp_target = {};
    int icmp_rc = napt_icmp_error_match(skb, caller_vpc_id, &icmp_target);
    if (icmp_rc < 0)
      return TC_ACT_SHOT;
    if (icmp_rc > 0) {
      if (napt_icmp_error_apply(skb, icmp_target.addr, icmp_target.port) < 0)
        return TC_ACT_SHOT;
      if (rewrite_ipv4_addr(skb, /*is_source=*/true, icmp_target.addr) < 0)
        return TC_ACT_SHOT;
      __u32 icmp_zero = 0;
      struct trace_nat_event *icmp_ne =
          bpf_map_lookup_elem(&pod_egress_nat_scratch, &icmp_zero);
      if (icmp_ne)
        trace_observe_nat(skb, icmp_ne);
      __u32 icmp_ifindex = 0;
      return forward_via_host_fib(skb, &icmp_ifindex);
    }
    // The call scrubbed the packet pointers; the Echo path below needs
    // them again.
    iph = load_iph(skb);
    if (!iph)
      return TC_ACT_SHOT;
    data_end = skb_data_end(skb);
  }

  __be16 sport, dport;
  if (read_napt_ports(iph, data_end, &sport, &dport) < 0)
    return TC_ACT_SHOT;

  // Resolve this node's NAPT source IP for the requested gateway.
  struct napt_src_key nsk = {.nat_gateway_id = nat_gateway_id};
  const struct napt_src_val *nsv = bpf_map_lookup_elem(&napt_src, &nsk);
  if (!nsv)
    return TC_ACT_SHOT;
  __be32 host_napt_ip = nsv->host_ip;

  __u8 init_flags = 0;
  __u8 init_state = CT_STATE_ESTABLISHED;
  if (iph->protocol == IPPROTO_TCP) {
    __u8 f;
    if (ct_read_tcp_flags(iph, data_end, &f) == 0) {
      init_flags = f & TCP_FLAG_TRACKED;
      init_state = ct_initial_state_for_syn(f);
    }
  }

  __u64 now = bpf_ktime_get_ns();

  // Forward CT key (scope=caller VPC, saddr=pod, daddr=internet, sport=sp, dport=dp)
  struct ct_key fwd_key = {
      .scope = caller_vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };

  // If a forward entry already exists, reuse its allocation.
  struct ct_val *existing = bpf_map_lookup_elem(&ct_map, &fwd_key);
  __be16 alloc_port = 0;
  if (existing && existing->action == CT_ACTION_NAPT_OUT) {
    existing->last_seen_ns = now;
    alloc_port = existing->new_sport;
  } else {
    // Linear-probe allocation. Seed with a 5-tuple hash to spread
    // initial candidates across the port space; on collision we
    // increment the candidate. Skip ports < 1024.
    __u32 seed = hash_tuple(iph->saddr, iph->daddr, sport, dport, iph->protocol);
    bool installed = false;

#pragma unroll
    for (int i = 0; i < NAPT_PROBE_LIMIT; i++) {
      __u32 candidate_host = 1024 + ((seed + i) % (65536 - 1024));
      __be16 candidate = bpf_htons((__u16)candidate_host);

      // The Echo Reply repeats the Identifier we allocated, so both
      // slots of the reverse key hold the candidate instead of the
      // swapped port pair a TCP or UDP flow produces.
      struct ct_key rev_key = {
          .scope = CT_SCOPE_HOST,
          .saddr = iph->daddr,
          .daddr = host_napt_ip,
          .sport = is_icmp ? candidate : dport,
          .dport = candidate,
          .proto = iph->protocol,
      };
      struct ct_val rev_val = {
          .new_saddr = 0,
          .new_daddr = iph->saddr,
          .new_sport = 0,
          .new_dport = sport,
          .next_subnet_id = subnet - subnet, // placeholder zero; set below
          .action = CT_ACTION_NAPT_IN,
          .state = init_state,
          .flags_seen = 0,
          .last_seen_ns = now,
      };
      // next_subnet_id of the reverse entry must point back to the Pod's
      // Subnet so node_ingress can fdb-forward to the pod. We can't know
      // the Pod's subnet_id at this site by VPC alone — we'll fill it
      // from `subnet`'s Subnet ID looked up via ifindex_subnet.
      // Simpler: the caller's subnet_id is what we already have in scope
      // via ifindex_subnet, but pod_egress receives `subnet` (struct
      // subnet_val). We need the subnet *id*, not vpc_id. Carry it via
      // ifindex_subnet:
      struct ifindex_subnet_key isk = {.ifindex = skb->ifindex};
      const struct ifindex_subnet_val *isv =
          bpf_map_lookup_elem(&ifindex_subnet, &isk);
      if (!isv)
        return TC_ACT_SHOT;
      rev_val.next_subnet_id = isv->subnet_id;

      long rc =
          bpf_map_update_elem(&ct_map, &rev_key, &rev_val, BPF_NOEXIST);
      if (rc == 0) {
        alloc_port = candidate;
        installed = true;
        break;
      }
      seed = napt_rotate_left(seed + 0x9e3779b1, 7);
    }

    if (!installed)
      return TC_ACT_SHOT;

    // Install the forward entry. BPF_ANY because we already verified
    // (via the lookup above) that no NAPT_OUT existed; any racing
    // installer for the same key would have produced an identical val.
    struct ct_val fwd_val = {
        .new_saddr = host_napt_ip,
        .new_daddr = iph->daddr,
        .new_sport = alloc_port,
        .new_dport = dport,
        .next_subnet_id = 0,
        .action = CT_ACTION_NAPT_OUT,
        .state = init_state,
        .flags_seen = init_flags,
        .last_seen_ns = now,
    };
    bpf_map_update_elem(&ct_map, &fwd_key, &fwd_val, BPF_ANY);
  }

  __u8 tcp_flags = 0;
  bool have_tcp_flags = false;
  if (iph->protocol == IPPROTO_TCP) {
    if (ct_read_tcp_flags(iph, data_end, &tcp_flags) == 0)
      have_tcp_flags = true;
  }

  __be32 napt_before_saddr = iph->saddr;
  __be32 napt_before_daddr = iph->daddr;
  __be16 napt_before_sport = sport;
  __be16 napt_before_dport = dport;
  __u8   napt_proto        = iph->protocol;

  if (rewrite_ipv4_addr(skb, /*is_source=*/true, host_napt_ip) < 0)
    return TC_ACT_SHOT;
  if (rewrite_l4_port(skb, /*is_source=*/true, alloc_port) < 0)
    return TC_ACT_SHOT;

  // Trace: NAPT_OUT — internet egress with src rewrite (NAPT). The
  // after-tuple is host-scoped (the underlay sees host_napt_ip).
  {
    struct trace_nat_event __ne = {
        .vpc_id = caller_vpc_id,
        .subnet_id = 0,
        .hook = TRACE_HOOK_POD_EGRESS,
        .reason = TRACE_REASON_NAPT_ALLOCATED,
        .scope = TRACE_SCOPE_VPC,
        .proto = napt_proto,
        .before_saddr = napt_before_saddr,
        .before_daddr = napt_before_daddr,
        .before_sport = napt_before_sport,
        .before_dport = napt_before_dport,
        .after_saddr = host_napt_ip,
        .after_daddr = napt_before_daddr,
        .after_sport = alloc_port,
        .after_dport = napt_before_dport,
    };
    trace_observe_nat(skb, &__ne);
  }

  if (have_tcp_flags) {
    struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &fwd_key);
    if (cv)
      ct_observe_tcp(&fwd_key, cv, tcp_flags);
  }

  // Dispatch via kernel FIB to the host network stack (same shape as
  // handle_snat's tail).
  __u32 egress_ifindex = 0;
  return forward_via_host_fib(skb, &egress_ifindex);
}

// handle_transit resolves a destination the VPC route table handed to a
// TransitGateway. That route only carried the transit route table id
// (overloaded into fib_val.subnet_id, the same field reuse
// FIB_ROUTE_TYPE_NAPT does for its gateway id), so a second LPM lookup
// in the transit table picks the target Subnet. A transit table never
// points at another transit table, so the lookup stops at two levels.
//
// noinline: the transit path is cold and its second lookup is big
// enough that expanding it into the main dispatch would spend verifier
// budget on every packet.
//
// It takes scalars instead of the caller's eth pointer so no packet
// pointer crosses the BPF-to-BPF call boundary; the header is re-derived
// here right before it is written, the way nat_load_iph callers do it.
//
// It returns the destination Subnet VNI and leaves the forward_l2 to the
// caller. Calling forward_l2 here would inline its bpf_tunnel_key into
// this frame, and tc_pod_egress already uses 408 of the kernel's
// 512-byte combined call-stack budget. Subnet VNIs start at 1 (see
// BACKEND_SUBNET_ID_UNDERLAY in maps.h), so 0 means "drop the packet";
// the drop trace is already emitted by then.
static __juneau_bpf_subprog __u32 handle_transit(struct __sk_buff *skb,
                                                 __u32 vpc_id,
                                                 __u32 tgw_table_id,
                                                 __be32 dst_be) {
  void *tgw_inner = bpf_map_lookup_elem(&tgw_fib_map, &tgw_table_id);
  if (!tgw_inner) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, vpc_id);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_TGW_TABLE,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id, 0,
                           tgw_table_id);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id, 0);
    return 0;
  }

  struct fib_key tkey = {
      .prefixlen = 32,
      .dst = dst_be,
  };
  const struct fib_val *tfv = bpf_map_lookup_elem(tgw_inner, &tkey);
  if (!tfv) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, vpc_id);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_TGW_ROUTE,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id, 0,
                           bpf_ntohl(dst_be));
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id, 0);
    return 0;
  }

  if (tfv->type == FIB_ROUTE_TYPE_BLACKHOLE) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, vpc_id);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_BLACKHOLE,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id, 0);
    return 0;
  }

  if (tfv->type != FIB_ROUTE_TYPE_CONNECTED) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, vpc_id);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id, 0);
    return 0;
  }

  __u32 next_subnet_id = tfv->subnet_id;
  __u8 next_smac[ETH_ALEN];
  __builtin_memcpy(next_smac, tfv->smac, ETH_ALEN);

  struct arp_table_key ak = {
      .subnet_id = next_subnet_id,
      .ipaddr = bpf_ntohl(dst_be),
  };
  const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
  if (!av) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, vpc_id);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_ARP,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id,
                           next_subnet_id, bpf_ntohl(dst_be));
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, vpc_id,
                       next_subnet_id);
    return 0;
  }

  void *data = nat_skb_data(skb);
  void *data_end = skb_data_end(skb);
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return 0;

  __builtin_memcpy(eth->h_dest, av->mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, next_smac, ETH_ALEN);

  return next_subnet_id;
}

static __always_inline int handle_l3(struct __sk_buff *skb, struct ethhdr *eth,
                                     const struct subnet_val *subnet) {
  void *data_end = skb_data_end(skb);
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  __u32 dst_be = iph->daddr; // keep network order for LPM trie

  // Reply leg of a Service flow whose forward DNAT was performed by
  // an external in-kernel kube-proxy iptables ruleset (rather than by
  // handle_service below) surfaces here as (src=Pod, dst=Node
  // underlay IP). Node underlay IPs live outside every Subnet CIDR so
  // fib_map cannot resolve them; without this branch the reply would
  // drop at the fib_map miss and the kernel's conntrack would never
  // see the response to un-DNAT it back into the caller's ClusterIP.
  //
  // Two sub-cases with different handling:
  //
  //  1. dst == THIS Node's own underlay IP (caller was a host-network
  //     process on the same Node, e.g. kube-apiserver → ClusterIP →
  //     locally-scheduled Pod). The reply is delivered locally via
  //     the INPUT chain, which does not traverse FORWARD, so
  //     KUBE-FORWARD's ctstate INVALID drop is not a concern. Hand
  //     the packet back to the kernel with TC_ACT_OK; kernel conntrack
  //     un-DNATs it into the caller's socket. bpf_fib_lookup cannot
  //     help here — it returns BPF_FIB_LKUP_RET_NOT_FWDED for RTN_LOCAL
  //     destinations because "forwarding to self" is not a thing.
  //
  //  2. dst == a REMOTE Node's underlay IP (caller was on Node A,
  //     backend Pod is on Node B, juneau's own data plane cross-Node'd
  //     the SYN so this Node's conntrack has no forward-leg entry).
  //     Netfilter marks the reply INVALID in FORWARD and the KUBE-
  //     FORWARD rule drops it before it can reach eno1. Resolve the
  //     underlay egress interface / neighbor via bpf_fib_lookup and
  //     bpf_redirect past FORWARD + POSTROUTING; the remote Node's
  //     conntrack un-DNATs the reply as usual.
  if (bpf_map_lookup_elem(&node_underlays, &dst_be)) {
    __u32 uk = 0;
    const __u32 *self_underlay = bpf_map_lookup_elem(&host_underlay, &uk);
    if (self_underlay && *self_underlay != 0 && *self_underlay == dst_be) {
      // The Pod sent the reply to its default-gateway MAC (subnet
      // gw_mac); eth_type_trans on the host-side veth therefore tagged
      // skb->pkt_type=PACKET_OTHERHOST at reception. With dst now the
      // local NodeIP the kernel's ip_rcv_core would drop with
      // reason=OTHERHOST unless we reset pkt_type — same fix-up
      // handle_service_host_local applies for its forward leg.
      if (bpf_skb_change_type(skb, PACKET_HOST) < 0)
        return TC_ACT_SHOT;
      __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, subnet->vpc_id);
      trace_emit_pass_kernel_l3(skb, __tid, TRACE_HOOK_POD_EGRESS,
                                TRACE_SCOPE_VPC, subnet->vpc_id, 0);
      return TC_ACT_OK;
    }

    __u32 egress_ifindex = 0;
    int fib_ret = forward_via_host_fib(skb, &egress_ifindex);
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, subnet->vpc_id);
    if (fib_ret == TC_ACT_SHOT) {
      trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                         subnet->vpc_id, 0);
      return TC_ACT_SHOT;
    }
    trace_emit_redirect_l3(skb, __tid, TRACE_REASON_REDIRECT_IFINDEX,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                           subnet->vpc_id, 0, egress_ifindex);
    return fib_ret;
  }

  __u32 tid = subnet->table_id;
  void *fib_inner_map = bpf_map_lookup_elem(&fib_map, &tid);
  if (!fib_inner_map) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, subnet->vpc_id);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_FIB_TABLE,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                           subnet->vpc_id, 0, tid);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                       subnet->vpc_id, 0);
    return TC_ACT_SHOT;
  }

  struct fib_key fkey = {
      .prefixlen = 32,
      .dst = dst_be,
  };
  const struct fib_val *fv = bpf_map_lookup_elem(fib_inner_map, &fkey);
  if (!fv) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, subnet->vpc_id);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_FIB_ROUTE,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                           subnet->vpc_id, 0, bpf_ntohl(dst_be));
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                       subnet->vpc_id, 0);
    return TC_ACT_SHOT;
  }

  if (fv->type == FIB_ROUTE_TYPE_CONNECTED ||
      fv->type == FIB_ROUTE_TYPE_PEERING) {
    struct arp_table_key ak = {
        .subnet_id = fv->subnet_id,
        .ipaddr = bpf_ntohl(dst_be),
    };
    const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
    if (!av)
      return TC_ACT_SHOT;

    __builtin_memcpy(eth->h_dest, av->mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);

    return forward_l2(skb, eth, subnet->vpc_id, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_ENDPOINT) {
    __builtin_memcpy(eth->h_dest, fv->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);

    return forward_l2(skb, eth, subnet->vpc_id, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_INTERNET_GATEWAY)
    return handle_snat(skb, eth, iph);

  // One call site on purpose: handle_service is __always_inline and pulls
  // in handle_service_host_local / _host_remote / _shared, so a second
  // call would duplicate all of that against the verifier's budget.
  if (fv->type == FIB_ROUTE_TYPE_SERVICE ||
      fv->type == FIB_ROUTE_TYPE_VPC_ENDPOINT)
    return handle_service(skb, eth, iph, subnet,
                          fv->type == FIB_ROUTE_TYPE_VPC_ENDPOINT);

  if (fv->type == FIB_ROUTE_TYPE_NAPT)
    return handle_napt(skb, eth, iph, subnet, fv->subnet_id);

  if (fv->type == FIB_ROUTE_TYPE_TRANSIT) {
    __u32 transit_subnet_id =
        handle_transit(skb, subnet->vpc_id, fv->subnet_id, dst_be);
    if (transit_subnet_id == 0)
      return TC_ACT_SHOT;
    return forward_l2(skb, eth, subnet->vpc_id, transit_subnet_id);
  }

  return TC_ACT_SHOT;
}

// handle_virtual_service classifies Pod egress packets destined for a
// per-Subnet virtual service (DNS today; arbitrary L7 services in the
// future) and hands them off to the daemon's userspace packet plane via
// the TAP device whose ifindex was programmed into virtual_service_map
// at registration time.
//
// On a hit, return-path metadata (Pod ifindex, Pod MAC, service MAC,
// vpc_id) is captured into virtual_service_flow_map so the daemon can
// build the AF_PACKET sockaddr_ll for the response without consulting
// the host routing table — required because Pod IPs may overlap across
// VPCs and Linux has no native vpc_id dimension.
//
// Return value semantics:
//   * `1`  — packet was dispatched (caller MUST return *out as the TC verdict)
//   * `0`  — no virtual service matched; caller continues with its
//            existing dispatch (gw-MAC / forward_l2)
//   * `<0` — fatal parse error; caller MUST return TC_ACT_SHOT
static __always_inline int
handle_virtual_service(struct __sk_buff *skb, struct ethhdr *eth,
                       struct iphdr *iph, void *data_end, __u32 subnet_id,
                       __u32 vpc_id, int *out) {
  __u8 proto = iph->protocol;
  if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
    return 0;

  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return -1;

  // Bail on fragments other than the first: we cannot read L4 ports so
  // dispatch by 5-tuple is impossible. Letting these fall through to
  // the L2 path drops them via the absent FDB entry without surprising
  // the caller.
  if ((bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0)
    return 0;

  void *l4 = (void *)iph + ihl * 4;
  __be16 dport;
  __be16 sport;
  if (proto == IPPROTO_UDP) {
    struct udphdr *udp = l4;
    if ((void *)(udp + 1) > data_end)
      return -1;
    sport = udp->source;
    dport = udp->dest;
  } else {
    struct tcphdr *tcp = l4;
    if ((void *)(tcp + 1) > data_end)
      return -1;
    sport = tcp->source;
    dport = tcp->dest;
  }

  struct virtual_service_key vk = {
      .subnet_id = subnet_id,
      .dst_ip = iph->daddr,
      .dst_port = dport,
      .proto = proto,
      ._pad = 0,
  };
  const struct virtual_service_val *vv =
      bpf_map_lookup_elem(&virtual_service_map, &vk);
  if (!vv)
    return 0;

  // tap_ifindex == 0 marks a half-initialised registration (entry
  // written before the daemon's packet plane finished bringing up the
  // TAP). Fall through rather than redirect to ifindex 0 and silently
  // drop.
  if (vv->tap_ifindex == 0)
    return 0;

  struct virtual_service_flow_key fk = {
      .subnet_id = subnet_id,
      .src_ip = iph->saddr,
      .dst_ip = iph->daddr,
      .src_port = sport,
      .dst_port = dport,
      .proto = proto,
  };
  struct virtual_service_flow_val fv = {
      .vpc_id = vpc_id,
      .service_id = vv->service_id,
      .pod_ifindex = skb->ifindex,
      .last_seen_ns = bpf_ktime_get_ns(),
  };
  __builtin_memcpy(fv.pod_mac, eth->h_source, ETH_ALEN);
  __builtin_memcpy(fv.service_mac, vv->service_mac, ETH_ALEN);
  // BPF_ANY: refresh on every packet so the daemon's GC sees recent
  // last_seen_ns even for long-lived UDP "flows".
  bpf_map_update_elem(&virtual_service_flow_map, &fk, &fv, BPF_ANY);

  // Stamp subnet_id into iph->id before redirect. The TAP carries no
  // tenant metadata of its own and Pod IPs may overlap across VPCs,
  // so the daemon's dispatcher needs an unambiguous subnet_id to key
  // the flow_map lookup. iph->id is normally a counter for IP
  // fragment reassembly; the daemon never reassembles or forwards the
  // original packet (it builds a fresh response), so overwriting id
  // is safe. MAX_SUBNET caps VNIs at 16384, well within 16 bits.
  //
  if (subnet_id <= 0xFFFF) {
    __be16 old_id = iph->id;
    __be16 sid_be = bpf_htons((__u16)subnet_id);

    // UDP is parsed directly by userspace, but TCP is injected as a
    // complete IPv4 packet into gVisor netstack, which validates the
    // IPv4 header checksum. Keep the packet valid for both consumers.
    if (bpf_l3_csum_replace(skb,
                            sizeof(struct ethhdr) +
                                __builtin_offsetof(struct iphdr, check),
                            old_id, sid_be, sizeof(sid_be)) < 0)
      return -1;

    if (bpf_skb_store_bytes(skb,
                            sizeof(struct ethhdr) +
                                __builtin_offsetof(struct iphdr, id),
                            &sid_be, sizeof(sid_be), 0) < 0)
      return -1;
  }

  *out = bpf_redirect(vv->tap_ifindex, 0);
  return 1;
}

static __always_inline int handle_l2(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = skb_data_end(skb);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  struct ifindex_subnet_key key = {
      .ifindex = skb->ifindex,
  };
  const struct ifindex_subnet_val *val =
      bpf_map_lookup_elem(&ifindex_subnet, &key);
  if (!val) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, 0);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_IFINDEX_SUBNET,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, 0, 0,
                           skb->ifindex);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, 0, 0);
    return TC_ACT_SHOT;
  }

  struct subnet_key skey = {
      .subnet_id = val->subnet_id,
  };
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &skey);
  if (!subnet) {
    __u32 __tid = trace_lookup_id_l3(skb, TRACE_SCOPE_VPC, 0);
    trace_emit_map_miss_l3(skb, __tid, TRACE_REASON_MISS_SUBNET,
                           TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, 0,
                           val->subnet_id, val->subnet_id);
    trace_emit_drop_l3(skb, __tid, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC, 0,
                       val->subnet_id);
    return TC_ACT_SHOT;
  }

  __u16 h_proto = bpf_ntohs(eth->h_proto);

  // Hook-entry trace event. trace_classify_and_emit_enter is a
  // __noinline subprogram (see trace.h) so the verifier counts the
  // call site as a single CALL rather than inlining the body —
  // critical for pod_egress, whose pre-trace insn count already
  // sits near the verifier ceiling. We also keep the returned
  // trace_id so downstream drop/redirect/policy sites can emit
  // events without re-classifying.
  __u32 __trace_id = 0;
  {
    struct trace_hook_ctx __ctx = {
        .reason = TRACE_REASON_ENTER_POD_EGRESS,
        .hook = TRACE_HOOK_POD_EGRESS,
        .vpc_id = subnet->vpc_id,
        .subnet_id = val->subnet_id,
        .scope = TRACE_SCOPE_VPC,
    };
    __trace_id = trace_classify_and_emit_enter(skb, &__ctx);
  }

  if (h_proto == ETH_P_ARP)
    return handle_arp(skb, data_end, eth, val->subnet_id, subnet);

  // Apply forward DNAT recorded in conntrack for established Service
  // flows. DNAT rewrites the destination IP and must re-route via FIB to
  // find the new next-hop. Reverse SNAT lives in pod_ingress on the
  // destination veth, so this program does nothing for non-DNAT packets.
  if (h_proto == ETH_P_IP) {
    // host-network Service backend が同居するノードで、apiserver か
    // らの reply (NodeIP→PodIP) は host stack 経由で
    // juneau_node_h → juneau_node に着信する。reverse 書き戻しは
    // この入口で完結させ、Pod の veth に fdb で配送する。
    int snapt_rc = TC_ACT_OK;
    int snapt_hit = apply_conntrack_svc_napt_in(skb, &snapt_rc);
    if (snapt_hit < 0) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                         subnet->vpc_id, val->subnet_id);
      return TC_ACT_SHOT;
    }
    if (snapt_hit == 1)
      return snapt_rc;

    // Same-Node reply leg of a shared-Service flow: backend Pod is
    // sending to a SNAT IP that the same Node minted on the forward
    // path. Reverse the rewrite here so the reply skips VXLAN entirely
    // and terminates at the caller Pod's veth via fdb.
    int shared_rc = TC_ACT_OK;
    int shared_hit = apply_conntrack_svc_shared_in(skb, subnet, &shared_rc);
    if (shared_hit < 0) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                         subnet->vpc_id, val->subnet_id);
      return TC_ACT_SHOT;
    }
    if (shared_hit == 1)
      return shared_rc;

    // LoadBalancer reverse NAT (Phase 7): the backend Pod is sending
    // a reply to the original external client. Rewriting saddr from
    // PodIP to VIP here ensures the client sees the VIP as the
    // response source.
    int lb_rc = apply_conntrack_lb_rev_nat(skb, subnet->vpc_id);
    if (lb_rc < 0) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                         subnet->vpc_id, val->subnet_id);
      return TC_ACT_SHOT;
    }
    if (lb_rc == 1) {
      // Emit the reverse-NAT trace event populated by lb_rev_nat into
      // pod_egress_nat_scratch. We invoke trace_observe_nat from this
      // call site (inlined into tc_pod_egress) so the chain stays
      // 2 frames — calling it from inside lb_rev_nat would be a
      // 3-frame chain that overflows the verifier's 512-byte budget.
      __u32 lb_zero = 0;
      struct trace_nat_event *lb_ne =
          bpf_map_lookup_elem(&pod_egress_nat_scratch, &lb_zero);
      if (lb_ne)
        trace_observe_nat(skb, lb_ne);

      // This is the reply leg of an externally-originated LB flow, not a
      // new VPC egress flow. Send it directly through the host FIB so a
      // VPC default route cannot apply NATGateway NAPT to the VIP.
      __u32 lb_ifindex = 0;
      return forward_via_host_fib(skb, &lb_ifindex);
    }

    // Unified policy stage: NetworkACL → SecurityGroup → CT install.
    // Runs BEFORE apply_conntrack_dnat so each layer evaluates the
    // user-visible 5-tuple (e.g. Service ClusterIP), not the
    // rewritten backend IP. -1/-2 are terminal DENY / internal error;
    // 0 means "established flow short-circuited" or "no enforcement";
    // 1 means "admitted on first packet, CT installed".
    int policy_rc =
        apply_policy(skb, POLICY_HOOK_POD_EGRESS, subnet->vpc_id,
                     subnet->acl_id, __trace_id, val->subnet_id);
    if (policy_rc < 0) {
      // -1 = ACL deny, -3 = SG deny, -2 = internal error.
      // Each maps to its own trace reason so the timeline names the
      // policy layer that actually rejected the packet.
      __u32 reason = TRACE_REASON_DROP_SHOT;
      if (policy_rc == -1)
        reason = TRACE_REASON_POLICY_ACL_DROP;
      else if (policy_rc == -3)
        reason = TRACE_REASON_POLICY_SG_DROP;
      trace_emit_drop_l3(skb, __trace_id, reason, TRACE_HOOK_POD_EGRESS,
                         TRACE_SCOPE_VPC, subnet->vpc_id, val->subnet_id);
      return TC_ACT_SHOT;
    }

    int rc = apply_conntrack_dnat(skb, subnet->vpc_id);
    if (rc < 0) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                         subnet->vpc_id, val->subnet_id);
      return TC_ACT_SHOT;
    }

    // The helper reloaded skb->data internally, so refresh our local
    // eth/iph/data_end from skb before continuing with the dispatch.
    struct iphdr *iph = load_iph(skb);
    if (!iph) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                         subnet->vpc_id, val->subnet_id);
      return TC_ACT_SHOT;
    }
    eth = (struct ethhdr *)((void *)iph - sizeof(struct ethhdr));
    data_end = skb_data_end(skb);

    if (rc == 1) {
      // CT-cached DNAT applied. dispatch_after_dnat will redirect; we
      // emit the DNAT_APPLIED event here since we no longer have the
      // before-NAT tuple available downstream. The before-tuple was
      // overwritten by apply_conntrack_dnat — we approximate by using
      // the post-NAT tuple as both before and after; the more
      // detailed emit happens at the actual NAT decision in
      // handle_service / handle_service_shared.
      //
      // Use the map-miss helper (TRACE_VERDICT_OK) rather than the
      // drop helper: this is the success path. Earlier code used
      // trace_emit_drop_l3 which mislabelled the timeline event with
      // [DROP].
      trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_DNAT_APPLIED,
                             TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                             subnet->vpc_id, val->subnet_id, 0);
      return dispatch_after_dnat(skb, eth, iph, subnet->vpc_id,
                                 subnet->table_id, iph->daddr);
    }

    // Virtual service classifier runs after Service-DNAT but before the
    // gw-MAC / forward_l2 split. DNS and any future Subnet-local
    // virtual service VIPs use a per-Subnet service MAC distinct from
    // gw_mac, so they would otherwise fall through to forward_l2 and
    // get dropped on the missing FDB entry.
    int virt_rc = TC_ACT_OK;
    int virt_hit = handle_virtual_service(skb, eth, iph, data_end,
                                          val->subnet_id, subnet->vpc_id,
                                          &virt_rc);
    if (virt_hit < 0) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                         TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                         subnet->vpc_id, val->subnet_id);
      return TC_ACT_SHOT;
    }
    if (virt_hit == 1) {
      trace_emit_redirect_l3(skb, __trace_id, TRACE_REASON_REDIRECT_IFINDEX,
                             TRACE_HOOK_POD_EGRESS, TRACE_SCOPE_VPC,
                             subnet->vpc_id, val->subnet_id, 0);
      return virt_rc;
    }
  }

  bool is_gw = true;
#pragma unroll
  for (int i = 0; i < ETH_ALEN; i++) {
    if (eth->h_dest[i] != subnet->gw_mac[i]) {
      is_gw = false;
      break;
    }
  }
  if (is_gw)
    return handle_l3(skb, eth, subnet);

  return forward_l2(skb, eth, subnet->vpc_id, val->subnet_id);
}

SEC("tc")
int tc_pod_egress(struct __sk_buff *skb) {
  // Hot-path gate: forces the verifier to load every trace_* map in
  // this program object so daemons can pin them under PIN_BY_NAME at
  // load time. Returns 0 immediately when no session is active.
  (void)trace_is_active();
  return handle_l2(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
