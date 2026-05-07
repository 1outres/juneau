// L2 / underlay forwarding helpers shared across TC programs.
//
// The data plane has multiple call sites (LB, Service NAPT, ElasticIP DNAT,
// shared-Service reverse path) that all want the same primitive: "given a
// rewritten packet and a destination Subnet, dispatch via fdb to the right
// veth, or VXLAN-tunnel to the remote Node hosting the destination". The
// helper lives in a header so each program compilation unit inlines its
// own copy — eBPF programs are compiled independently and cannot link to
// shared object files.
#ifndef JUNEAU_BPF_FORWARD_H
#define JUNEAU_BPF_FORWARD_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "trace.h"

#ifndef FORWARD_ETH_ALEN
#define FORWARD_ETH_ALEN 6
#endif

#ifndef FORWARD_TC_ACT_OK
#define FORWARD_TC_ACT_OK 0
#endif
#ifndef FORWARD_TC_ACT_SHOT
#define FORWARD_TC_ACT_SHOT 2
#endif

// forward_l2 dispatches `skb` to the next stage based on the destination
// Subnet's fdb entry for `eth->h_dest`. Three outcomes:
//
//   1. fdb hit + ifindex != 0  → bpf_redirect to that local ifindex
//      (the destination Pod / NetworkInterface lives on this Node).
//   2. fdb hit + ifindex == 0  → VXLAN-encapsulate to fdb_val.vtep_ip
//      with tunnel_id=subnet_id and bpf_redirect to vxlan_ifindex
//      (the destination lives on a remote Node).
//   3. fdb miss                → emit a drop trace and return TC_ACT_SHOT.
//
// Trace events are emitted under the HOST scope; callers that need a
// VPC-scoped trace are expected to emit their own enter/redirect events
// before / after invoking this helper. The trace_id argument may be 0
// to suppress all events.
static __always_inline int forward_l2(struct __sk_buff *skb, struct ethhdr *eth,
                                      __u32 subnet_id, __u32 trace_id) {
  struct fdb_key fk = {};
  fk.subnet_id = subnet_id;
  __builtin_memcpy(fk.mac, eth->h_dest, FORWARD_ETH_ALEN);
  const struct fdb_val *fv = bpf_map_lookup_elem(&fdb, &fk);
  if (!fv) {
    trace_emit_map_miss_l3(skb, trace_id, TRACE_REASON_MISS_FDB,
                           TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                           subnet_id, subnet_id);
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                       subnet_id);
    return FORWARD_TC_ACT_SHOT;
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
    return FORWARD_TC_ACT_SHOT;
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
    return FORWARD_TC_ACT_SHOT;
  }

  trace_emit_redirect_l3(skb, trace_id, TRACE_REASON_REDIRECT_VXLAN,
                         TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                         subnet_id, *vx_if);
  return bpf_redirect(*vx_if, 0);
}

// forward_underlay_to_peer encapsulates `skb` for VXLAN delivery to a
// peer Node's main interface and bpf_redirects onto the host's VXLAN
// device. The packet is left intact (no L2 / L3 / L4 rewrite) so the
// receiver can process the inner frame as if it had landed on its own
// underlay interface — used by the LB owner-redirection path with
// `vni = VNI_UNDERLAY`, but the helper accepts any caller-chosen VNI
// for future cross-Node fast paths.
//
// The peer's underlay IPv4 (`peer_underlay_ip`) is in network byte
// order, matching the value held in the lb_owner_table / node_underlay
// maps. Returns TC_ACT_SHOT on encap failure; on success returns the
// bpf_redirect verdict and the caller should propagate it directly.
static __always_inline int
forward_underlay_to_peer(struct __sk_buff *skb, __be32 peer_underlay_ip,
                         __u32 vni, __u32 trace_id) {
  __u32 vx_key = 0;
  const __u32 *vx_if = bpf_map_lookup_elem(&vxlan_ifindex, &vx_key);
  if (!vx_if || *vx_if == 0) {
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0, vni);
    return FORWARD_TC_ACT_SHOT;
  }

  struct bpf_tunnel_key tkey = {};
  tkey.remote_ipv4 = peer_underlay_ip;
  tkey.tunnel_id = vni;
  tkey.tunnel_ttl = 64;
  tkey.tunnel_tos = 0;

  if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0) {
    trace_emit_drop_l3(skb, trace_id, TRACE_REASON_DROP_SHOT,
                       TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0, vni);
    return FORWARD_TC_ACT_SHOT;
  }

  trace_emit_redirect_l3(skb, trace_id, TRACE_REASON_REDIRECT_VXLAN,
                         TRACE_HOOK_NODE_INGRESS, TRACE_SCOPE_HOST, 0,
                         vni, *vx_if);
  return bpf_redirect(*vx_if, 0);
}

#endif // JUNEAU_BPF_FORWARD_H
