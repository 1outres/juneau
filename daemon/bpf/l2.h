// Forwarding for an L2Network: learn a MAC, send a known one out of the
// port that holds it, copy an unknown one to every other port.
//
// The L2 data plane reads no address, no policy and no conntrack. It is
// deliberately its own set of programs and not a mode of pod_egress:
// pod_egress already spends 58% of the verifier's instruction budget,
// and the flood loop below calls bpf_clone_redirect, which invalidates
// the packet bounds on every call and makes the verifier walk the code
// after it again.
#ifndef JUNEAU_BPF_L2_H
#define JUNEAU_BPF_L2_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "trace.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

// L2_TUNNEL_TTL is the outer IP TTL of a frame this node sends over the
// overlay. It matches what forward_l2 stamps on Subnet traffic.
#define L2_TUNNEL_TTL 64

// l2_flood_ctx is what the two bpf_for_each_map_elem callbacks below
// read. The callback signature has one context pointer, so everything
// they need travels in here.
struct l2_flood_ctx {
  struct __sk_buff *skb;
  // skip_ifindex is the port the frame arrived on. A switch never
  // sends a frame back out of the port it came from.
  __u32 skip_ifindex;
  __u32 vni;
  __u32 vxlan_ifindex;
  __u32 copies;
};

// l2_is_bum reports whether a destination MAC has to reach every port
// rather than one. Broadcast and multicast both have the low bit of
// the first octet set, so one test covers ff:ff:ff:ff:ff:ff, the IPv4
// multicast range 01:00:5e:* and the IPv6 one 33:33:*. Letting
// multicast flood is what a switch without IGMP snooping does, and it
// is what carries neighbor discovery for IPv6 on the segment.
static __always_inline bool l2_is_bum(const __u8 *dst_mac) {
  return (dst_mac[0] & 1) != 0;
}

static __always_inline struct l2_fdb_inner_map *l2_fdb_for(__u32 vni) {
  return bpf_map_lookup_elem(&l2_fdb, &vni);
}

// l2_learn records where a source MAC lives. ifindex names a local
// veth and vtep_ip a remote node; the caller sets exactly one.
//
// A MAC that moves is followed straight away: the entry is overwritten
// the moment the first frame arrives from its new place. A MAC that
// stays only has its last_seen_ns refreshed, and only once every
// L2_FDB_REFRESH_NS, so a busy port does not write to the table on
// every frame.
//
// Returns 1 when a new place was recorded, 0 otherwise.
static __always_inline int l2_learn(struct l2_fdb_inner_map *table,
                                    const __u8 *mac, __u32 ifindex,
                                    __u32 vtep_ip) {
  struct l2_fdb_key key = {};
  __builtin_memcpy(key.mac, mac, ETH_ALEN);

  __u64 now = bpf_ktime_get_ns();
  struct l2_fdb_val *found = bpf_map_lookup_elem(table, &key);
  if (found && found->ifindex == ifindex && found->vtep_ip == vtep_ip) {
    if (now - found->last_seen_ns >= L2_FDB_REFRESH_NS)
      found->last_seen_ns = now;
    return 0;
  }

  struct l2_fdb_val val = {
      .ifindex = ifindex,
      .vtep_ip = vtep_ip,
      .last_seen_ns = now,
  };
  if (bpf_map_update_elem(table, &key, &val, BPF_ANY) < 0)
    return 0;
  return 1;
}

// l2_flood_local_cb copies the frame to one local veth. Returning 0
// keeps the walk going; bpf_for_each_map_elem rejects anything other
// than 0 or 1.
static long l2_flood_local_cb(struct bpf_map *map, const __u32 *key,
                              __u8 *value, struct l2_flood_ctx *fctx) {
  __u32 ifindex = *key;
  if (ifindex == fctx->skip_ifindex)
    return 0;
  if (bpf_clone_redirect(fctx->skb, ifindex, 0) < 0)
    return 0;
  fctx->copies++;
  return 0;
}

// l2_flood_remote_cb copies the frame to one remote node. The tunnel
// key is stamped on the frame before every copy, because the copy
// carries the tunnel metadata of the frame it was made from.
static long l2_flood_remote_cb(struct bpf_map *map, const __u32 *key,
                               __u8 *value, struct l2_flood_ctx *fctx) {
  struct bpf_tunnel_key tkey = {};
  tkey.remote_ipv4 = *key;
  tkey.tunnel_id = fctx->vni;
  tkey.tunnel_ttl = L2_TUNNEL_TTL;

  if (bpf_skb_set_tunnel_key(fctx->skb, &tkey, sizeof(tkey), 0) < 0)
    return 0;
  if (bpf_clone_redirect(fctx->skb, fctx->vxlan_ifindex, 0) < 0)
    return 0;
  fctx->copies++;
  return 0;
}

// l2_flood copies the frame to every port of the segment but the one
// it came in on, and returns how many copies it made.
//
// deliver_remote is false for a frame the overlay delivered. The node
// that sent it already copied it to every other node, so sending it
// back out would multiply it without end. This is the split horizon
// rule, and it is the whole reason the caller has to say where the
// frame came from.
//
// The local ports are served first and the remote nodes second, and
// that order is load-bearing: the remote pass stamps a tunnel key on
// the frame, and handing a frame with tunnel metadata to a veth
// crashes the kernel (cilium#19428). Once the remote pass has run,
// nothing hands the frame to a local port again.
static __always_inline __u32 l2_flood(struct __sk_buff *skb, __u32 vni,
                                      __u32 in_ifindex, bool deliver_remote) {
  struct l2_flood_ctx fctx = {
      .skb = skb,
      .skip_ifindex = in_ifindex,
      .vni = vni,
      .vxlan_ifindex = 0,
      .copies = 0,
  };

  struct l2_bum_local_inner_map *local = bpf_map_lookup_elem(&l2_bum_local, &vni);
  if (local)
    bpf_for_each_map_elem(local, l2_flood_local_cb, &fctx, 0);

  if (!deliver_remote)
    return fctx.copies;

  struct l2_bum_remote_inner_map *remote =
      bpf_map_lookup_elem(&l2_bum_remote, &vni);
  if (!remote)
    return fctx.copies;

  __u32 vx_key = 0;
  const __u32 *vx_if = bpf_map_lookup_elem(&vxlan_ifindex, &vx_key);
  if (!vx_if || *vx_if == 0)
    return fctx.copies;
  fctx.vxlan_ifindex = *vx_if;

  bpf_for_each_map_elem(remote, l2_flood_remote_cb, &fctx, 0);
  return fctx.copies;
}

// l2_forward_unicast sends the frame to the one port that holds the
// destination MAC. Returns the TC verdict, or -1 when the MAC is not
// in the table and the caller has to flood instead.
static __always_inline int l2_forward_unicast(struct __sk_buff *skb,
                                              struct l2_fdb_inner_map *table,
                                              const __u8 *dst_mac, __u32 vni) {
  struct l2_fdb_key key = {};
  __builtin_memcpy(key.mac, dst_mac, ETH_ALEN);

  const struct l2_fdb_val *entry = bpf_map_lookup_elem(table, &key);
  if (!entry)
    return -1;

  if (entry->ifindex != 0)
    return bpf_redirect(entry->ifindex, 0);

  __u32 vx_key = 0;
  const __u32 *vx_if = bpf_map_lookup_elem(&vxlan_ifindex, &vx_key);
  if (!vx_if || *vx_if == 0)
    return TC_ACT_SHOT;

  struct bpf_tunnel_key tkey = {};
  tkey.remote_ipv4 = entry->vtep_ip;
  tkey.tunnel_id = vni;
  tkey.tunnel_ttl = L2_TUNNEL_TTL;
  if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0)
    return TC_ACT_SHOT;

  return bpf_redirect(*vx_if, 0);
}

#endif // JUNEAU_BPF_L2_H
