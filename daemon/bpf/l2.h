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
#include "arp.h"
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

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

// L2_TUNNEL_TTL is the outer IP TTL of a frame this node sends over the
// overlay. It matches what forward_l2 stamps on Subnet traffic.
#define L2_TUNNEL_TTL 64

// l2_port is where a frame came from, which is what both the flood and
// the unicast path need to know to keep the segment from feeding
// itself.
struct l2_port {
  __u32 vni;
  // in_ifindex is the veth the frame arrived on, and 0 when the
  // overlay delivered it.
  __u32 in_ifindex;
  // from_overlay says the frame has already crossed the overlay once,
  // so this node must not put it back on.
  bool from_overlay;
};

// l2_gw_hops reads the hop count a frame carries.
static __always_inline __u32 l2_gw_hops(const struct __sk_buff *skb) {
  return (skb->mark & L2_MARK_GW_HOP_MASK) >> L2_MARK_GW_HOP_SHIFT;
}

// l2_gw_take_hop counts one more hand-off to a gateway port and reports
// whether the frame may take it. A frame at the limit is refused, which
// is what stops a loop between the gateway and something on the segment
// that keeps sending the frame back.
static __always_inline bool l2_gw_take_hop(struct __sk_buff *skb) {
  __u32 hops = l2_gw_hops(skb);
  if (hops >= L2_GW_MAX_HOPS)
    return false;
  hops++;
  skb->mark = (skb->mark & ~L2_MARK_GW_HOP_MASK) |
              ((hops << L2_MARK_GW_HOP_SHIFT) & L2_MARK_GW_HOP_MASK);
  return true;
}

// l2_arp_for returns the address table of one segment.
static __always_inline struct l2_arp_inner_map *l2_arp_for(__u32 vni) {
  return bpf_map_lookup_elem(&l2_arp, &vni);
}

// l2_is_gateway_mac reports whether a MAC is the one the gateway of the
// segment signs with. Every node answers on that same address, so the
// entry read here is this node's copy of an identity they all share.
static __always_inline bool l2_is_gateway_mac(const __u8 *mac, __u32 vni) {
  struct l2_gateway_key gkey = {.vni = vni};
  const struct l2_gateway_val *gateway =
      bpf_map_lookup_elem(&l2_gateway, &gkey);
  if (!gateway)
    return false;

#pragma unroll
  for (int i = 0; i < ETH_ALEN; i++) {
    if (mac[i] != gateway->mac[i])
      return false;
  }
  return true;
}

// l2_arp_snoop records the sender of an ARP frame so the gateway can
// address a packet the Vpc sent into the segment.
//
// Every opcode is read, not just the request: a reply and a gratuitous
// announcement both carry the sender pair, and a host that moves
// announces itself before it sends anything else. Nothing is answered
// here. The segment carries the user's own DHCP server, router and
// duplicate-address probes, and a proxy reply would break all three.
//
// It reports whether the frame is a reply addressed to the gateway.
// That one is the answer to a question a gateway asked, and it is the
// only ARP frame the other nodes have to be given rather than left to
// see for themselves; l2_flood_answer is what gives it to them. The
// classification is returned from here because it needs the same parse
// the recording needs, and reading the header twice would pay for it
// twice on every frame the segment carries.
//
// The frame is only read, so the caller may call this before it copies
// the addresses it needs out of the header.
static __always_inline bool l2_arp_snoop(struct __sk_buff *skb, __u32 vni,
                                         const struct ethhdr *eth) {
  if (eth->h_proto != bpf_htons(ETH_P_ARP))
    return false;

  void *data_end = (void *)(long)skb->data_end;
  struct arphdr *arp = (void *)(eth + 1);
  if ((void *)(arp + 1) > data_end)
    return false;
  if (arp->ar_hrd != bpf_htons(ARP_HRD_ETHER))
    return false;
  if (arp->ar_pro != bpf_htons(ARP_PRO_IPV4))
    return false;
  if (arp->ar_hln != ARP_ETH_ALEN || arp->ar_pln != 4)
    return false;

  struct arp_payload *payload = (void *)(arp + 1);
  if ((void *)(payload + 1) > data_end)
    return false;

  struct l2_arp_key key = {.ipv4 = bpf_ntohl(payload->spa)};
  if (key.ipv4 != 0) {
    struct l2_arp_inner_map *table = l2_arp_for(vni);
    if (table) {
      struct l2_arp_val val = {};
      __builtin_memcpy(val.mac, payload->sha, ETH_ALEN);
      bpf_map_update_elem(table, &key, &val, BPF_ANY);
    }
  }

  if (arp->ar_op != bpf_htons(ARP_OP_REPLY))
    return false;
  return l2_is_gateway_mac(eth->h_dest, vni);
}

// l2_arp_probe_for returns the ask-again table of one segment.
static __always_inline struct l2_arp_probe_inner_map *
l2_arp_probe_for(__u32 vni) {
  return bpf_map_lookup_elem(&l2_arp_probe, &vni);
}

// l2_arp_probe_take reports whether the gateway may ask the segment for
// target now, and writes down the ask when it may.
//
// target is in host byte order, the form l2_arp is keyed on.
//
// Two CPUs asking at the same moment can both be let through. The cost
// is one extra frame on the segment, which is far below what the pacing
// is there to prevent, and the alternative is a lock on a table every
// packet for an unresolved address touches.
static __always_inline bool
l2_arp_probe_take(struct l2_arp_probe_inner_map *table, __u32 target) {
  struct l2_arp_probe_key key = {.ipv4 = target};
  __u64 now = bpf_ktime_get_ns();

  struct l2_arp_probe_val *asked = bpf_map_lookup_elem(table, &key);
  if (asked) {
    if (now - asked->asked_ns < L2_ARP_PROBE_INTERVAL_NS)
      return false;
    asked->asked_ns = now;
    return true;
  }

  struct l2_arp_probe_val fresh = {.asked_ns = now};
  return bpf_map_update_elem(table, &key, &fresh, BPF_ANY) == 0;
}

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
  // from_overlay is the same flag l2_port carries. The local walk needs
  // it too, because the gateway port is skipped for a frame the overlay
  // delivered.
  bool from_overlay;
  // gateway_only holds the local walk to the gateway port. The frame is
  // an answer the gateway asked for, which the other nodes have to be
  // given but no workload on this one was waiting for.
  bool gateway_only;
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
// A frame that names neither is not recorded. Every reader of the
// table takes an entry as a place to send to, so an entry that names
// nowhere would turn a flood into a black hole.
//
// A MAC that moves is followed straight away: the entry is overwritten
// the moment the first frame arrives from its new place. A MAC that
// stays only has its last_seen_ns refreshed, and only once every
// L2_FDB_REFRESH_NS, so a busy port does not write to the table on
// every frame.
//
// The gateway entry is the one place a frame cannot move. It is the
// address of a port juneau made, and a workload that sends from it is
// either confused or trying to take the segment's way out for itself.
//
// Returns 1 when a new place was recorded, 0 otherwise.
static __always_inline int l2_learn(struct l2_fdb_inner_map *table,
                                    const __u8 *mac, __u32 ifindex,
                                    __u32 vtep_ip) {
  if (ifindex == 0 && vtep_ip == 0)
    return 0;

  struct l2_fdb_key key = {};
  __builtin_memcpy(key.mac, mac, ETH_ALEN);

  __u64 now = bpf_ktime_get_ns();
  struct l2_fdb_val *found = bpf_map_lookup_elem(table, &key);
  if (found && (found->flags & L2_FDB_FLAG_GATEWAY))
    return 0;
  if (found && found->ifindex == ifindex && found->vtep_ip == vtep_ip) {
    if (now - found->last_seen_ns >= L2_FDB_REFRESH_NS)
      found->last_seen_ns = now;
    return 0;
  }

  struct l2_fdb_val val = {
      .ifindex = ifindex,
      .vtep_ip = vtep_ip,
      .last_seen_ns = now,
      .flags = 0,
  };
  if (bpf_map_update_elem(table, &key, &val, BPF_ANY) < 0)
    return 0;
  return 1;
}

// l2_flood_local_cb copies the frame to one local veth. Returning 0
// keeps the walk going; bpf_for_each_map_elem rejects anything other
// than 0 or 1.
//
// The gateway port is the one member that takes its copy on ingress:
// everything else on the list is a workload that receives what is put
// on its egress, while the gateway is a port juneau reads from.
//
// It is also skipped for a frame the overlay delivered. Every node that
// holds a port on the segment runs a gateway of its own on the same
// address, so the node the frame started on has already offered it to
// one. Copying it again here would answer a broadcast once per node.
static long l2_flood_local_cb(struct bpf_map *map, const __u32 *key,
                              __u8 *value, struct l2_flood_ctx *fctx) {
  __u32 ifindex = *key;
  if (ifindex == fctx->skip_ifindex)
    return 0;

  __u64 flags = 0;
  if (*value & L2_PORT_FLAG_GATEWAY) {
    if (fctx->from_overlay)
      return 0;
    if (!l2_gw_take_hop(fctx->skb))
      return 0;
    flags = BPF_F_INGRESS;
  } else if (fctx->gateway_only) {
    return 0;
  }

  if (bpf_clone_redirect(fctx->skb, ifindex, flags) < 0)
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

// l2_flood_ports copies the frame to the ports of the segment and
// returns how many copies it made. gateway_only holds the local pass to
// the gateway port; the two wrappers below are what callers use.
//
// A frame the overlay delivered reaches local ports only. The node
// that sent it already copied it to every other node, so sending it
// back out would multiply it without end. This is the split horizon
// rule, and it is the whole reason the caller has to say where the
// frame came from.
//
// The local ports are served first and the remote nodes second, and
// that order is load-bearing: the remote pass stamps a tunnel key on
// the frame, and handing a frame with tunnel metadata to a veth
// crashes the kernel (cilium#19428). Once the remote pass has run,
// nothing hands the frame to a local port again. It is also why a
// caller that wants both a local port and the other nodes has to take
// this path rather than redirect the frame itself: the redirect would
// hand a stamped frame to a veth.
static __always_inline __u32 l2_flood_ports(struct __sk_buff *skb,
                                            const struct l2_port *port,
                                            bool gateway_only) {
  struct l2_flood_ctx fctx = {
      .skb = skb,
      .skip_ifindex = port->in_ifindex,
      .vni = port->vni,
      .vxlan_ifindex = 0,
      .copies = 0,
      .from_overlay = port->from_overlay,
      .gateway_only = gateway_only,
  };

  __u32 vni = port->vni;
  struct l2_bum_local_inner_map *local = bpf_map_lookup_elem(&l2_bum_local, &vni);
  if (local)
    bpf_for_each_map_elem(local, l2_flood_local_cb, &fctx, 0);

  if (port->from_overlay)
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

// l2_flood copies the frame to every port of the segment but the one it
// came in on.
static __always_inline __u32 l2_flood(struct __sk_buff *skb,
                                      const struct l2_port *port) {
  return l2_flood_ports(skb, port, false);
}

// l2_flood_answer copies an ARP reply addressed to the gateway to the
// gateway port of this node and to every other node.
//
// The other nodes need it because the gateway is anycast. Each node
// runs one on the same address and the same MAC, so a host answers
// whichever gateway is local to it, and only that node would learn the
// address. The node that asked is the node the packet from the Vpc was
// routed on, which is a different one whenever the client and the host
// sit apart, and it would go on asking forever.
//
// Only the reply travels. A request is answered by the gateway that
// received it, and everything else on the segment is the workloads'
// own business.
//
// The other nodes read the address out of it and drop it, in the L2
// branch of vxlan_ingress. Nothing sends it on from there, so it cannot
// go round.
static __always_inline __u32 l2_flood_answer(struct __sk_buff *skb,
                                             const struct l2_port *port) {
  return l2_flood_ports(skb, port, true);
}

// L2_ARP_FRAME_LEN is the length of an Ethernet/IPv4 ARP frame: the
// header, the fixed part and the four addresses.
#define L2_ARP_FRAME_LEN                                                       \
  (sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arp_payload))

// l2_arp_request turns the frame into an ARP request from sender_mac
// and copies it to every port of the segment but the one it came in on.
// It returns how many copies it made, or -1 when the frame could not be
// turned into a request.
//
// The frame the caller is holding is reused rather than a new one
// built, because a BPF program has no way to make a frame of its own:
// the flood copies whatever skb it was handed. What is left of the
// original is the caller's to drop, and dropping it is why the packet
// that needed the answer is lost. A router would hold that packet until
// the reply came back; there is nowhere in BPF to hold an skb.
//
// bpf_skb_change_tail invalidates every pointer into the frame, so the
// caller must copy out whatever it still needs before calling this, and
// the bounds are read again here.
//
// sender_ip and target_ip are in network byte order, the form they are
// written to the wire in.
static __always_inline int l2_arp_request(struct __sk_buff *skb,
                                          const struct l2_port *from,
                                          const __u8 *sender_mac,
                                          __be32 sender_ip,
                                          __be32 target_ip) {
  if (bpf_skb_change_tail(skb, L2_ARP_FRAME_LEN, 0) < 0)
    return -1;

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;
  struct arphdr *arp = (void *)(eth + 1);
  if ((void *)(arp + 1) > data_end)
    return -1;
  struct arp_payload *payload = (void *)(arp + 1);
  if ((void *)(payload + 1) > data_end)
    return -1;

  __builtin_memset(eth->h_dest, 0xff, ETH_ALEN);
  __builtin_memcpy(eth->h_source, sender_mac, ETH_ALEN);
  eth->h_proto = bpf_htons(ETH_P_ARP);

  arp->ar_hrd = bpf_htons(ARP_HRD_ETHER);
  arp->ar_pro = bpf_htons(ARP_PRO_IPV4);
  arp->ar_hln = ARP_ETH_ALEN;
  arp->ar_pln = 4;
  arp->ar_op = bpf_htons(ARP_OP_REQUEST);

  __builtin_memcpy(payload->sha, sender_mac, ETH_ALEN);
  payload->spa = sender_ip;
  __builtin_memset(payload->tha, 0, ETH_ALEN);
  payload->tpa = target_ip;

  return (int)l2_flood(skb, from);
}

// l2_forward is what l2_forward_unicast decided. verdict is the value
// the program returns; reason and target_ifindex are what the trace
// event is stamped with.
struct l2_forward {
  int verdict;
  __u32 reason;
  __u32 target_ifindex;
};

// l2_forward_unicast sends the frame to the port that holds the
// destination MAC. It reports true when it placed the frame, and false
// when this node has nowhere to put it and the caller has to flood
// instead.
//
// Two of its answers come from where the frame arrived rather than
// from the table:
//
//   - A MAC that lives on the very port the frame came in on is
//     dropped. A switch never sends a frame back out of the port it
//     came from, and a workload running its own bridge behind the NIC
//     would send it right back.
//   - A MAC on another node is not reachable from a frame the overlay
//     delivered. The node that sent it can reach that node directly,
//     so relaying would put the frame on the overlay a second time and
//     teach the far node the wrong place for the source MAC. Falling
//     back to the local flood is what a switch does with a frame it
//     cannot place.
//
// The gateway port is the one MAC handed to an ingress rather than an
// egress: the frame is addressed to the router, so the router has to
// receive it. BPF_F_INGRESS is what makes the kernel deliver it that
// way; with flags 0 it would run the port's egress and leak out of the
// veth peer into the host stack.
static __always_inline bool l2_forward_unicast(struct __sk_buff *skb,
                                               struct l2_fdb_inner_map *table,
                                               const __u8 *dst_mac,
                                               const struct l2_port *port,
                                               struct l2_forward *out) {
  struct l2_fdb_key key = {};
  __builtin_memcpy(key.mac, dst_mac, ETH_ALEN);

  const struct l2_fdb_val *entry = bpf_map_lookup_elem(table, &key);
  if (!entry)
    return false;

  if (entry->ifindex != 0) {
    if (entry->ifindex == port->in_ifindex) {
      out->verdict = TC_ACT_SHOT;
      out->reason = TRACE_REASON_L2_HAIRPIN_DROP;
      out->target_ifindex = entry->ifindex;
      return true;
    }
    if (entry->flags & L2_FDB_FLAG_GATEWAY) {
      if (!l2_gw_take_hop(skb)) {
        out->verdict = TC_ACT_SHOT;
        out->reason = TRACE_REASON_L2_GW_LOOP_DROP;
        out->target_ifindex = entry->ifindex;
        return true;
      }
      out->verdict = bpf_redirect(entry->ifindex, BPF_F_INGRESS);
      out->reason = TRACE_REASON_REDIRECT_IFINDEX;
      out->target_ifindex = entry->ifindex;
      return true;
    }
    out->verdict = bpf_redirect(entry->ifindex, 0);
    out->reason = TRACE_REASON_REDIRECT_IFINDEX;
    out->target_ifindex = entry->ifindex;
    return true;
  }

  if (port->from_overlay)
    return false;

  __u32 vx_key = 0;
  const __u32 *vx_if = bpf_map_lookup_elem(&vxlan_ifindex, &vx_key);
  if (!vx_if || *vx_if == 0) {
    out->verdict = TC_ACT_SHOT;
    out->reason = TRACE_REASON_DROP_SHOT;
    return true;
  }

  struct bpf_tunnel_key tkey = {};
  tkey.remote_ipv4 = entry->vtep_ip;
  tkey.tunnel_id = port->vni;
  tkey.tunnel_ttl = L2_TUNNEL_TTL;
  if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0) {
    out->verdict = TC_ACT_SHOT;
    out->reason = TRACE_REASON_DROP_SHOT;
    return true;
  }

  out->verdict = bpf_redirect(*vx_if, 0);
  out->reason = TRACE_REASON_REDIRECT_VXLAN;
  out->target_ifindex = *vx_if;
  return true;
}

#endif // JUNEAU_BPF_L2_H
