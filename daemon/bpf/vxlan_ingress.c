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

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// apply_shared_service_reverse handles the cross-Node reply leg of a
// shared-Service flow. When a default-Vpc backend Pod replies to a SNAT
// IP that lives on a *different* Node, the reply travels over VXLAN and
// arrives here. The forward path on the originating Node installed a
// CT_ACTION_SVC_SHARED_IN entry keyed on the backend's reply tuple; we
// reverse the rewrite, re-resolve L2 in the caller's Subnet, and
// redirect to the caller Pod's veth.
//
// Returns 1 when the packet was rewritten and dispatched (the caller
// should return *out_rc), 0 on no matching entry (fall through to fdb-
// driven forwarding), -1 on rewrite failure.
static __always_inline int apply_shared_service_reverse(
    struct __sk_buff *skb, const struct subnet_val *tunnel_subnet,
    int *out_rc) {
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
      .scope = tunnel_subnet->vpc_id,
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = sport,
      .dport = dport,
      .proto = iph->protocol,
  };
  struct ct_val *cv = bpf_map_lookup_elem(&ct_map, &ck);
  if (!cv || cv->action != CT_ACTION_SVC_SHARED_IN)
    return 0;

  // Resolve the caller-side Subnet to find the caller Pod's MAC and the
  // gw_mac to stamp on the reply.
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
  __u32 caller_subnet_id = cv->next_subnet_id;

  // Capture before/after tuple values for the trace event.
  __be32 __nat_before_saddr = iph->saddr;
  __be32 __nat_before_daddr = iph->daddr;
  __be16 __nat_before_sport = sport;
  __be16 __nat_before_dport = dport;
  __u8   __nat_proto        = iph->protocol;
  __be32 __nat_after_saddr  = cv->new_saddr;
  __be32 __nat_after_daddr  = cv->new_daddr;
  __be16 __nat_after_sport  = cv->new_sport;
  __be16 __nat_after_dport  = cv->new_dport;

  if (nat_apply_napt_in_rewrite(skb, cv) < 0)
    return -1;

  // Trace: shared-Service NAPT_IN reverse rewrite.
  {
    struct trace_nat_event __ne = {
        .vpc_id = tunnel_subnet->vpc_id,
        .subnet_id = caller_subnet_id,
        .hook = TRACE_HOOK_VXLAN_INGRESS,
        .reason = TRACE_REASON_REVERSE_NAT_APPLIED,
        .scope = TRACE_SCOPE_VPC,
        .proto = __nat_proto,
        .before_saddr = __nat_before_saddr,
        .before_daddr = __nat_before_daddr,
        .before_sport = __nat_before_sport,
        .before_dport = __nat_before_dport,
        .after_saddr = __nat_after_saddr,
        .after_daddr = __nat_after_daddr,
        .after_sport = __nat_after_sport,
        .after_dport = __nat_after_dport,
    };
    trace_observe_nat(skb, &__ne);
  }

  if (have_tcp_flags) {
    struct ct_val *cv2 = bpf_map_lookup_elem(&ct_map, &ck);
    if (cv2)
      ct_observe_tcp(&ck, cv2, tcp_flags);
  }

  // Re-derive the L2 header after the rewrite (skb pointer reload) and
  // dispatch the packet on the caller Pod's veth via fdb. The fdb entry
  // points at a local ifindex because the caller Pod sits on this same
  // Node — this is the originating Node, where the SNAT IP and the
  // ServiceNATAttachment NetworkEndpoint live.
  void *data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;
  __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

  struct fdb_key fk = {};
  fk.subnet_id = caller_subnet_id;
  __builtin_memcpy(fk.mac, dst_mac, ETH_ALEN);
  const struct fdb_val *fv = bpf_map_lookup_elem(&fdb, &fk);
  if (!fv || fv->ifindex == 0)
    return -1;

  *out_rc = bpf_redirect(fv->ifindex, 0);
  return 1;
}

static __always_inline int tc_vxlan_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  struct bpf_tunnel_key tkey = {};
  if (bpf_skb_get_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0)
    return TC_ACT_SHOT;

  __u32 subnet_id = tkey.tunnel_id & 0xFFFFFF;

  struct subnet_key skey = {.subnet_id = subnet_id};
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &skey);
  if (!subnet) {
    return TC_ACT_SHOT;
  }

  // Hook-entry trace event. Tunnel-decapsulated packets carry the
  // VPC-scoped tuple of the *destination* node, which is what the
  // user sees in the timeline at "vxlan_ingress" stops.
  __u32 __trace_id = 0;
  {
    struct trace_hook_ctx __ctx = {
        .reason = TRACE_REASON_ENTER_VXLAN_INGRESS,
        .hook = TRACE_HOOK_VXLAN_INGRESS,
        .vpc_id = subnet->vpc_id,
        .subnet_id = subnet_id,
        .scope = TRACE_SCOPE_VPC,
    };
    __trace_id = trace_classify_and_emit_enter(skb, &__ctx);
  }

  // Cross-Node reply leg of the shared-Service path: a CT_ACTION_SVC_SHARED_IN
  // entry on this Node tells us we minted the SNAT IP this packet is bound
  // for. Reverse the rewrite and deliver straight to the caller Pod's veth,
  // skipping the regular fdb path that would just hand the packet off to a
  // non-existent local iface for the SNAT IP.
  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    int shared_rc = TC_ACT_OK;
    int shared_hit = apply_shared_service_reverse(skb, subnet, &shared_rc);
    if (shared_hit < 0) {
      trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                      TRACE_HOOK_VXLAN_INGRESS, TRACE_SCOPE_VPC,
                      subnet->vpc_id, subnet_id);
      return TC_ACT_SHOT;
    }
    if (shared_hit == 1) {
      // shared_rc holds the redirect verdict.
      trace_emit_redirect_l3(skb, __trace_id, TRACE_REASON_REDIRECT_IFINDEX,
                          TRACE_HOOK_VXLAN_INGRESS, TRACE_SCOPE_VPC,
                          subnet->vpc_id, subnet_id, 0);
      return shared_rc;
    }
  }

  // Service reverse SNAT lives in pod_ingress, attached to the
  // destination Pod's veth egress. vxlan_ingress just decapsulates and
  // hands the packet to fdb-driven forwarding. The default Subnet (VNI
  // 1) is no longer special-cased: its gw_mac is a cluster-wide LAA and
  // its Pods participate in the standard fdb path like any other Subnet.
  struct fdb_key fk = {};
  fk.subnet_id = subnet_id;
  __builtin_memcpy(fk.mac, eth->h_dest, ETH_ALEN);
  const struct fdb_val *fv = bpf_map_lookup_elem(&fdb, &fk);
  if (!fv) {
    trace_emit_map_miss_l3(skb, __trace_id, TRACE_REASON_MISS_FDB,
                        TRACE_HOOK_VXLAN_INGRESS, TRACE_SCOPE_VPC,
                        subnet->vpc_id, subnet_id, subnet_id);
    trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                    TRACE_HOOK_VXLAN_INGRESS, TRACE_SCOPE_VPC,
                    subnet->vpc_id, subnet_id);
    return TC_ACT_SHOT;
  }

  if (fv->ifindex != 0) {
    trace_emit_redirect_l3(skb, __trace_id, TRACE_REASON_REDIRECT_IFINDEX,
                        TRACE_HOOK_VXLAN_INGRESS, TRACE_SCOPE_VPC,
                        subnet->vpc_id, subnet_id, fv->ifindex);
    return bpf_redirect(fv->ifindex, 0);
  }

  trace_emit_drop_l3(skb, __trace_id, TRACE_REASON_DROP_SHOT,
                  TRACE_HOOK_VXLAN_INGRESS, TRACE_SCOPE_VPC,
                  subnet->vpc_id, subnet_id);
  return TC_ACT_SHOT;
}

SEC("tc")
int tc_vxlan_ingress_entry(struct __sk_buff *skb) {
  // See tc_pod_egress for why this anchor exists.
  (void)trace_is_active();
  return tc_vxlan_ingress(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
