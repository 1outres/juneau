// TCP-aware conntrack helpers. Mirror Go-side daemon/internal/daemon/
// dataplane/ctstate so kernel decisions and user-space GC stay in lock
// step. Hot-path callers must read TCP flags before any L4 rewrite (the
// flags byte sits next to the source/dest ports, which the rewrite
// touches) and call ct_observe_tcp after the rewrite completes so the
// state update reflects the packet that actually leaves this hop.
#ifndef JUNEAU_BPF_CT_H
#define JUNEAU_BPF_CT_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

#define TCP_FLAG_TRACKED \
  (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK)

// read_tcp_flags pulls the flags byte (offset 13 inside tcphdr) by raw
// byte access. vmlinux.h declares struct tcphdr's fin/syn/rst/... as C
// bitfields, which BPF cannot reliably load via field access; raw byte
// reads sidestep that and stay verifier-friendly.
static __always_inline int ct_read_tcp_flags(struct iphdr *iph, void *data_end,
                                             __u8 *out) {
  if (iph->ihl < 5)
    return -1;
  if (iph->protocol != IPPROTO_TCP)
    return -1;
  struct tcphdr *tcp = (void *)iph + iph->ihl * 4;
  if ((void *)(tcp + 1) > data_end)
    return -1;
  *out = ((__u8 *)tcp)[13];
  return 0;
}

// ct_derive_next_state advances cur for a single packet's TCP flags.
// Mirrors ctstate.DeriveNextState in Go.
static __always_inline __u8 ct_derive_next_state(__u8 cur, __u8 flags) {
  if (flags & TCP_FLAG_RST)
    return CT_STATE_CLOSED;
  if (flags & TCP_FLAG_FIN) {
    if (cur == CT_STATE_FIN_WAIT)
      return CT_STATE_CLOSED;
    return CT_STATE_FIN_WAIT;
  }
  if (cur == CT_STATE_NEW && (flags & TCP_FLAG_ACK))
    return CT_STATE_ESTABLISHED;
  return cur;
}

// ct_initial_state_for_syn picks the seed state when handle_service
// installs a brand-new entry. Mirrors ctstate.InitialStateForSYN.
static __always_inline __u8 ct_initial_state_for_syn(__u8 flags) {
  if (flags & TCP_FLAG_SYN)
    return CT_STATE_NEW;
  return CT_STATE_ESTABLISHED;
}

// ct_build_opposite_key derives the peer entry's key from a self entry.
// Forward (DNAT) self: caller→ClusterIP, peer is reverse (SNAT) keyed on
// backend→caller. Reverse self: backend→caller, peer is forward keyed on
// caller→ClusterIP. The asymmetry comes from new_saddr/new_daddr meaning
// different things in the two action types.
static __always_inline void ct_build_opposite_key(const struct ct_key *self,
                                                  const struct ct_val *cv,
                                                  struct ct_key *opp) {
  opp->vpc_id = self->vpc_id;
  opp->proto = self->proto;
  opp->_pad[0] = 0;
  opp->_pad[1] = 0;
  opp->_pad[2] = 0;
  if (cv->action == CT_ACTION_DNAT) {
    opp->saddr = cv->new_daddr;
    opp->daddr = self->saddr;
    opp->sport = cv->new_dport;
    opp->dport = self->sport;
  } else {
    opp->saddr = self->daddr;
    opp->daddr = cv->new_saddr;
    opp->sport = self->dport;
    opp->dport = cv->new_sport;
  }
}

// ct_observe_tcp records flags, advances state, and (on CLOSED) deletes
// both directions. Caller must already have applied the L4 rewrite; we
// only mutate map state here, never the packet.
static __always_inline void ct_observe_tcp(const struct ct_key *self,
                                           struct ct_val *cv, __u8 flags) {
  cv->flags_seen |= flags & TCP_FLAG_TRACKED;
  __u8 next = ct_derive_next_state(cv->state, flags);
  cv->state = next;
  if (next != CT_STATE_CLOSED)
    return;

  struct ct_key opp;
  ct_build_opposite_key(self, cv, &opp);
  bpf_map_delete_elem(&ct_map, &opp);
  bpf_map_delete_elem(&ct_map, self);
}

#endif // JUNEAU_BPF_CT_H
