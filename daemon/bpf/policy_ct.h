// Conntrack for the policy stage. See policy_ct_map in maps.h for why
// policy admission does not share ct_map.
//
// The TCP state machine is not duplicated here: ct.h owns it and both
// tables step through the same states, which is also what lets one
// user-space GC sweep both.
#ifndef JUNEAU_BPF_POLICY_CT_H
#define JUNEAU_BPF_POLICY_CT_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "ct.h"
#include "maps.h"

// __juneau_bpf_subprog mirrors the macro in trace.h. Defined locally
// here so policy_ct.h does not have to include trace.h.
#ifndef __juneau_bpf_subprog
#define __juneau_bpf_subprog __attribute__((noinline)) __attribute__((used))
#endif

// policy_ct_peer_hook returns the enforcement point that sees the same
// flow from the other side. Installing under both hooks is what makes
// a reply packet short-circuit at the hook that admitted it.
static __always_inline __u8 policy_ct_peer_hook(__u8 hook) {
  if (hook == POLICY_HOOK_POD_EGRESS)
    return POLICY_HOOK_POD_INGRESS;
  return POLICY_HOOK_POD_EGRESS;
}

// policy_ct_epoch reads the current policy generation. The lookup
// cannot fail on an ARRAY map at index 0; the branch is there because
// the verifier demands it.
static __always_inline __u32 policy_ct_epoch(void) {
  __u32 index = 0;
  const __u32 *epoch = bpf_map_lookup_elem(&policy_epoch_map, &index);
  if (!epoch)
    return 0;
  return *epoch;
}

// policy_ct_reverse_key mirrors the tuple and moves it to the peer
// hook: the same flow, as the other enforcement point sees it. One
// hook always owns this pair, so installing it and closing it build
// the key the same way.
static __always_inline struct policy_ct_key
policy_ct_reverse_key(const struct policy_ct_key *key) {
  struct policy_ct_key rev = {
      .epoch = key->epoch,
      .scope = key->scope,
      .saddr = key->daddr,
      .daddr = key->saddr,
      .sport = key->dport,
      .dport = key->sport,
      .proto = key->proto,
      .hook = policy_ct_peer_hook(key->hook),
  };
  return rev;
}

static __always_inline struct policy_ct_key
policy_ct_build_key(__u8 hook, __u32 epoch, __u32 vpc_id, __be32 saddr, __be32 daddr,
                    __be16 sport, __be16 dport, __u8 proto) {
  struct policy_ct_key key = {
      .epoch = epoch,
      .scope = vpc_id,
      .saddr = saddr,
      .daddr = daddr,
      .sport = sport,
      .dport = dport,
      .proto = proto,
      .hook = hook,
  };
  return key;
}

// policy_ct_install writes the admission for both directions of the
// flow, as seen from one enforcement point: fwd_key as given, plus the
// inverted tuple under the peer hook.
//
// Marked as a BPF-to-BPF subprogram (noinline) so the key and value it
// builds live in their own stack frame. Re-using the caller's fwd key
// (already built for the short-circuit lookup) keeps the combined
// call-chain stack under the kernel's 512-byte ceiling.
static __juneau_bpf_subprog void
policy_ct_install(const struct policy_ct_key *fwd_key, __u8 init_state,
                  __u8 init_flags) {
  struct policy_ct_val val = {
      .state = init_state,
      .flags_seen = init_flags,
      .last_seen_ns = bpf_ktime_get_ns(),
  };
  bpf_map_update_elem(&policy_ct_map, fwd_key, &val, BPF_ANY);

  struct policy_ct_key rev_key = policy_ct_reverse_key(fwd_key);
  bpf_map_update_elem(&policy_ct_map, &rev_key, &val, BPF_ANY);
}

// policy_ct_observe_tcp records flags, advances the state, and on
// CLOSED removes the pair this enforcement point installed. Only that
// pair is removed: the other hook keeps its own entries and closes
// them when it sees the same handshake.
//
// The two deletes are written out here instead of in a shared helper.
// This function is inlined deep inside tc_pod_egress, and a noinline
// call taking a stack pointer from there made the verifier's state
// search blow past the 1,000,000 instruction limit.
static __always_inline void
policy_ct_observe_tcp(const struct policy_ct_key *self,
                      struct policy_ct_val *pv, __u8 flags) {
  pv->flags_seen |= flags & TCP_FLAG_TRACKED;
  __u8 next = ct_derive_next_state(pv->state, flags);
  pv->state = next;
  if (next != CT_STATE_CLOSED)
    return;

  struct policy_ct_key opp = policy_ct_reverse_key(self);
  bpf_map_delete_elem(&policy_ct_map, &opp);
  bpf_map_delete_elem(&policy_ct_map, self);
}

#endif // JUNEAU_BPF_POLICY_CT_H
