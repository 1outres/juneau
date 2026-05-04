// Shared BPF trace framework for kubectl-juneau trace.
//
// Every TC program (pod_egress, pod_ingress, vxlan_ingress,
// node_ingress) includes this header to (a) anchor the per-node
// trace maps via PIN_BY_NAME and (b) emit decision-point events
// through a small set of helpers.
//
// The hot path is gated on a single ARRAY-map lookup: when no trace
// session is active, every helper short-circuits before doing any
// real work. Cost on the no-trace path is one map lookup per hook
// entry, which the verifier inlines into a constant offset.
//
// Reason codes match the daemon's debug.proto enum
// `TraceEventReason`. Numbers must stay stable across releases —
// userspace renderers depend on the wire mapping. Add new reasons by
// appending; never renumber.
#ifndef JUNEAU_BPF_TRACE_H
#define JUNEAU_BPF_TRACE_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Verifier budget bounds. Each session consumes one trace_config_map
// slot, up to MAX_TRACE_TUPLES tuple_map slots, and shares the global
// trace_events ringbuf. 16 concurrent sessions is more than any sane
// debug workflow ever needs; raising it costs map memory only.
#ifndef MAX_TRACE_SESSIONS
#define MAX_TRACE_SESSIONS 16
#endif

#ifndef MAX_TRACE_TUPLES
#define MAX_TRACE_TUPLES 4096
#endif

#ifndef MAX_TRACE_EVENTS_BYTES
// 256 KiB ringbuf — power-of-two as required by BPF_MAP_TYPE_RINGBUF.
// Sized for short-lived sessions; userspace drains continuously.
#define MAX_TRACE_EVENTS_BYTES (256 * 1024)
#endif

// ---- Reason codes ---------------------------------------------------
// Layout: 100s = hook entry, 200s = lookup miss, 300s = policy,
// 400s = service / NAT, 500s = terminal verdict. Keep groups
// contiguous so a userspace switch-case stays compact.
#define TRACE_REASON_UNSPECIFIED 0

#define TRACE_REASON_ENTER_POD_EGRESS    100
#define TRACE_REASON_ENTER_POD_INGRESS   101
#define TRACE_REASON_ENTER_VXLAN_INGRESS 102
#define TRACE_REASON_ENTER_NODE_INGRESS  103

#define TRACE_REASON_MISS_IFINDEX_SUBNET 200
#define TRACE_REASON_MISS_SUBNET         201
#define TRACE_REASON_MISS_FIB_TABLE      202
#define TRACE_REASON_MISS_FIB_ROUTE      203
#define TRACE_REASON_MISS_ARP            204
#define TRACE_REASON_MISS_FDB            205
#define TRACE_REASON_MISS_SERVICE        206
#define TRACE_REASON_MISS_BACKEND        207
#define TRACE_REASON_MISS_CONNTRACK      208

#define TRACE_REASON_POLICY_ACL_PASS 300
#define TRACE_REASON_POLICY_ACL_DROP 301
#define TRACE_REASON_POLICY_SG_PASS  302
#define TRACE_REASON_POLICY_SG_DROP  303

#define TRACE_REASON_SERVICE_LOOKUP_HIT       400
#define TRACE_REASON_SERVICE_BACKEND_SELECTED 401
#define TRACE_REASON_DNAT_APPLIED             402
#define TRACE_REASON_SNAT_APPLIED             403
#define TRACE_REASON_NAPT_ALLOCATED           404
#define TRACE_REASON_REVERSE_NAT_APPLIED      405

#define TRACE_REASON_REDIRECT_IFINDEX 500
#define TRACE_REASON_REDIRECT_VXLAN   501
#define TRACE_REASON_PASS_KERNEL      502
#define TRACE_REASON_DROP_SHOT        503

// Hook identifiers. Embedded into trace_event.hook so the userspace
// renderer can attribute events to a specific BPF program without
// re-deriving from the reason code.
#define TRACE_HOOK_POD_EGRESS    1
#define TRACE_HOOK_POD_INGRESS   2
#define TRACE_HOOK_VXLAN_INGRESS 3
#define TRACE_HOOK_NODE_INGRESS  4

// Capture flag bits — mirror TraceCaptureConfig in the CRD. Daemons
// translate user-facing booleans into this bitmask before writing
// trace_config_val.
#define TRACE_CAP_PACKET_META 0x01
#define TRACE_CAP_MAP_MISS    0x02
#define TRACE_CAP_POLICY      0x04
#define TRACE_CAP_NAT         0x08

// Capture levels — Summary < Decision < Verbose. Used by
// trace_should_emit() to gate decision-class events.
#define TRACE_LEVEL_SUMMARY  0
#define TRACE_LEVEL_DECISION 1
#define TRACE_LEVEL_VERBOSE  2

// Verdicts tagged on terminal events.
#define TRACE_VERDICT_OK       0
#define TRACE_VERDICT_DROP     1
#define TRACE_VERDICT_REDIRECT 2

// Tuple keyspace.
#define TRACE_SCOPE_HOST 0
#define TRACE_SCOPE_VPC  1

// ---- Maps -----------------------------------------------------------

// trace_active is the single-entry hot-path gate. Userspace stores
// the live session count here; BPF reads a u32, branches on zero,
// and skips every other trace lookup.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} trace_active SEC(".maps");

// trace_config_val carries per-session configuration. Daemons program
// one entry per active TraceSession; expiry is materialized into ns
// against bpf_ktime_get_ns so BPF can treat expired sessions as a
// fast no-op without consulting wall clock.
struct trace_config_val {
  __u64 expires_ns;     // monotonic deadline; 0 = no deadline
  __u32 capture_flags;  // bitmask of TRACE_CAP_*
  __u8  level;          // TRACE_LEVEL_*
  __u8  mode;           // 0=ObserveOnly, 1=ActiveProbe
  __u8  _pad[2];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_TRACE_SESSIONS);
  __type(key, __u32);             // trace_id
  __type(value, struct trace_config_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} trace_config_map SEC(".maps");

// trace_tuple_key keys the tuple → trace_id resolver. Initial tuples
// are populated by kubectl through the daemon-side reconciler;
// learned post-NAT tuples are appended at runtime via
// trace_learn_tuple. _pad is explicit so userspace's struct mirror
// can encode/decode bit-for-bit.
struct trace_tuple_key {
  __u8  scope;
  __u8  proto;
  __u8  _pad[2];
  __u32 vpc_id;
  __be32 saddr;
  __be32 daddr;
  __be16 sport;
  __be16 dport;
};

struct trace_tuple_val {
  __u32 trace_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_TRACE_TUPLES);
  __type(key, struct trace_tuple_key);
  __type(value, struct trace_tuple_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} trace_tuple_map SEC(".maps");

// trace_event is the wire format for the trace_events ringbuf.
//
// The struct is laid out manually for explicit padding so userspace
// can decode it byte-for-byte regardless of host alignment rules. Two
// tuples are carried inline so NAT before/after pairs fit in a single
// event without an event-pair protocol on top.
//
// Bumping the layout requires a coordinated daemon update — version
// it via a new reason code, never by mutating existing fields.
struct juneau_trace_event {
  __u32 trace_id;
  __u32 reason;
  __u32 hook;
  __u32 ifindex;
  __u32 vpc_id;
  __u32 subnet_id;
  __u64 ts_ns;
  __be32 saddr;
  __be32 daddr;
  __be16 sport;
  __be16 dport;
  __u8  proto;
  __u8  verdict;
  __u8  scope;
  __u8  _pad0;
  // Optional second tuple. When unused the four addr/port fields are
  // zero; the userspace decoder treats an all-zero second tuple as
  // absent.
  __be32 saddr2;
  __be32 daddr2;
  __be16 sport2;
  __be16 dport2;
  // Hook-specific aux. Examples:
  //   - service backend: aux1 = backend_index, aux2 = backend_subnet_id
  //   - redirect: aux1 = target ifindex
  //   - policy: aux1 = sg_id or acl_id, aux2 = matched rule index
  __u32 aux1;
  __u32 aux2;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_TRACE_EVENTS_BYTES);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} trace_events SEC(".maps");

// ---- Helpers --------------------------------------------------------

// trace_skb_data / trace_skb_data_end mirror nat.h's same-named helpers
// (see nat.h:33-49 for the rationale). Using inline asm with an
// immediate-offset load forces clang to emit `*(u32 *)(skb + 76)` /
// `*(u32 *)(skb + 80)` rather than `r6 += 76; *(u32 *)(r6 + 0)`. The
// verifier accepts the former but rejects the latter as "dereference
// of modified ctx ptr". Two back-to-back inlined trace helpers (e.g.
// trace_emit_map_miss_l3 then trace_emit_drop_l3) routinely trip the
// bad codegen without these wrappers.
//
// We duplicate rather than include nat.h because trace.h is the most
// upstream header in the BPF source tree and we want to keep it free
// of dependencies on the dataplane-specific helpers.
static __always_inline void *trace_skb_data(const struct __sk_buff *skb) {
  void *p;
  __asm__ volatile("%[p] = *(u32 *)(%[skb] + %[off])"
                   : [p] "=r"(p)
                   : [skb] "r"(skb),
                     [off] "i"(__builtin_offsetof(struct __sk_buff, data)));
  return p;
}

static __always_inline void *trace_skb_data_end(const struct __sk_buff *skb) {
  void *p;
  __asm__ volatile("%[p] = *(u32 *)(%[skb] + %[off])"
                   : [p] "=r"(p)
                   : [skb] "r"(skb),
                     [off] "i"(__builtin_offsetof(struct __sk_buff, data_end)));
  return p;
}

// trace_is_active is the hot-path gate. Returns non-zero only when at
// least one session has been programmed. Cost: one ARRAY map lookup
// (constant-folded by the verifier into a single load).
static __always_inline int trace_is_active(void) {
  __u32 zero = 0;
  __u32 *count = bpf_map_lookup_elem(&trace_active, &zero);
  if (!count)
    return 0;
  return *count != 0;
}

// trace_lookup_tuple resolves a tuple to the session that claims it,
// or 0 if none. Callers should fast-path on trace_is_active() first.
static __always_inline __u32
trace_lookup_tuple(const struct trace_tuple_key *key) {
  if (!trace_is_active())
    return 0;
  const struct trace_tuple_val *v = bpf_map_lookup_elem(&trace_tuple_map, key);
  if (!v)
    return 0;
  return v->trace_id;
}

// trace_get_config returns the per-session config or NULL when the
// session is unknown / expired. Callers pass `now_ns` so the helper
// does not have to call bpf_ktime_get_ns() itself (some hot paths
// already cache the timestamp).
static __always_inline const struct trace_config_val *
trace_get_config(__u32 trace_id, __u64 now_ns) {
  if (trace_id == 0)
    return 0;
  const struct trace_config_val *cfg =
      bpf_map_lookup_elem(&trace_config_map, &trace_id);
  if (!cfg)
    return 0;
  if (cfg->expires_ns != 0 && now_ns >= cfg->expires_ns)
    return 0;
  return cfg;
}

// trace_should_emit gates decision-class events on capture mask +
// minimum level. Pass capture_flag=0 to bypass the mask check (used
// for terminal verdicts which always fire when the session is alive).
static __always_inline int
trace_should_emit(const struct trace_config_val *cfg, __u32 capture_flag,
                  __u8 min_level) {
  if (!cfg)
    return 0;
  if (cfg->level < min_level)
    return 0;
  if (capture_flag != 0 && (cfg->capture_flags & capture_flag) == 0)
    return 0;
  return 1;
}

// __juneau_bpf_subprog marks a function as a BPF-to-BPF subprogram:
//   - noinline so each call site costs the verifier just one CALL
//     instruction rather than the full inlined body. Without this,
//     pod_egress.c overflows the 1M-insn verifier ceiling once the
//     trace path is added.
//   - used so static linkage does not let the linker drop the
//     function when only the host program references it indirectly.
//
// Requires kernel >= 5.0 (BPF-to-BPF calls). Juneau already targets
// modern kernels so this is safe.
//
// BPF subprograms have a 5-register argument limit (R1-R5), so any
// helper that needs more than 5 logical inputs must accept a pointer
// to a struct holding them. trace_emit_args below is exactly that
// container — wrappers fill it on stack and pass the address.
#ifndef __juneau_bpf_subprog
#define __juneau_bpf_subprog __attribute__((noinline)) __attribute__((used))
#endif

// trace_emit_args is the container struct passed to trace_emit_full.
// One pointer fits in a single register; callers fill the struct on
// the stack at each call site.
struct trace_emit_args {
  __u32 trace_id;
  __u32 reason;
  __u32 hook;
  __u32 ifindex;
  __u32 vpc_id;
  __u32 subnet_id;
  __u8  scope;
  __u8  proto;
  __u8  verdict;
  __u8  _pad0;
  __be32 saddr;
  __be32 daddr;
  __be16 sport;
  __be16 dport;
  __be32 saddr2;
  __be32 daddr2;
  __be16 sport2;
  __be16 dport2;
  __u32 aux1;
  __u32 aux2;
};

// trace_emit_full submits a fully-populated event. The single point
// of truth for the wire format. Marked noinline so the body lives
// in exactly one place and each trace_emit_* wrapper costs just one
// CALL at its call site.
static __juneau_bpf_subprog void
trace_emit_full(const struct trace_emit_args *a) {
  if (!a || a->trace_id == 0)
    return;
  struct juneau_trace_event *ev =
      bpf_ringbuf_reserve(&trace_events, sizeof(*ev), 0);
  if (!ev)
    return;
  // Zero-init via aggregate assignment so reserved-but-unfilled
  // padding bytes do not leak stack data into userspace. Clang lowers
  // this to a constant-size memset.
  __builtin_memset(ev, 0, sizeof(*ev));
  ev->trace_id = a->trace_id;
  ev->reason = a->reason;
  ev->hook = a->hook;
  ev->ifindex = a->ifindex;
  ev->vpc_id = a->vpc_id;
  ev->subnet_id = a->subnet_id;
  ev->ts_ns = bpf_ktime_get_ns();
  ev->saddr = a->saddr;
  ev->daddr = a->daddr;
  ev->sport = a->sport;
  ev->dport = a->dport;
  ev->proto = a->proto;
  ev->verdict = a->verdict;
  ev->scope = a->scope;
  ev->saddr2 = a->saddr2;
  ev->daddr2 = a->daddr2;
  ev->sport2 = a->sport2;
  ev->dport2 = a->dport2;
  ev->aux1 = a->aux1;
  ev->aux2 = a->aux2;
  bpf_ringbuf_submit(ev, 0);
}

// trace_emit_enter records a hook entry event. Used by every TC
// program at the top of the entry function once the tuple is known.
static __always_inline void
trace_emit_enter(__u32 trace_id, __u32 reason, __u32 hook, __u32 ifindex,
                 __u32 vpc_id, __u32 subnet_id, __u8 scope, __u8 proto,
                 __be32 saddr, __be32 daddr, __be16 sport, __be16 dport) {
  struct trace_emit_args a = {0};
  a.trace_id = trace_id;
  a.reason = reason;
  a.hook = hook;
  a.ifindex = ifindex;
  a.vpc_id = vpc_id;
  a.subnet_id = subnet_id;
  a.scope = scope;
  a.proto = proto;
  a.verdict = TRACE_VERDICT_OK;
  a.saddr = saddr;
  a.daddr = daddr;
  a.sport = sport;
  a.dport = dport;
  trace_emit_full(&a);
}

// trace_emit_drop tags a terminal SHOT verdict with the reason code
// that produced it.
static __always_inline void
trace_emit_drop(__u32 trace_id, __u32 reason, __u32 hook, __u32 ifindex,
                __u32 vpc_id, __u32 subnet_id, __u8 scope, __u8 proto,
                __be32 saddr, __be32 daddr, __be16 sport, __be16 dport) {
  struct trace_emit_args a = {0};
  a.trace_id = trace_id;
  a.reason = reason;
  a.hook = hook;
  a.ifindex = ifindex;
  a.vpc_id = vpc_id;
  a.subnet_id = subnet_id;
  a.scope = scope;
  a.proto = proto;
  a.verdict = TRACE_VERDICT_DROP;
  a.saddr = saddr;
  a.daddr = daddr;
  a.sport = sport;
  a.dport = dport;
  trace_emit_full(&a);
}

// trace_emit_redirect records a TC_ACT_REDIRECT (or VXLAN encap +
// redirect) verdict with the target ifindex in aux1.
static __always_inline void
trace_emit_redirect(__u32 trace_id, __u32 reason, __u32 hook, __u32 ifindex,
                    __u32 vpc_id, __u32 subnet_id, __u8 scope, __u8 proto,
                    __be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
                    __u32 target_ifindex, __u32 aux2) {
  struct trace_emit_args a = {0};
  a.trace_id = trace_id;
  a.reason = reason;
  a.hook = hook;
  a.ifindex = ifindex;
  a.vpc_id = vpc_id;
  a.subnet_id = subnet_id;
  a.scope = scope;
  a.proto = proto;
  a.verdict = TRACE_VERDICT_REDIRECT;
  a.saddr = saddr;
  a.daddr = daddr;
  a.sport = sport;
  a.dport = dport;
  a.aux1 = target_ifindex;
  a.aux2 = aux2;
  trace_emit_full(&a);
}

// trace_emit_map_miss records a lookup miss. Cheap to emit since map
// misses are rare in healthy clusters; daemons render them as the
// strongest "why did the packet stop?" signal.
static __always_inline void
trace_emit_map_miss(__u32 trace_id, __u32 reason, __u32 hook, __u32 ifindex,
                    __u32 vpc_id, __u32 subnet_id, __u8 scope, __u8 proto,
                    __be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
                    __u32 aux1) {
  struct trace_emit_args a = {0};
  a.trace_id = trace_id;
  a.reason = reason;
  a.hook = hook;
  a.ifindex = ifindex;
  a.vpc_id = vpc_id;
  a.subnet_id = subnet_id;
  a.scope = scope;
  a.proto = proto;
  a.verdict = TRACE_VERDICT_OK;
  a.saddr = saddr;
  a.daddr = daddr;
  a.sport = sport;
  a.dport = dport;
  a.aux1 = aux1;
  trace_emit_full(&a);
}

// trace_emit_nat carries before/after tuple pairs. before_* go in the
// primary tuple slot; after_* in the secondary slot. Userspace
// renders this as `dnat 10.96.0.10:443 -> 10.0.2.8:8443`.
static __always_inline void
trace_emit_nat(__u32 trace_id, __u32 reason, __u32 hook, __u32 ifindex,
               __u32 vpc_id, __u32 subnet_id, __u8 scope, __u8 proto,
               __be32 before_saddr, __be32 before_daddr, __be16 before_sport,
               __be16 before_dport, __be32 after_saddr, __be32 after_daddr,
               __be16 after_sport, __be16 after_dport) {
  struct trace_emit_args a = {0};
  a.trace_id = trace_id;
  a.reason = reason;
  a.hook = hook;
  a.ifindex = ifindex;
  a.vpc_id = vpc_id;
  a.subnet_id = subnet_id;
  a.scope = scope;
  a.proto = proto;
  a.verdict = TRACE_VERDICT_OK;
  a.saddr = before_saddr;
  a.daddr = before_daddr;
  a.sport = before_sport;
  a.dport = before_dport;
  a.saddr2 = after_saddr;
  a.daddr2 = after_daddr;
  a.sport2 = after_sport;
  a.dport2 = after_dport;
  trace_emit_full(&a);
}

// trace_emit_policy records an ACL/SG verdict. aux1 carries the
// rule's owning identifier (acl_id or sg_id); aux2 carries the
// matched rule index for operator drill-down.
static __always_inline void
trace_emit_policy(__u32 trace_id, __u32 reason, __u32 hook, __u32 ifindex,
                  __u32 vpc_id, __u32 subnet_id, __u8 scope, __u8 proto,
                  __be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
                  __u32 policy_id, __u32 rule_index) {
  struct trace_emit_args a = {0};
  a.trace_id = trace_id;
  a.reason = reason;
  a.hook = hook;
  a.ifindex = ifindex;
  a.vpc_id = vpc_id;
  a.subnet_id = subnet_id;
  a.scope = scope;
  a.proto = proto;
  a.verdict = TRACE_VERDICT_OK;
  a.saddr = saddr;
  a.daddr = daddr;
  a.sport = sport;
  a.dport = dport;
  a.aux1 = policy_id;
  a.aux2 = rule_index;
  trace_emit_full(&a);
}

// trace_learn_tuple installs a translated tuple into the local tuple
// map so a subsequent hook (or the destination node, after the
// daemon mirrors learned tuples) can resolve the same trace_id.
static __always_inline void
trace_learn_tuple(__u32 trace_id, const struct trace_tuple_key *key) {
  if (trace_id == 0)
    return;
  struct trace_tuple_val v = {.trace_id = trace_id};
  bpf_map_update_elem(&trace_tuple_map, key, &v, BPF_ANY);
}

// trace_make_key zero-inits the key (so _pad is deterministic) and
// fills the populated fields. Hash maps key on the entire struct
// including padding, so userspace and BPF must agree byte-for-byte.
static __always_inline struct trace_tuple_key
trace_make_key(__u8 scope, __u32 vpc_id, __u8 proto, __be32 saddr,
               __be32 daddr, __be16 sport, __be16 dport) {
  struct trace_tuple_key k = {0};
  k.scope = scope;
  k.proto = proto;
  k.vpc_id = vpc_id;
  k.saddr = saddr;
  k.daddr = daddr;
  k.sport = sport;
  k.dport = dport;
  return k;
}

// ---- Hook-entry classification --------------------------------------
//
// trace_classify_* helpers parse the L3/L4 header out of skb, build
// the appropriate tuple key and resolve the matching trace_id. They
// are designed to be the single trace call at the top of each TC
// program's entry function — one call site keeps the verifier
// instruction count bounded and makes "is this packet traced?"
// trivial to answer everywhere downstream.
//
// Returns 0 (no trace claims this packet) on the no-session fast
// path, on header parse failures, or on packets that match no
// configured tuple. Callers should propagate the trace_id into
// terminal verdict / decision-point emit calls.

#ifndef IPPROTO_TCP_BPF
#define IPPROTO_TCP_BPF 6
#endif
#ifndef IPPROTO_UDP_BPF
#define IPPROTO_UDP_BPF 17
#endif

static __always_inline __u32
trace_read_l4_ports(const struct iphdr *iph, void *data_end, __be16 *sport,
                    __be16 *dport) {
  *sport = 0;
  *dport = 0;
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return 0;
  void *l4 = (void *)iph + ihl * 4;
  if (iph->protocol == IPPROTO_TCP_BPF) {
    struct tcphdr *t = l4;
    if ((void *)(t + 1) > data_end)
      return 0;
    *sport = t->source;
    *dport = t->dest;
  } else if (iph->protocol == IPPROTO_UDP_BPF) {
    struct udphdr *u = l4;
    if ((void *)(u + 1) > data_end)
      return 0;
    *sport = u->source;
    *dport = u->dest;
  }
  return 1;
}

// (trace_classify_l3 was removed in the noinline refactor —
// trace_classify_and_emit_enter below replaces it as a single
// subprogram that combines lookup + emit.)

// trace_hook_ctx bundles the per-hook context callers pass to
// trace_classify_and_emit_enter. Bundling keeps the subprogram's
// argument count under BPF's 5-register limit.
struct trace_hook_ctx {
  __u32 reason;
  __u32 hook;
  __u32 vpc_id;
  __u32 subnet_id;
  __u8  scope;
  __u8  _pad[3];
};

// trace_nat_event bundles the args trace_observe_nat needs.
// Bundling keeps the subprogram's argument count under BPF's
// 5-register ceiling.
struct trace_nat_event {
  __u32 vpc_id;
  __u32 subnet_id;
  __u32 hook;
  __u32 reason;
  __u8  scope;
  __u8  proto;
  __u8  _pad[2];
  __be32 before_saddr;
  __be32 before_daddr;
  __be16 before_sport;
  __be16 before_dport;
  __be32 after_saddr;
  __be32 after_daddr;
  __be16 after_sport;
  __be16 after_dport;
};

// trace_observe_nat is called by NAT decision points (Service DNAT,
// SNAT, NAPT, shared-Service rewrite). It resolves the trace_id from
// the BEFORE tuple, emits a NAT event carrying both tuples, and
// installs the AFTER tuple in trace_tuple_map so subsequent hooks
// on this node match without re-classifying.
//
// Userspace (the daemon's ringbuf reader → debug stream) propagates
// the AFTER tuple to other nodes via Debug.LearnTuple, so when the
// rewritten packet crosses the wire and lands on a different node's
// vxlan_ingress / pod_ingress, the lookup hits there too.
static __juneau_bpf_subprog void
trace_observe_nat(struct __sk_buff *skb, const struct trace_nat_event *e) {
  if (!trace_is_active() || !e)
    return;
  struct trace_tuple_key bk = trace_make_key(e->scope, e->vpc_id, e->proto,
                                             e->before_saddr, e->before_daddr,
                                             0, e->before_dport);
  __u32 id = trace_lookup_tuple(&bk);
  if (id == 0 && e->before_dport != 0) {
    bk.dport = 0;
    id = trace_lookup_tuple(&bk);
  }
  if (id == 0)
    return;

  struct trace_emit_args a = {0};
  a.trace_id = id;
  a.reason = e->reason;
  a.hook = e->hook;
  a.ifindex = skb->ifindex;
  a.vpc_id = e->vpc_id;
  a.subnet_id = e->subnet_id;
  a.scope = e->scope;
  a.proto = e->proto;
  a.verdict = TRACE_VERDICT_OK;
  a.saddr = e->before_saddr;
  a.daddr = e->before_daddr;
  a.sport = e->before_sport;
  a.dport = e->before_dport;
  a.saddr2 = e->after_saddr;
  a.daddr2 = e->after_daddr;
  a.sport2 = e->after_sport;
  a.dport2 = e->after_dport;
  trace_emit_full(&a);

  // Install the post-NAT tuple locally so any further hook on this
  // same node (e.g. pod_ingress on the response leg) resolves the
  // same trace_id. Cross-node propagation is userspace's job.
  struct trace_tuple_key ak = trace_make_key(e->scope, e->vpc_id, e->proto,
                                             e->after_saddr, e->after_daddr,
                                             0, e->after_dport);
  trace_learn_tuple(id, &ak);
}

// trace_classify_and_emit_enter classifies the packet, emits an
// enter event if it matches a session, and returns the resolved
// trace_id (0 = no match). One subprogram per hook-entry call site
// keeps the verifier surface minimal.
//
// Source ports are wildcarded on the lookup so kubectl-stored
// tuples (which cannot know an ephemeral source port) match both
// initial and return-leg packets. A second-chance lookup with
// dport=0 lets operators run "trace src to dst, all protocols"
// without enumerating destination ports.
static __juneau_bpf_subprog __u32
trace_classify_and_emit_enter(struct __sk_buff *skb,
                              const struct trace_hook_ctx *ctx) {
  if (!trace_is_active())
    return 0;
  void *data = trace_skb_data(skb);
  void *data_end = trace_skb_data_end(skb);
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return 0;
  if (eth->h_proto != bpf_htons(0x0800))
    return 0;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return 0;
  __be16 sport = 0, dport = 0;
  trace_read_l4_ports(iph, data_end, &sport, &dport);

  struct trace_tuple_key k = trace_make_key(ctx->scope, ctx->vpc_id,
                                            iph->protocol, iph->saddr,
                                            iph->daddr, 0, dport);
  __u32 id = trace_lookup_tuple(&k);
  if (id == 0 && dport != 0) {
    k.dport = 0;
    id = trace_lookup_tuple(&k);
  }
  if (id == 0)
    return 0;

  trace_emit_enter(id, ctx->reason, ctx->hook, skb->ifindex, ctx->vpc_id,
                   ctx->subnet_id, ctx->scope, iph->protocol, iph->saddr,
                   iph->daddr, sport, dport);
  return id;
}

// ---- Terminal-verdict / map-miss helpers ----------------------------
//
// These helpers wrap the underlying trace_emit_drop / _redirect /
// _map_miss with skb-side header parsing so callers can drop them in
// at TC_ACT_SHOT / bpf_redirect / lookup-miss sites with a single
// line.
//
// The skb-parse + ringbuf path is heavy enough that inlining each
// call site (drop, redirect, map_miss) into pod_egress / node_ingress
// blew through the verifier's 1M-insn budget once trace.h was
// added. So the implementation lives once in the
// trace_emit_l3 subprogram below; the public wrappers are tiny shims
// that fill `trace_emit_l3_args` and CALL into the shared subprogram.
// Net effect: each public call site costs ~one struct fill + one
// CALL, regardless of which variant.

// trace_emit_l3_args bundles the shim → subprogram inputs. `verdict`
// distinguishes drop / redirect / map-miss callers without needing
// three near-identical subprograms; `aux1` carries target_ifindex
// (redirect) or aux1 (map_miss), unused (zero) for drop.
struct trace_emit_l3_args {
  __u32 trace_id;
  __u32 reason;
  __u32 hook;
  __u32 vpc_id;
  __u32 subnet_id;
  __u32 aux1;
  __u8  scope;
  __u8  verdict;
  __u8  _pad[2];
};

// trace_emit_l3 is the shared subprogram. Marked noinline so each
// shim call site costs a single CALL rather than the full skb parse
// + ringbuf reserve + memset + field copies.
static __juneau_bpf_subprog void
trace_emit_l3(struct __sk_buff *skb, const struct trace_emit_l3_args *a) {
  if (!a || a->trace_id == 0)
    return;
  void *data = trace_skb_data(skb);
  void *data_end = trace_skb_data_end(skb);
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return;
  __be16 sport = 0, dport = 0;
  trace_read_l4_ports(iph, data_end, &sport, &dport);

  struct trace_emit_args ea = {0};
  ea.trace_id = a->trace_id;
  ea.reason = a->reason;
  ea.hook = a->hook;
  ea.ifindex = skb->ifindex;
  ea.vpc_id = a->vpc_id;
  ea.subnet_id = a->subnet_id;
  ea.scope = a->scope;
  ea.proto = iph->protocol;
  ea.verdict = a->verdict;
  ea.saddr = iph->saddr;
  ea.daddr = iph->daddr;
  ea.sport = sport;
  ea.dport = dport;
  ea.aux1 = a->aux1;
  trace_emit_full(&ea);
}

static __always_inline void
trace_emit_drop_l3(struct __sk_buff *skb, __u32 trace_id, __u32 reason,
                   __u32 hook, __u8 scope, __u32 vpc_id, __u32 subnet_id) {
  if (trace_id == 0)
    return;
  struct trace_emit_l3_args a = {0};
  a.trace_id = trace_id;
  a.reason = reason;
  a.hook = hook;
  a.vpc_id = vpc_id;
  a.subnet_id = subnet_id;
  a.scope = scope;
  a.verdict = TRACE_VERDICT_DROP;
  trace_emit_l3(skb, &a);
}

static __always_inline void
trace_emit_redirect_l3(struct __sk_buff *skb, __u32 trace_id, __u32 reason,
                       __u32 hook, __u8 scope, __u32 vpc_id, __u32 subnet_id,
                       __u32 target_ifindex) {
  if (trace_id == 0)
    return;
  struct trace_emit_l3_args a = {0};
  a.trace_id = trace_id;
  a.reason = reason;
  a.hook = hook;
  a.vpc_id = vpc_id;
  a.subnet_id = subnet_id;
  a.aux1 = target_ifindex;
  a.scope = scope;
  a.verdict = TRACE_VERDICT_REDIRECT;
  trace_emit_l3(skb, &a);
}

static __always_inline void
trace_emit_map_miss_l3(struct __sk_buff *skb, __u32 trace_id, __u32 reason,
                       __u32 hook, __u8 scope, __u32 vpc_id, __u32 subnet_id,
                       __u32 aux1) {
  if (trace_id == 0)
    return;
  struct trace_emit_l3_args a = {0};
  a.trace_id = trace_id;
  a.reason = reason;
  a.hook = hook;
  a.vpc_id = vpc_id;
  a.subnet_id = subnet_id;
  a.aux1 = aux1;
  a.scope = scope;
  a.verdict = TRACE_VERDICT_OK;
  trace_emit_l3(skb, &a);
}

// trace_lookup_id_l3 is for sites that need a trace_id at decision
// points but were not classified at hook entry (e.g. terminal
// verdicts in helpers that don't receive trace_id from the caller).
// It re-derives the tuple and looks up the id.
//
// Marked noinline for the same reason as trace_emit_l3 above:
// pod_egress has many lookup sites and inlining the skb-parse +
// tuple_map lookup at each one overflows the verifier 1M-insn
// budget.
static __juneau_bpf_subprog __u32
trace_lookup_id_l3(struct __sk_buff *skb, __u8 scope, __u32 vpc_id) {
  if (!trace_is_active())
    return 0;
  void *data = trace_skb_data(skb);
  void *data_end = trace_skb_data_end(skb);
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return 0;
  if (eth->h_proto != bpf_htons(0x0800))
    return 0;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return 0;
  __be16 sport = 0, dport = 0;
  trace_read_l4_ports(iph, data_end, &sport, &dport);
  struct trace_tuple_key k = trace_make_key(scope, vpc_id, iph->protocol,
                                            iph->saddr, iph->daddr, 0, dport);
  __u32 id = trace_lookup_tuple(&k);
  if (id == 0 && dport != 0) {
    k.dport = 0;
    id = trace_lookup_tuple(&k);
  }
  return id;
}

#endif // JUNEAU_BPF_TRACE_H
