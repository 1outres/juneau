// go:build ignore
//
// l2_ingress runs at the egress of the host side of a veth whose NIC
// joined an L2Network, which is the last stop before the frame reaches
// the workload. An L2 segment applies no policy and rewrites nothing,
// so the program only records the delivery: without it a trace ends at
// the hook that redirected the frame and never says whether it landed.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "l2.h"
#include "maps.h"
#include "trace.h"

static __always_inline int handle(struct __sk_buff *skb) {
  struct l2_ifindex_key pkey = {.ifindex = skb->ifindex};
  const struct l2_ifindex_val *port = bpf_map_lookup_elem(&l2_ifindex, &pkey);
  if (!port)
    return TC_ACT_OK;

  struct l2_network_key nkey = {.vni = port->vni};
  const struct l2_network_val *network =
      bpf_map_lookup_elem(&l2_network_map, &nkey);
  if (!network)
    return TC_ACT_OK;

  __u32 __trace_id = 0;
  {
    struct trace_hook_ctx __ctx = {
        .reason = TRACE_REASON_ENTER_L2_INGRESS,
        .hook = TRACE_HOOK_L2_INGRESS,
        .vpc_id = network->vpc_id,
        .subnet_id = port->vni,
        .scope = TRACE_SCOPE_VPC,
    };
    __trace_id = trace_classify_and_emit_enter(skb, &__ctx);
  }

  trace_emit_pass_kernel_l3(skb, __trace_id, TRACE_HOOK_L2_INGRESS,
                            TRACE_SCOPE_VPC, network->vpc_id, port->vni);
  return TC_ACT_OK;
}

SEC("tc")
int tc_l2_ingress(struct __sk_buff *skb) {
  // See tc_pod_egress for why this anchor exists.
  (void)trace_is_active();
  return handle(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
