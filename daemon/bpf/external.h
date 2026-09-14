// The external addresses juneau owns, read the same way by every hook
// that has to decide whether a packet is juneau's to handle.
//
// node_ingress takes a packet for an owned address and passes the rest to
// the host stack. pod_egress sends what a NIC on an ElasticIP addresses to
// an owned address through node_ingress instead of out of the node. The
// two must agree on what owned means, or a packet would be hairpinned to a
// node_ingress that hands it to the host stack.
#ifndef JUNEAU_BPF_EXTERNAL_H
#define JUNEAU_BPF_EXTERNAL_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "maps.h"

// external_address_owned reports whether juneau owns addr, which is in
// network byte order.
static __always_inline bool external_address_owned(__be32 addr) {
  struct external_address_pools_key key = {
      .prefixlen = 32,
      .addr = addr,
  };
  const __u8 *owned = bpf_map_lookup_elem(&external_address_pools, &key);
  if (!owned)
    return false;
  return *owned != 0;
}

#endif // JUNEAU_BPF_EXTERNAL_H
