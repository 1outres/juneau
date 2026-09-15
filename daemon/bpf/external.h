// The external addresses juneau owns, read the same way by every hook
// that has to decide whether a packet is juneau's to handle.
//
// node_ingress takes a packet for an owned address and passes the rest to
// the host stack. pod_egress sends what a NIC on an ElasticIP addresses to
// an owned address delivered to this node through node_ingress instead of
// out of the node. The two must read the map alike, or a packet would be
// hairpinned to a node_ingress that hands it to the host stack.
#ifndef JUNEAU_BPF_EXTERNAL_H
#define JUNEAU_BPF_EXTERNAL_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "maps.h"

// external_address_claim returns the EXTERNAL_ADDRESS_* value the most
// specific claim of addr holds, or EXTERNAL_ADDRESS_UNCLAIMED when juneau
// does not own it. addr is in network byte order.
static __always_inline __u8 external_address_claim(__be32 addr) {
  struct external_address_pools_key key = {
      .prefixlen = 32,
      .addr = addr,
  };
  const __u8 *claim = bpf_map_lookup_elem(&external_address_pools, &key);
  if (!claim)
    return EXTERNAL_ADDRESS_UNCLAIMED;
  return *claim;
}

#endif // JUNEAU_BPF_EXTERNAL_H
