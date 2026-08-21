// ARP wire format and reply synthesis shared by the TC eBPF programs.
//
// Two hooks answer ARP: pod_egress serves the overlay Subnet gateway
// and Pod addresses on a veth, node_ingress serves juneau-owned
// external addresses on the node NIC. Both parse the same frame and
// build the same reply, so the wire handling lives here and each hook
// only decides which MAC to answer with.
#ifndef JUNEAU_BPF_ARP_H
#define JUNEAU_BPF_ARP_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#ifndef ARP_ETH_ALEN
#define ARP_ETH_ALEN 6
#endif

#ifndef ARP_HRD_ETHER
#define ARP_HRD_ETHER 1
#endif

#ifndef ARP_PRO_IPV4
#define ARP_PRO_IPV4 0x0800
#endif

#ifndef ARP_OP_REQUEST
#define ARP_OP_REQUEST 1
#endif

#ifndef ARP_OP_REPLY
#define ARP_OP_REPLY 2
#endif

struct arp_payload {
  __u8 sha[ARP_ETH_ALEN];
  __be32 spa;
  __u8 tha[ARP_ETH_ALEN];
  __be32 tpa;
} __attribute__((packed));

struct arp_request {
  struct arphdr *hdr;
  struct arp_payload *payload;
  __u32 target_addr;
};

// arp_parse_request accepts only an Ethernet/IPv4 ARP request and
// fills req. target_addr is the requested address in host order, the
// form juneau's maps are keyed on. Returns 0 on success and -1 for
// every other frame, which the caller handles as it sees fit.
static __always_inline int arp_parse_request(void *data_end, struct ethhdr *eth,
                                             struct arp_request *req) {
  struct arphdr *arp = (void *)(eth + 1);
  if ((void *)(arp + 1) > data_end)
    return -1;

  if (arp->ar_hrd != bpf_htons(ARP_HRD_ETHER))
    return -1;
  if (arp->ar_pro != bpf_htons(ARP_PRO_IPV4))
    return -1;
  if (arp->ar_hln != ARP_ETH_ALEN || arp->ar_pln != 4)
    return -1;
  if (arp->ar_op != bpf_htons(ARP_OP_REQUEST))
    return -1;

  struct arp_payload *payload = (void *)(arp + 1);
  if ((void *)(payload + 1) > data_end)
    return -1;

  req->hdr = arp;
  req->payload = payload;
  req->target_addr = bpf_ntohl(payload->tpa);
  return 0;
}

// arp_rewrite_to_reply turns the parsed request into a reply from
// responder_mac in place. The caller then redirects the frame back
// out of the interface it arrived on.
static __always_inline void arp_rewrite_to_reply(struct ethhdr *eth,
                                                 const struct arp_request *req,
                                                 const __u8 *responder_mac) {
  __u8 requester_mac[ARP_ETH_ALEN];
  __builtin_memcpy(requester_mac, eth->h_source, ARP_ETH_ALEN);
  __be32 requester_ip = req->payload->spa;
  __be32 target_ip = req->payload->tpa;

  __builtin_memcpy(eth->h_dest, requester_mac, ARP_ETH_ALEN);
  __builtin_memcpy(eth->h_source, responder_mac, ARP_ETH_ALEN);

  req->hdr->ar_op = bpf_htons(ARP_OP_REPLY);
  __builtin_memcpy(req->payload->tha, requester_mac, ARP_ETH_ALEN);
  req->payload->tpa = requester_ip;
  __builtin_memcpy(req->payload->sha, responder_mac, ARP_ETH_ALEN);
  req->payload->spa = target_ip;
}

#endif // JUNEAU_BPF_ARP_H
