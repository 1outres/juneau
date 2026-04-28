// Shared map and key/value definitions for TC eBPF programs.
#ifndef JUNEAU_BPF_MAPS_H
#define JUNEAU_BPF_MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef MAX_IF_SUBNET
#define MAX_IF_SUBNET 32768
#endif

#ifndef MAX_SUBNET
#define MAX_SUBNET 16384
#endif

#ifndef MAX_ARP_TABLE
#define MAX_ARP_TABLE 131072
#endif

#ifndef MAX_FDB
#define MAX_FDB 131072
#endif

#ifndef MAX_FIB
#define MAX_FIB 32768
#endif

#ifndef MAX_FIB_MAP
#define MAX_FIB_MAP 32768
#endif

#ifndef MAX_ADDRESS_POOLS_MAP
#define MAX_ADDRESS_POOLS_MAP 512
#endif

#ifndef MAX_NAT_MAP
#define MAX_NAT_MAP 131072
#endif

#ifndef MAX_SERVICE_MAP
#define MAX_SERVICE_MAP 16384
#endif

#ifndef MAX_BACKEND_MAP
#define MAX_BACKEND_MAP 65536
#endif

#ifndef MAX_CT_MAP
#define MAX_CT_MAP 131072
#endif

#define FIB_ROUTE_TYPE_CONNECTED 1
#define FIB_ROUTE_TYPE_ENDPOINT 2
#define FIB_ROUTE_TYPE_INTERNET_GATEWAY 3
#define FIB_ROUTE_TYPE_SERVICE 4
#define FIB_ROUTE_TYPE_HOST_GATEWAY 5
#define FIB_ROUTE_TYPE_NAPT 6

#define CT_ACTION_DNAT 1
#define CT_ACTION_SNAT 2

// ct_state values mirror daemon/internal/daemon/dataplane/ctstate. Keep
// them in sync: user-space GC reads ct_val.state and assumes these
// numbers.
#define CT_STATE_NEW 0
#define CT_STATE_ESTABLISHED 1
#define CT_STATE_FIN_WAIT 2
#define CT_STATE_CLOSED 3

struct ifindex_subnet_key {
  __u32 ifindex;
};

struct ifindex_subnet_val {
  __u32 subnet_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_IF_SUBNET);
  __type(key, struct ifindex_subnet_key);
  __type(value, struct ifindex_subnet_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_subnet SEC(".maps");

struct ifindex_host_mac_key {
  __u32 ifindex;
};

struct ifindex_host_mac_val {
  __u8 mac[6];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_IF_SUBNET);
  __type(key, struct ifindex_host_mac_key);
  __type(value, struct ifindex_host_mac_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_host_mac SEC(".maps");

struct subnet_key {
  __u32 subnet_id;
};

struct subnet_val {
  __u32 table_id;
  __u32 vpc_id;
  __u8 gw_mac[6];
  __u32 gw_addr;
  __u32 mask;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_SUBNET);
  __type(key, struct subnet_key);
  __type(value, struct subnet_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} subnet_map SEC(".maps");

struct arp_table_key {
  __u32 subnet_id;
  __u32 ipaddr;
};

struct arp_table_val {
  __u8 mac[6];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ARP_TABLE);
  __type(key, struct arp_table_key);
  __type(value, struct arp_table_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} arp_table SEC(".maps");

struct fdb_key {
  __u32 subnet_id;
  __u8 mac[6];
};

struct fdb_val {
  __u32 ifindex;
  __u32 vtep_ip;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FDB);
  __type(key, struct fdb_key);
  __type(value, struct fdb_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} fdb SEC(".maps");

struct host_iface_val {
  __u32 ifindex;
  __u8 mac[6];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct host_iface_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} host_iface SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32); // vxlan ifindex
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} vxlan_ifindex SEC(".maps");

struct fib_key {
  __u32 prefixlen;
  __u32 dst;
};

struct fib_val {
  __u8 type;
  __u8 dmac[6];
  __u8 smac[6];
  __u32 subnet_id;
  __u32 oif;
};

struct fib_inner_map {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_FIB);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct fib_key);
  __type(value, struct fib_val);
};

struct fib_inner_map fib_inner SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_FIB_MAP);
  __type(key, __u32); // table_id
  __type(value, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct fib_inner_map);
} fib_map SEC(".maps");

struct bgp_address_pools_key {
  __u32 prefixlen;
  __u32 addr;
};

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_ADDRESS_POOLS_MAP);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct bgp_address_pools_key);
  __type(value, __u8);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} bgp_address_pools SEC(".maps");

struct nat_inside {
  __u32 subnet_id;
  __u32 addr;
};

struct nat_outside {
  __u32 addr;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_NAT_MAP);
  __type(key, struct nat_inside);
  __type(value, struct nat_outside);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_snat_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_NAT_MAP);
  __type(key, struct nat_outside);
  __type(value, struct nat_inside);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_dnat_map SEC(".maps");

// service_map maps a Kubernetes Service tuple (cluster IP + L4 port +
// proto) to the metadata that describes which backends it dispatches to
// and which Vpc owns the Service. Cluster IPs are unique cluster-wide
// (allocated by the apiserver), so this map is not keyed by Vpc.
struct service_key {
  __u32 cluster_ip;
  __u16 port;
  __u8 proto;
  __u8 _pad;
};

struct service_val {
  __u32 owner_vpc_id;   // Vpc that owns the Service; checked against caller_vpc_id
  __u32 backend_count;
  __u32 affinity_sec;
  __u32 _pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_SERVICE_MAP);
  __type(key, struct service_key);
  __type(value, struct service_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} service_map SEC(".maps");

// backend_map enumerates the actual backend Pods for a Service. The
// index is selected by hashing the client tuple (with affinity) modulo
// service_val.backend_count. backend_subnet_id (=VNI) lets the data
// plane VXLAN-encapsulate to the right L2 segment.
struct backend_key {
  __u32 cluster_ip;
  __u16 port;
  __u8 proto;
  __u8 _pad;
  __u32 index;
};

struct backend_val {
  __u32 backend_ip;
  __u16 backend_port;
  __u8 _pad[2];
  __u32 backend_subnet_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_BACKEND_MAP);
  __type(key, struct backend_key);
  __type(value, struct backend_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} backend_map SEC(".maps");

// ct_map is the conntrack table for Service-related flows. Both
// directions of a flow are stored as separate entries: forward (caller
// to ClusterIP) carries a DNAT action, reverse (backend to caller)
// carries a SNAT action. Backed by an LRU hash so old entries evict
// gracefully under pressure; user space additionally GC's expired
// entries.
struct ct_key {
  __u32 vpc_id;
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u8 proto;
  __u8 _pad[3];
};

struct ct_val {
  __u32 new_saddr;
  __u32 new_daddr;
  __u16 new_sport;
  __u16 new_dport;
  __u32 backend_subnet_id; // VNI of the backend Pod's Subnet (for forward direction; 0 for reverse)
  __u8 action;             // CT_ACTION_DNAT or CT_ACTION_SNAT
  __u8 state;              // CT_STATE_*: latest state derived from observed TCP flags
  __u8 flags_seen;         // OR-accumulated FIN|SYN|RST|ACK seen on this entry's direction
  __u8 _pad;
  __u64 last_seen_ns;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_CT_MAP);
  __type(key, struct ct_key);
  __type(value, struct ct_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} ct_map SEC(".maps");

#endif // JUNEAU_BPF_MAPS_H
