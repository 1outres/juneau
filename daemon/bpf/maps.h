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

#ifndef MAX_SERVICE_NAT_IP
// MAX_SERVICE_NAT_IP bounds service_nat_ip, the per-Node SNAT IP table
// keyed by provider Vpc id. One entry per (this Node, provider Vpc)
// pair; in practice the number of provider Vpcs is small (default Vpc
// + a few tenant Vpcs) so this is generously sized.
#define MAX_SERVICE_NAT_IP 256
#endif

#ifndef MAX_SERVICE_ACL
// MAX_SERVICE_ACL bounds service_acl_map, the per-(Service × consumer
// Vpc) ACL allow-list. Sized for ~64k (Service × consumer) pairs.
#define MAX_SERVICE_ACL 65536
#endif

#ifndef MAX_SERVICE_AFFINITY_MAP
// MAX_SERVICE_AFFINITY_MAP bounds service_affinity_map, the per-(Service
// × client IP) sticky-backend cache used when sessionAffinity=ClientIP
// is configured. LRU_HASH so capacity overflow degrades gracefully:
// evicted entries cause a fresh selection on the next packet rather
// than a correctness violation.
#define MAX_SERVICE_AFFINITY_MAP 65536
#endif

#ifndef MAX_CT_MAP
#define MAX_CT_MAP 524288
#endif

#ifndef MAX_NAPT_SRC
#define MAX_NAPT_SRC 4096
#endif

#ifndef MAX_NODE_UNDERLAY
// MAX_NODE_UNDERLAY bounds node_underlay, the cluster-wide set of
// Juneau Node underlay IPs. One entry per Node; clusters are typically
// O(100) Nodes so 4096 is comfortably oversized while keeping the map
// small enough to scan when debugging.
#define MAX_NODE_UNDERLAY 4096
#endif

#ifndef MAX_LB_OWNER_TABLE
// MAX_LB_OWNER_TABLE bounds lb_owner_table, the Maglev consistent-hash
// slot table that maps a flow's 5-tuple hash to its owner Node's
// underlay IP. The value 4093 is prime (Maglev requires this so the
// (offset, skip) walks generate full-period permutations) and chosen
// to give comfortable balance for cluster sizes up to ~1000 Nodes:
//
//   N=10  → ~409 slots/Node, 1/N disruption ≈ 1% of flows on Node churn.
//   N=100 → ~40  slots/Node.
//   N=1000→ ~4   slots/Node, still enough to keep balance within ±1.
//
// Memory: 4093 * sizeof(__u32) ≈ 16 KiB, the same order as the other
// per-Node tables we ship; well below verifier and host-RAM budgets.
//
// Keep this value in lockstep with maglev.productionM in
// daemon/internal/daemon/dataplane/maglev — both sides need the same
// slot count or the data-plane lookup index will overrun the table.
#define MAX_LB_OWNER_TABLE 4093
#endif

#ifndef MAX_VIRTUAL_SERVICE_MAP
#define MAX_VIRTUAL_SERVICE_MAP 16384
#endif

#ifndef MAX_VIRTUAL_SERVICE_FLOW_MAP
#define MAX_VIRTUAL_SERVICE_FLOW_MAP 131072
#endif

#ifndef MAX_SECURITY_GROUPS
#define MAX_SECURITY_GROUPS 16384
#endif

#ifndef MAX_RULES_PER_SG
// MAX_RULES_PER_SG bounds the per-SG rule array size. The data plane
// scans this many rules per SG per first-packet evaluation, so the
// number must fit the verifier instruction budget when combined with
// MAX_SGS_PER_NIC (worst case scan = MAX_SGS_PER_NIC * MAX_RULES_PER_SG
// rules). 8 fits comfortably below the 1M-insn ceiling on Linux 5.10+.
// Controllers reject SGs whose post-expansion rule count exceeds this
// and surface a clean Reason.
#define MAX_RULES_PER_SG 8
#endif

#ifndef MAX_SG_MEMBERSHIP
// MAX_SG_MEMBERSHIP bounds the cluster-wide (vpc_id, ipv4) → SG list
// table. Sized for ~64k Pods.
#define MAX_SG_MEMBERSHIP 65536
#endif

// MAX_SGS_PER_NIC matches NetworkInterface.spec.securityGroups MaxItems
// and PodSecurityGroupsMax in the controller webhook. Keep all three in
// lockstep — the data plane scans this many SGs per packet at most.
//
// Note: this also bounds the verifier instruction budget for sg_eval:
// worst-case insn count grows with MAX_SGS_PER_NIC * MAX_RULES_PER_SG.
// Two SGs per NIC (e.g. one role-based + one shared) is enough for most
// real deployments; can be raised later if the verifier budget allows.
#define MAX_SGS_PER_NIC 2

#define FIB_ROUTE_TYPE_CONNECTED 1
#define FIB_ROUTE_TYPE_ENDPOINT 2
#define FIB_ROUTE_TYPE_INTERNET_GATEWAY 3
#define FIB_ROUTE_TYPE_SERVICE 4
#define FIB_ROUTE_TYPE_NAPT 6

#define CT_ACTION_DNAT 1
#define CT_ACTION_SNAT 2
#define CT_ACTION_NAPT_OUT 3
#define CT_ACTION_NAPT_IN 4
// SVC_NAPT_OUT / SVC_NAPT_IN: combined DNAT+SNAT for host-network
// Service backends (e.g. kube-apiserver). Pod traffic destined to a
// ClusterIP whose backend is on the underlay (no Pod / no NetworkInterface)
// is rewritten on egress so dst becomes the backend's host IP and src
// becomes this node's underlay IP — letting the kernel route the packet
// over the underlay as if it originated from the node itself. The
// reverse direction undoes both rewrites on the way back.
#define CT_ACTION_SVC_NAPT_OUT 5
#define CT_ACTION_SVC_NAPT_IN 6
// SVC_SHARED_OUT / SVC_SHARED_IN: combined DNAT+SNAT for shared Services
// hosted in the default Vpc. Callers in non-default Vpcs (with
// EnableService=true) reach the ClusterIP through this path: egress
// rewrites dst to the backend Pod IP (DNAT) and src to this Node's
// SNAT IP (SNAT, port-allocated to keep reverse-CT keys unique across
// concurrent callers). The response from the backend matches the
// SVC_SHARED_IN entry, which mirrors both rewrites back so the original
// caller sees a reply from the ClusterIP.
#define CT_ACTION_SVC_SHARED_OUT 7
#define CT_ACTION_SVC_SHARED_IN 8
// POLICY_PASS marks a flow whose first packet was admitted by every
// applicable policy layer (NetworkACL at the Subnet boundary plus
// SecurityGroup at the NetworkInterface). Subsequent packets short-
// circuit the per-layer rule scans via a single CT lookup. Both
// directions of the flow are installed at admission time so reply
// packets do not re-evaluate any layer.
//
// The CT entry does not encode which layers were involved: if any
// layer's ruleset changes the daemon-side reconciler is responsible for
// flushing affected entries so re-evaluation occurs. See
// daemon/internal/daemon/dataplane/policy for that bookkeeping.
#define CT_ACTION_POLICY_PASS 9

// LB_OUT / LB_IN: combined DNAT+SNAT for Service.type=LoadBalancer.
// External clients arrive at any node via BGP-ECMP'd traffic landing on
// the underlay; node_ingress matches the destination against
// service_map and (for entries flagged SVC_FLAG_LOAD_BALANCER) rewrites
// dst → backend Pod IP and src → this node's underlay IP with an
// allocated source port (so per-flow reverse keys remain unique).
// LB_OUT is the forward leg; the reverse leg (LB_IN) fires when the
// backend's reply, addressed to the receiver node's underlay IP,
// arrives at node_ingress on the same node and is rewritten back to
// (VIP, original client). Both legs live in the HOST scope because
// external clients have no VPC identity.
#define CT_ACTION_LB_OUT 10
#define CT_ACTION_LB_IN  11

// BACKEND_SUBNET_ID_UNDERLAY is the sentinel value the user-space
// service reconciler writes into backend_val.backend_subnet_id when an
// endpoint lives on the underlay (host-network endpoints, e.g.
// kube-apiserver). Pod-backed entries carry a real Subnet VNI >= 2 (1
// is reserved for VNI_UNDERLAY), so 0 is unambiguous.
#define BACKEND_SUBNET_ID_UNDERLAY 0

// VNI_UNDERLAY is reserved for VXLAN packets that carry "underlay-
// equivalent" payloads — packets whose inner header is meant to be
// processed without any VPC scope. Producers set the tunnel VNI to
// this value when injecting cross-Node control / fast-path traffic
// onto the existing VXLAN device instead of a separate transport.
//
// Today the only producer is LB owner redirection (node_ingress
// forwards a flow to its Maglev-elected owner Node by encapsulating
// the original underlay frame with this VNI; the receiver's
// vxlan_ingress recognises VNI_UNDERLAY, skips Subnet/FDB lookups,
// and hands the inner packet to the LB forward path as if it had
// arrived on the main interface).
//
// Future cross-Node control-plane traffic (debug RPCs, agent fan-
// out) can reuse VNI_UNDERLAY by branching on inner-packet content
// in vxlan_ingress; reserving the VNI now avoids needing a fresh
// reservation per feature.
//
// Allocation: the controller's subnet-vni AllocationPool starts at
// Min=2 so user-facing Subnets never collide with this value. The
// 0 / 1 / >=2 ladder mirrors BACKEND_SUBNET_ID_UNDERLAY=0 (host-
// network backend marker) and keeps the semantic ladder clean:
// 0 = host-network sentinel, 1 = VXLAN underlay tunnel,
// >=2 = real Subnet VNIs.
#define VNI_UNDERLAY 1

// backend_val.kind values. control-plane (Service reconciler) decides
// the kind by comparing endpoint.nodeName to the daemon's nodeName so
// the data plane never has to infer locality from FIB-lookup side
// effects. POD == 0 keeps backward compat with old reconcilers that did
// not set kind.
#define BACKEND_KIND_POD         0
#define BACKEND_KIND_HOST_REMOTE 1
#define BACKEND_KIND_HOST_LOCAL  2

#define CT_SCOPE_HOST 0

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
  // acl_id is the cluster-wide NetworkACL identifier programmed at
  // this Subnet's boundary. 0 means "no ACL attached"; the data-plane
  // policy stage skips ACL evaluation in that case and lets traffic
  // flow straight to the SG layer. Daemon-side reconciler keeps this
  // in sync with Subnet.status.networkACL.aclID.
  __u32 acl_id;
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

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32); // vxlan ifindex
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} vxlan_ifindex SEC(".maps");

// host_underlay holds this node's underlay IPv4 (the Node's
// InternalIP, in network byte order). Single-entry array map shared
// across programs. pod_egress writes the source IP for host-network
// Service NAPT here at startup; node_ingress consults it to detect
// the response leg of those flows.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} host_underlay SEC(".maps");

// node_underlay holds every Juneau Node's underlay IPv4 in the
// cluster, keyed by the IP itself in network byte order. Existence is
// the verdict (the value byte is unused). Populated by the daemon's
// node-underlay reconciler from juneau_node NetworkEndpoints, with
// the local Node's IP also seeded synchronously at start-up so the
// LB reverse path is reachable before the first informer event.
//
// Used by the LB data path:
//   - pod_egress checks this map when a Pod sends to a destination
//     outside its VPC's FIB. A hit means "this is a Node IP; route
//     via the underlay" so the reply leg of an LB flow whose
//     receiver SNAT'd to a Node IP can leave the backend's VPC and
//     reach the receiver node's main interface.
//   - node_ingress consults host_underlay (single-entry, faster) to
//     match the local Node's IP for the LB_IN reverse path.
struct node_underlay_key {
  __u32 ipaddr;     // network byte order
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_NODE_UNDERLAY);
  __type(key, struct node_underlay_key);
  __type(value, __u8);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} node_underlay SEC(".maps");

// lb_owner_table is the Maglev consistent-hash slot table keyed by
// flow-hash slot index, valued by the underlay IPv4 (network byte
// order) of the Node responsible for that slot's flows. Cluster-wide:
// every Juneau Node holds an identical copy, populated by the daemon's
// lb-owner reconciler from current Node membership using the Maglev
// algorithm.
//
// Used by node_ingress's LB forward path (and, post-decap, by
// vxlan_ingress when VNI_UNDERLAY traffic arrives): the receiving
// Node hashes the 5-tuple modulo MAX_LB_OWNER_TABLE, looks up the
// slot, and — if the slot's owner is not this Node — VXLAN-encaps
// the original frame to the owner with VNI_UNDERLAY. The owner runs
// the SNAT/DNAT/CT-install path locally so every packet of a flow
// converges on the same per-flow CT entry regardless of which Node
// the upstream router ECMP'd it onto.
//
// Initial state: all-zero (the BPF runtime zero-fills array maps).
// Zero is a valid sentinel — 0.0.0.0 is not a routable underlay IP,
// so callers treat zero as "no owner programmed; fall through to
// local handling". This makes the data path safe before the
// reconciler has finished its first pass.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_LB_OWNER_TABLE);
  __type(key, __u32);   // slot index
  __type(value, __u32); // owner underlay IPv4, network byte order
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} lb_owner_table SEC(".maps");

// service_nat_ip holds this node's per-(Node × provider Vpc) SNAT
// source IPs (values in network byte order) keyed by the provider's
// vpc_id. Populated by the daemon from every local
// ServiceNATAttachment.status.assignedIP whose spec.vpc resolves to a
// known Vpc. When handle_service_shared looks up the destination
// Service's owner Vpc and finds no entry, the shared-Service path
// drops the packet rather than emitting traffic with a zero source.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_SERVICE_NAT_IP);
  __type(key, __u32);   // provider vpc_id
  __type(value, __u32); // SNAT IP, network byte order
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} service_nat_ip SEC(".maps");

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

// SVC_FLAG_SHARED marks a Service as reachable from other Vpcs (any
// Vpc with spec.service.consume=true that passes the per-Service
// consumer ACL when set). The data plane treats shared Services as
// if owner_vpc_id matched and routes them through the SNAT-aware
// shared path.
#define SVC_FLAG_SHARED (1U << 0)

// SVC_FLAG_HAS_ACL signals that service_acl_map carries an explicit
// whitelist for this Service. When set, only callers whose
// (cluster_ip, port, proto, caller_vpc_id) tuple is present in
// service_acl_map are admitted. When unset every consume-enabled Vpc
// is admitted by default. Only meaningful in combination with
// SVC_FLAG_SHARED.
#define SVC_FLAG_HAS_ACL (1U << 1)

// SVC_FLAG_AFFINITY_CLIENT_IP marks a Service whose backend selection
// is sticky per caller IP. Set by the reconciler when
// Service.spec.sessionAffinity=ClientIP. The data plane consults
// service_affinity_map keyed by caller IP and returns the cached
// backend index when the entry is fresh (expires_at_ns > now and
// backend_gen matches service_val.gen).
#define SVC_FLAG_AFFINITY_CLIENT_IP (1U << 2)

// SVC_FLAG_INTERNAL_LOCAL records that the reconciler installed only
// node-local backends for this Service because Service.spec
// .internalTrafficPolicy=Local. The flag has no effect on the BPF
// fast path — locality filtering already happens at reconcile time
// by writing only local backends into backend_map. The bit is
// retained for observability and so dump tooling can compare the
// programmed state against the spec.
#define SVC_FLAG_INTERNAL_LOCAL (1U << 3)

// SVC_FLAG_LOAD_BALANCER marks a service_map entry as reachable from
// outside the cluster via the underlay path. node_ingress gates the
// Service-DNAT fast path on this bit so that ClusterIP entries
// (which share the same map but accept only Pod-sourced traffic)
// never accidentally serve external requests that happened to ECMP
// onto this node. Set by the reconciler when a Service is
// type=LoadBalancer AND status.loadBalancer.ingress carries an IP;
// flipping false→true invalidates affinity bindings via the gen bump.
#define SVC_FLAG_LOAD_BALANCER (1U << 4)

struct service_val {
  __u32 owner_vpc_id;   // Vpc that owns the Service; checked against caller_vpc_id
  __u32 backend_count;
  __u32 affinity_sec;   // sessionAffinity ClientIP timeout in seconds; 0 unless SVC_FLAG_AFFINITY_CLIENT_IP set
  __u32 flags;          // bitmask: SVC_FLAG_*
  // gen increases every time the reconciler rewrites the backend set
  // for this Service. Cached service_affinity_map entries that
  // captured an older gen are treated as stale and re-selected,
  // preventing affinity-induced index drift when a Pod backend goes
  // away.
  __u32 gen;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_SERVICE_MAP);
  __type(key, struct service_key);
  __type(value, struct service_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} service_map SEC(".maps");

// service_acl_map encodes the per-(Service × consumer Vpc) admit list
// used when service_val.flags & SVC_FLAG_HAS_ACL. Entries are written
// by the user-space Service reconciler from
// juneau.loutres.me/shared-service-allowed-consumer-vpcs annotations
// and consulted by handle_service_shared on the forward path.
// Existence is the verdict: present → admitted, absent → dropped.
struct service_acl_key {
  __u32 cluster_ip;     // network byte order, matches service_key.cluster_ip
  __u16 port;
  __u8 proto;
  __u8 _pad;
  __u32 caller_vpc_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_SERVICE_ACL);
  __type(key, struct service_acl_key);
  __type(value, __u8);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} service_acl_map SEC(".maps");

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
  __u8 kind;        // BACKEND_KIND_*
  __u8 _pad;
  __u32 backend_subnet_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_BACKEND_MAP);
  __type(key, struct backend_key);
  __type(value, struct backend_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} backend_map SEC(".maps");

// service_affinity_map caches sessionAffinity=ClientIP decisions:
// a single backend index per (Service tuple × caller IP), valid for
// service_val.affinity_sec seconds since the last hit. LRU_HASH so the
// table self-evicts under pressure; correctness only requires that a
// stale entry not bind to a freed backend index, which is enforced by
// matching backend_gen against service_val.gen on lookup.
struct service_affinity_key {
  __u32 cluster_ip;     // host order, mirrors service_key.cluster_ip
  __u16 port;
  __u8 proto;
  __u8 _pad;
  __u32 client_ip;      // host order; AF_INET only
};

struct service_affinity_val {
  __u32 backend_index;  // index into backend_map for the sticky backend
  __u32 backend_gen;    // service_val.gen at write time; mismatch invalidates
  __u64 expires_at_ns;  // CLOCK_MONOTONIC; 0 means "never recorded"
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_SERVICE_AFFINITY_MAP);
  __type(key, struct service_affinity_key);
  __type(value, struct service_affinity_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} service_affinity_map SEC(".maps");

// ct_map is the conntrack table shared by Service and NAPT flows. Both
// directions of a flow are stored as separate entries:
//
//   - Service forward (caller → ClusterIP) carries CT_ACTION_DNAT; scope=vpc_id of caller.
//   - Service reverse (backend → caller) carries CT_ACTION_SNAT; scope=vpc_id of caller.
//   - NAPT forward (pod → internet) carries CT_ACTION_NAPT_OUT; scope=vpc_id of pod.
//   - NAPT reverse (internet → host_napt_ip) carries CT_ACTION_NAPT_IN; scope=CT_SCOPE_HOST (=0).
//
// The map is a regular HASH (not LRU) because LRU's eviction order is
// not flow-aware; user-space periodically scans for idle timeouts.
struct ct_key {
  __u32 scope;             // CT_SCOPE_HOST=0 for host-facing keyspace, otherwise vpc_id
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
  __u32 next_subnet_id;    // VNI used to forward the rewritten packet:
                           //   Service DNAT: backend Pod's Subnet
                           //   NAPT_IN: target Pod's Subnet
                           //   Service SNAT / NAPT_OUT: 0
  __u8 action;             // CT_ACTION_DNAT | CT_ACTION_SNAT | CT_ACTION_NAPT_OUT | CT_ACTION_NAPT_IN
  __u8 state;              // CT_STATE_*: latest state derived from observed TCP flags
  __u8 flags_seen;         // OR-accumulated FIN|SYN|RST|ACK seen on this entry's direction
  __u8 _pad;
  __u64 last_seen_ns;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_CT_MAP);
  __type(key, struct ct_key);
  __type(value, struct ct_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} ct_map SEC(".maps");

// napt_src maps a NATGWID (overloaded into fib_val.subnet_id when
// fib_val.type == FIB_ROUTE_TYPE_NAPT) to the host_napt_ip the local
// node should rewrite the source IP to. Populated by the daemon's NAPT
// reconciler from per-(ExternalNetwork, Node) ExternalNetworkAttachments.
struct napt_src_key {
  __u32 nat_gateway_id;
};

struct napt_src_val {
  __u32 host_ip;           // network byte order
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_NAPT_SRC);
  __type(key, struct napt_src_key);
  __type(value, struct napt_src_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} napt_src SEC(".maps");

// virtual_service_map dispatches Pod traffic destined to a per-Subnet
// virtual service (DNS today; arbitrary L7 services in the future) to
// the daemon's userspace packet plane. Keyed by the (subnet_id, dst IP,
// dst port, proto) tuple so multiple Subnets can share the same VIP
// (.2 in each Subnet's CIDR) without collision. The control-plane writes
// one entry per (Subnet × {UDP/53, TCP/53}) for DNS; the data plane only
// matches entries whose `tap_ifindex` is non-zero (so a half-initialised
// service — e.g. registered before the TAP exists — never causes a
// silent black hole).
struct virtual_service_key {
  __u32 subnet_id;
  __be32 dst_ip;       // network byte order; matches iph->daddr directly
  __be16 dst_port;     // network byte order; matches udp/tcp dst port
  __u8 proto;          // IPPROTO_UDP / IPPROTO_TCP
  __u8 _pad;
};

// VIRTSVC_FLAG_* describe per-entry behaviour. None defined yet; the
// flags slot is reserved so we can opt new services in to behaviours
// (e.g. "skip flow recording", "drop on missing TAP") without rev-ing
// the value layout.
#define VIRTSVC_FLAG_NONE 0

struct virtual_service_val {
  __u32 service_id;
  __u32 tap_ifindex;     // 0 means "service registered but TAP not ready"
  __u8 service_mac[6];
  __u8 _pad[2];
  __u32 flags;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_VIRTUAL_SERVICE_MAP);
  __type(key, struct virtual_service_key);
  __type(value, struct virtual_service_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} virtual_service_map SEC(".maps");

// virtual_service_flow_map records per-flow return-path metadata so the
// daemon can deliver responses straight to the originating Pod's veth
// without consulting the host routing table (Pod IPs may overlap across
// VPCs; Linux has no native vpc_id dimension). Populated on every Pod
// → service packet that hits virtual_service_map; the daemon reads it
// to build the AF_PACKET sockaddr_ll for the response. Keyed by the
// 5-tuple plus subnet_id so VPC isolation is preserved.
struct virtual_service_flow_key {
  __u32 subnet_id;
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u8 proto;
  __u8 _pad[3];
};

struct virtual_service_flow_val {
  __u32 vpc_id;
  __u32 service_id;
  __u32 pod_ifindex;        // host-side veth ifindex for AF_PACKET sockaddr_ll
  __u8 pod_mac[6];          // Pod's host-side veth MAC (response dst)
  __u8 service_mac[6];      // service MAC observed on the request (response src)
  __u8 _pad[2];
  __u64 last_seen_ns;       // userspace GC timestamp
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_VIRTUAL_SERVICE_FLOW_MAP);
  __type(key, struct virtual_service_flow_key);
  __type(value, struct virtual_service_flow_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} virtual_service_flow_map SEC(".maps");

// ---- SecurityGroup data-plane tables --------------------------------
//
// The SG plane is built around three tables:
//
//   sg_membership_map: cluster-wide. Maps a Pod's (vpc_id, ipv4) to the
//                      set of SG groupIDs attached to its NetworkInterface.
//                      Used for both "self" (egress evaluator side) and
//                      "peer" (from-SG / to-SG rule resolution) lookups.
//
//   sg_meta_map:       per-SG metadata (rule counts, ruleset_version,
//                      has_egress_rules). Lets the eval loop terminate
//                      early when the relevant direction has no rules.
//
//   sg_rule_table:     HASH_OF_MAPS keyed by sg_id, inner is a fixed-size
//                      array of sg_rule entries scanned by the evaluator.
//
// All three are populated by the daemon-side reconciler in
// daemon/internal/daemon/dataplane/reconciler/securitygroup.go and
// sg_membership.go.

// SG_DIR_* and SG_PEER_KIND_* keep the rule layout self-describing.
#define SG_DIR_INGRESS 0
#define SG_DIR_EGRESS  1

#define SG_PEER_KIND_CIDR 0
#define SG_PEER_KIND_SG   1

#define SG_VERDICT_DENY  0
#define SG_VERDICT_ALLOW 1

// SG rules use POLICY_PROTO_ANY (defined in policy_match.h) for the
// "protocol=all" wildcard, and IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP
// for concrete protocols. The BPF evaluator therefore compares the
// stored proto byte directly against iph->protocol.

struct sg_membership_key {
  __u32 vpc_id;
  __be32 ipv4;
};

struct sg_membership_val {
  __u8  count;
  __u8  _pad[3];
  __u32 sgs[MAX_SGS_PER_NIC];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_SG_MEMBERSHIP);
  __type(key, struct sg_membership_key);
  __type(value, struct sg_membership_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_membership_map SEC(".maps");

struct sg_meta_val {
  __u32 ingress_count;
  __u32 egress_count;
  __u32 ruleset_version;
  __u8  has_egress_rules;   // 0 → default-allow egress; 1 → allow-list only
  __u8  _pad[3];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_SECURITY_GROUPS);
  __type(key, __u32);       // sg_id
  __type(value, struct sg_meta_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_meta_map SEC(".maps");

// sg_rule encodes a single (peer × proto × ports) tuple after the
// controller has expanded the user-facing rule. port_lo/port_hi are
// inclusive; (0, 0xFFFF) wildcards the L4 port. peer_v4 carries either
// a CIDR base (network byte order) or a peer sg_id depending on
// peer_kind.
struct sg_rule {
  __u8  direction;          // SG_DIR_*
  __u8  proto;              // POLICY_PROTO_ANY or IPPROTO_*
  __u16 port_lo;            // host byte order
  __u16 port_hi;            // host byte order
  __u8  peer_kind;          // SG_PEER_KIND_*
  __u8  peer_prefixlen;     // CIDR prefix length (0..32)
  __be32 peer_v4;           // CIDR base (NBO) or peer sg_id (host order if SG)
  __u8  verdict;            // SG_VERDICT_*
  __u8  _pad[3];
};

struct sg_rules_inner {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_RULES_PER_SG);
  __type(key, __u32);
  __type(value, struct sg_rule);
};

struct sg_rules_inner sg_rules_inner_proto SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_SECURITY_GROUPS);
  __type(key, __u32);       // sg_id
  __type(value, __u32);     // inner map fd handle
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct sg_rules_inner);
} sg_rule_table SEC(".maps");

// ---- NetworkACL data-plane tables -----------------------------------
//
// The ACL plane mirrors the SG plane structurally and shares the L3/L4
// matching primitives in policy_match.h. Differences:
//
//   * Attachment: ACLs are referenced by Subnet (subnet_map.acl_id),
//     not by NetworkInterface. There is consequently no
//     acl_membership_map analogue.
//   * Rules carry explicit priority and Action. The daemon-side writer
//     sorts rules by priority (ascending) so the BPF evaluator can scan
//     front-to-back and short-circuit on the first match.
//   * MAX_RULES_PER_ACL is larger than MAX_RULES_PER_SG because ACL
//     rules are CIDR-only (no peer-set fan-out), so the post-expansion
//     rule budget per ACL is more forgiving. Verifier pressure is
//     dominated by SG, which sits downstream of ACL eval.

#define MAX_RULES_PER_ACL 16
#define MAX_NETWORK_ACLS  4096

#define ACL_DIR_INGRESS 0
#define ACL_DIR_EGRESS  1

#define ACL_VERDICT_DENY  0
#define ACL_VERDICT_ALLOW 1
// ACL_VERDICT_PASS is the evaluator's "no ACL attached / direction
// defaults to allow / no rule matched and direction is in default-
// allow mode" signal. Distinct from ALLOW so callers know whether to
// install CT.
#define ACL_VERDICT_PASS  2

struct acl_meta_val {
  __u32 ingress_count;
  __u32 egress_count;
  __u64 ruleset_version;
  __u8  has_ingress_rules;  // 0 → ingress is default-allow (no enforcement)
  __u8  has_egress_rules;   // 0 → egress is default-allow
  __u8  _pad[6];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_NETWORK_ACLS);
  __type(key, __u32);       // acl_id
  __type(value, struct acl_meta_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_meta_map SEC(".maps");

// acl_rule encodes a single (peer × proto × ports) tuple after the
// daemon-side writer expands and sorts the user-facing ruleset by
// priority. priority is kept on the rule for observability /
// debuggability (bpftool dumps); the eval loop relies on the slot
// order, not the priority field.
struct acl_rule {
  __u8  direction;          // ACL_DIR_*
  __u8  proto;              // POLICY_PROTO_ANY or IPPROTO_*
  __u16 port_lo;            // host byte order
  __u16 port_hi;            // host byte order
  __u8  prefixlen;          // CIDR prefix length (0..32)
  __u8  verdict;            // ACL_VERDICT_ALLOW or ACL_VERDICT_DENY
  __u16 priority;           // host byte order; lower runs first
  __u8  _pad[2];
  __be32 peer_v4;           // CIDR base, network byte order
};

struct acl_rules_inner {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_RULES_PER_ACL);
  __type(key, __u32);
  __type(value, struct acl_rule);
};

struct acl_rules_inner acl_rules_inner_proto SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_NETWORK_ACLS);
  __type(key, __u32);       // acl_id
  __type(value, __u32);     // inner map fd handle
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct acl_rules_inner);
} acl_rule_table SEC(".maps");

#endif // JUNEAU_BPF_MAPS_H
