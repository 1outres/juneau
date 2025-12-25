- Podから出るパケットを見る
- Podのveth peerのingressにアタッチするが、実質podのegressを見る形になる
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# eBPF map

## ifindex_subnet

```
#ifndef MAX_IF_SUBNET
#define MAX_IF_SUBNET 32768
#endif

struct ifindex_subnet_key {
    __u32 ifindex;
};

struct ifindex_subnet_val {
    __u32  subnet_id;
    __u8   gw_mac[6];
    __u32  gw_addr;
    __u32  mask;
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IF_SUBNET);
    __type(key,         struct ifindex_subnet_key);
    __type(value,       struct ifindex_subnet_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_subnet SEC(".maps");
```

## arp_table

```
#ifndef MAX_ARP_TABLE
#define MAX_ARP_TABLE 131072
#endif

struct arp_table_key {
    __u32 subnet_id;
    __u32 ipaddr;
};

struct arp_table_val {
    __u8  mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ARP_TABLE);
    __type(key,   struct arp_table_key);
    __type(value, struct arp_table_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} arp_table SEC(".maps");
```

## fdb

```
#ifndef MAX_FDB
#define MAX_FDB 131072
#endif

struct fdb_key {
    __u32 subnet_id;
    __u8  mac[6];
};

struct fdb_val {
  __u32 ifindex; // もしそのMACアドレスが同じnodeにある場合
  __u32 vtep_ip; // もしそのMACアドレスが違うnodeにある場合
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FDB);
    __type(key,   struct fdb_key);
    __type(value, struct fdb_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fdb SEC(".maps");
```

## host_iface

```
struct host_iface_val {
    __u32  ifindex;
    __u8   mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct host_iface_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} host_iface SEC(".maps");
```

## vxlan_ifindex

```
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);  // vxlan ifindex
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} vxlan_ifindex SEC(".maps");
```

- `gw_addr` と `mask` は host order の `__u32` を格納する (例: 10.16.0.1 -> 0x0a100001, /16 -> 0xffff0000)

# Functions

## tc_pod_egress

1. handle_l2関数を呼び出し、その関数の返り値を返す

## handle_l2

1. L2ヘッダーのパースを行う
2. ifindex_subnet mapを引く(key: skb->ifindex)
3. ARPリクエストの場合、handle_arp関数を呼び出し、その関数の返り値を返す（handle_arp関数にはifindex_subnet mapのvalも渡す）
4. subnet_idが1の場合、host_iface mapを引いて、ifindexにbpf_redirectする
5. subnet_idが1以外の場合、fdb mapを引く(macは宛先macaddr)
6. fdp mapになかったらドロップ
7. ifindexが0じゃなかったら、そのifindexにbpf_redirect
8. ifindexが0だったら
9. vxlan_ifindex mapを引く
10. vtep_ipを使ってbpf_skb_set_tunnel_key（VNIはsubnet_id）して、vxlan ifindexにbpf_redirectする

## handle_arp

1. ARPペイロードのパースを行う
2. 対象のIPアドレスが範囲内かどうか、gw_addrとmaskを使って範囲判定する。範囲外の場合ドロップする。
3. subnet_idが1の場合、gw_macをARPレスポンスとして返す(bpf_redirectを使う)
  - dst macをrequester mac, source macをgw_mac
  - thaをrequester mac, tpaをrequester ip, shaをgw_mac, spaを元のtpa
4. subnet_idが1以外の場合、arp_table mapを引く
5. arp_tableに見つからない場合ドロップ
6. エントリが見つかった場合、ARPレスポンスとして返す(bpf_redirectを使う)
