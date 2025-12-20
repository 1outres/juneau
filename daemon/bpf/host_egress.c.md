- ホストのifaceから出るパケットを見る（ホストからコンテナネットワークへの疎通性を確保するためのiface）
- Host ifaceのveth peerのingressにアタッチするが、実質hostのegressを見る形になる
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# eBPF map

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

# Functions

## tc_host_egress

1. handle_l2関数を呼び出し、その関数の返り値を返す

## handle_l2

1. L2ヘッダーのパースを行う
2. ARPリクエストの場合、handle_arp関数を呼び出し、その関数の返り値を返す
3. fdb mapを引く(subnet_idは1、macは宛先macaddr)
4. fdb mapになかったらドロップ
5. ifindexが0じゃなかったら、そのifindexにbpf_redirect
6. ifindexが0だったら
7. vxlan_ifindex mapを引く
8. vtep_ipを使ってbpf_skb_set_tunnel_key（VNIは1）して、vxlan ifindexにbpf_redirectする

## handle_arp

1. ARPペイロードのパースを行う
2. arp_table mapを引く(subnet_idは1、ipaddrはARP対象のIP)
3. arp_tableにみつからない場合ドロップ
4. エントリが見つかった場合、ARPレスポンスとして返す(bpf_redirectを使う)
