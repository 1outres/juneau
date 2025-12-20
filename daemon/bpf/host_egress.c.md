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
} arp_table SEC(".maps");
```

# Functions

## tc_host_egress

1. handle_l2関数を呼び出し、その関数の返り値を返す

## handle_l2

1. L2ヘッダーのパースを行う
2. ARPリクエストの場合、handle_arp関数を呼び出し、その関数の返り値を返す
3. ドロップする

## handle_arp

1. ARPペイロードのパースを行う
2. arp_table mapを引く(subnet_idは1、ipaddrはARP対象のIP)
3. arp_tableにみつからない場合ドロップ
4. エントリが見つかった場合、ARPレスポンスとして返す(bpf_redirectを使う)
