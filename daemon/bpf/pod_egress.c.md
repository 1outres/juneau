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

## host_ifindex

```
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);  // host iface index
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} host_ifindex SEC(".maps");
```

- `gw_addr` と `mask` は host order の `__u32` を格納する (例: 10.16.0.1 -> 0x0a100001, /16 -> 0xffff0000)

# Functions

## tc_pod_egress

1. handle_l2関数を呼び出し、その関数の返り値を返す

## handle_l2

1. L2ヘッダーのパースを行う
2. ifindex_subnet mapを引く(key: skb->ifindex)
3. ARPリクエストの場合、handle_arp関数を呼び出し、その関数の返り値を返す（handle_arp関数にはifindex_subnet mapのvalも渡す）
4. subnet_idが1の場合、host_ifindex mapを引いて、host iface indexにbpf_redirectする
5. ドロップする

## handle_arp

1. ARPペイロードのパースを行う
2. 対象のIPアドレスが範囲内かどうか、gw_addrとmaskを使って範囲判定する。範囲外の場合ドロップする。
3. subnet_idが1の場合、gw_macをARPレスポンスとして返す(bpf_redirectを使う)
  - dst macをrequester mac, source macをgw_mac
  - thaをrequester mac, tpaをrequester ip, shaをgw_mac, spaを元のtpa
4. subnet_idが1以外の場合、ドロップする
