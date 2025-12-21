- VXLANに入るパケットを見る
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# eBPF map

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

# Functions

## tc_vxlan_ingress

1. L2ヘッダーのパースを行う
2. tunnel keyを取得し、そこからsubnet_idを復元する
3. subnet_idが1の場合、host_iface mapを引く。宛先MACアドレスをmacで書き換えて、ifindexに転送する
4. ドロップする

