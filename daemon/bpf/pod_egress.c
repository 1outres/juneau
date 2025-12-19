// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

SEC("tc")
int tc_pod_egress(struct __sk_buff *skb) { return TC_ACT_OK; }

char __license[] SEC("license") = "Dual MIT/GPL";
