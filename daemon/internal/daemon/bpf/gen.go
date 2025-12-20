package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go PodEgress ../../../bpf/pod_egress.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go HostEgress ../../../bpf/host_egress.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go VxlanIngress ../../../bpf/vxlan_ingress.c
