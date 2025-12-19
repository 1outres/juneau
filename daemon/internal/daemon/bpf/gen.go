package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go HostEgress ../../../bpf/pod_egress.c
