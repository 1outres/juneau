package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go PodEgress ../../../bpf/pod_egress.c
