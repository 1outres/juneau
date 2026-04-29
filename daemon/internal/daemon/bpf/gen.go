package bpf

//go:generate bpf2go -cc bpf-clang -strip bpf-llvm-strip PodEgress ../../../bpf/pod_egress.c -- -I../../../bpf
//go:generate bpf2go -cc bpf-clang -strip bpf-llvm-strip PodIngress ../../../bpf/pod_ingress.c -- -I../../../bpf
//go:generate bpf2go -cc bpf-clang -strip bpf-llvm-strip VxlanIngress ../../../bpf/vxlan_ingress.c -- -I../../../bpf
//go:generate bpf2go -cc bpf-clang -strip bpf-llvm-strip NodeIngress ../../../bpf/node_ingress.c -- -I../../../bpf
