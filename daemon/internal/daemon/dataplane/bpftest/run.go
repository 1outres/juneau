package bpftest

import (
	"structs"
	"testing"

	"github.com/cilium/ebpf"
)

// skbContext is the head of struct __sk_buff, up to and including the
// last field BPF_PROG_TEST_RUN lets a caller set. The kernel takes a
// context shorter than the full struct and zeroes the rest, so
// stopping at ifindex is enough and keeps the layout easy to check
// against include/uapi/linux/bpf.h.
type skbContext struct {
	_              structs.HostLayout
	Len            uint32
	PktType        uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VlanPresent    uint32
	VlanTci        uint32
	VlanProto      uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
}

// Run hands one frame to a program as if it had arrived on the given
// device, and returns the TC verdict.
//
// The device has to exist: the kernel resolves ctx.ifindex before it
// runs the program and refuses the call when it cannot. That is what
// makes the flood tests possible — the ports a program copies to are
// real devices, and their counters say what arrived.
func Run(t *testing.T, prog *ebpf.Program, frame []byte, device Device) int {
	t.Helper()

	in := skbContext{Ifindex: uint32(device.Index)}
	verdict, err := prog.Run(&ebpf.RunOptions{
		Data:    frame,
		DataOut: make([]byte, len(frame)+256),
		Context: &in,
		Repeat:  1,
	})
	if err != nil {
		t.Fatalf("bpftest: run the program on %s: %v", device.Name, err)
	}
	return int(verdict)
}
