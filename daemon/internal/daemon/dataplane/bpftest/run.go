package bpftest

import (
	"encoding/binary"
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

// RunFrame is Run, plus the frame as the program left it. A program
// that rewrites the addresses of a frame before it forwards it can only
// be checked this way: the redirect itself carries nothing under
// BPF_PROG_TEST_RUN, so what the frame became is the whole result.
func RunFrame(t *testing.T, prog *ebpf.Program, frame []byte, device Device) (int, []byte) {
	t.Helper()

	in := skbContext{Ifindex: uint32(device.Index)}
	out := make([]byte, len(frame)+256)
	verdict, err := prog.Run(&ebpf.RunOptions{
		Data:    frame,
		DataOut: out,
		Context: &in,
		Repeat:  1,
	})
	if err != nil {
		t.Fatalf("bpftest: run the program on %s: %v", device.Name, err)
	}
	return int(verdict), out[:len(frame)]
}

// RunMarked is Run with a starting skb->mark, and it reports the mark
// the program left behind. juneau counts how often a frame has been
// handed to a gateway port there, so a test that drives that counter
// has to be able to both set it and read it back.
func RunMarked(t *testing.T, prog *ebpf.Program, frame []byte, device Device, mark uint32) (int, uint32) {
	t.Helper()

	in := skbContext{Ifindex: uint32(device.Index), Mark: mark}
	// The kernel writes the whole of its struct __sk_buff back, and it
	// refuses the call with ENOSPC when the room offered is smaller
	// than that. The struct grows between releases, so the buffer is
	// sized past any of them and only the mark is read out of it.
	out := make([]byte, skbContextOutBytes)
	verdict, err := prog.Run(&ebpf.RunOptions{
		Data:       frame,
		DataOut:    make([]byte, len(frame)+256),
		Context:    &in,
		ContextOut: out,
		Repeat:     1,
	})
	if err != nil {
		t.Fatalf("bpftest: run the program on %s: %v", device.Name, err)
	}
	return int(verdict), binary.NativeEndian.Uint32(out[skbMarkOffset : skbMarkOffset+4])
}

// skbContextOutBytes is the room offered for the context the kernel
// writes back, and skbMarkOffset is where mark sits in it: the third
// word of struct __sk_buff, after len and pkt_type.
const (
	skbContextOutBytes = 512
	skbMarkOffset      = 8
)
