package bpftest

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Send writes one frame out of a device, as the network stack of whatever
// sits behind it would. On one end of a Veth, the frame arrives at the
// other end and runs its ingress hook.
//
// The socket is opened in the network namespace of the calling thread, so
// call it from the goroutine Netns pinned.
func Send(t *testing.T, device Device, frame []byte) {
	t.Helper()

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatalf("bpftest: open a packet socket: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: device.Index}); err != nil {
		t.Fatalf("bpftest: send a frame out of %s: %v", device.Name, err)
	}
}
