package packetplane

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// Sender writes raw Ethernet frames to a specific kernel ifindex via a
// shared AF_PACKET socket. Used by the packet plane to deliver virtual
// service responses straight to a Pod's host-side veth, bypassing the
// host routing table — the only safe path when Pod IPs may overlap
// across VPCs.
//
// The socket is opened once per Sender and reused across all sends.
// AF_PACKET sendto() takes the destination ifindex in its sockaddr_ll
// argument, so a single socket can serve every Pod on the node.
type Sender struct {
	mu sync.Mutex
	fd int
}

// NewSender opens an AF_PACKET socket suitable for raw Ethernet
// transmission. The socket is created with htons(ETH_P_ALL) so the
// kernel doesn't filter outbound frames by EtherType. Returned Sender
// must be Close()d.
//
// Required capability: CAP_NET_RAW (the daemon already runs with this
// for VXLAN / TC). The socket is non-blocking so a slow downstream
// device cannot wedge the dispatcher goroutine.
func NewSender() (*Sender, error) {
	// SOCK_RAW + SOCK_NONBLOCK. Protocol = htons(ETH_P_ALL) so the
	// kernel does not bind us to a specific EtherType for sending.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET socket: %w", err)
	}
	return &Sender{fd: fd}, nil
}

// SendTo transmits the given raw Ethernet frame on the netdev with the
// supplied ifindex. dstMAC is required by sockaddr_ll for the kernel
// to resolve the link layer; on a veth this can be any value (the
// frame's own h_dest carries the real address) but we still pass the
// Pod's MAC so packet captures on the device show consistent metadata.
//
// Concurrent SendTo calls are serialised via a mutex — sendto() on an
// AF_PACKET socket is itself thread-safe, but serialising lets the
// dispatcher reuse the same scratch sockaddr_ll without a per-send
// allocation.
func (s *Sender) SendTo(ifindex int, dstMAC net.HardwareAddr, frame []byte) error {
	if s == nil || s.fd < 0 {
		return errors.New("packetplane: sender is closed")
	}
	if ifindex <= 0 {
		return fmt.Errorf("packetplane: invalid ifindex %d", ifindex)
	}
	if len(dstMAC) != 6 {
		return fmt.Errorf("packetplane: invalid MAC length %d", len(dstMAC))
	}

	var addr unix.SockaddrLinklayer
	addr.Protocol = htons(unix.ETH_P_IP)
	addr.Ifindex = ifindex
	addr.Halen = 6
	copy(addr.Addr[:], dstMAC)

	s.mu.Lock()
	defer s.mu.Unlock()
	return unix.Sendto(s.fd, frame, 0, &addr)
}

// Close releases the underlying AF_PACKET socket. Safe to call once;
// subsequent calls return nil.
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	err := unix.Close(s.fd)
	s.fd = -1
	return err
}

// htons swaps a uint16 to network byte order so AF_PACKET sees the
// canonical big-endian EtherType regardless of host endianness.
func htons(x uint16) uint16 {
	return (x<<8)&0xff00 | x>>8
}
