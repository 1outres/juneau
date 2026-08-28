package bpftest

import (
	"encoding/binary"
	"net"
	"testing"
)

// EtherType values the tests build frames with. IPv4 is here because
// the trace plane only recognises it; ARP and the two made-up ones
// stand for "anything at all", which is what an L2Network has to
// carry.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86dd
)

// minEthernetFrame is the shortest frame a real link carries. Frames
// are padded to it so nothing along the way has to decide what to do
// with a runt.
const minEthernetFrame = 60

// Broadcast is the destination MAC every port of a segment has to see.
var Broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// MAC builds a locally administered unicast address ending in the
// given byte, so a test can name its hosts 1, 2, 3 and read the map
// dumps without decoding.
func MAC(last byte) net.HardwareAddr {
	return net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, last}
}

// MulticastIPv4 is the Ethernet address IPv4 multicast maps onto.
var MulticastIPv4 = net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}

// MulticastIPv6 is the Ethernet address IPv6 neighbor discovery uses.
var MulticastIPv6 = net.HardwareAddr{0x33, 0x33, 0xff, 0x00, 0x00, 0x01}

// Frame builds one Ethernet frame. The payload is whatever the test
// wants; nothing in the L2 data plane reads past the header.
func Frame(t *testing.T, dst, src net.HardwareAddr, etherType uint16, payload []byte) []byte {
	t.Helper()
	if len(dst) != 6 || len(src) != 6 {
		t.Fatalf("bpftest: a frame needs two 6-byte addresses, got %d and %d", len(dst), len(src))
	}

	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)

	if len(frame) < minEthernetFrame {
		frame = append(frame, make([]byte, minEthernetFrame-len(frame))...)
	}
	return frame
}
