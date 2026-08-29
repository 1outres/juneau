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

// ARP opcodes a test builds a frame with.
const (
	ARPRequest = 1
	ARPReply   = 2
)

// ARP builds the payload of an Ethernet/IPv4 ARP frame. A request, a
// reply and a gratuitous announcement differ only in the opcode and the
// addresses, so one builder covers all three.
func ARP(t *testing.T, op uint16, senderMAC net.HardwareAddr, senderIP string, targetMAC net.HardwareAddr, targetIP string) []byte {
	t.Helper()

	payload := make([]byte, 28)
	binary.BigEndian.PutUint16(payload[0:2], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(payload[2:4], 0x0800) // protocol type: IPv4
	payload[4] = 6                                   // hardware address length
	payload[5] = 4                                   // protocol address length
	binary.BigEndian.PutUint16(payload[6:8], op)
	copy(payload[8:14], senderMAC)
	copy(payload[14:18], ipv4Bytes(t, senderIP))
	copy(payload[18:24], targetMAC)
	copy(payload[24:28], ipv4Bytes(t, targetIP))
	return payload
}

// IPv4 builds the payload of a minimal IPv4 packet. Nothing in the L2
// data plane reads past the destination address, so the header carries
// no options and no checksum.
func IPv4(t *testing.T, src, dst string) []byte {
	t.Helper()

	packet := make([]byte, 20)
	packet[0] = 0x45 // version 4, header length 5 words
	binary.BigEndian.PutUint16(packet[2:4], 20)
	packet[8] = 64 // ttl
	packet[9] = 1  // ICMP
	copy(packet[12:16], ipv4Bytes(t, src))
	copy(packet[16:20], ipv4Bytes(t, dst))
	return packet
}

func ipv4Bytes(t *testing.T, address string) []byte {
	t.Helper()
	ip := net.ParseIP(address).To4()
	if ip == nil {
		t.Fatalf("bpftest: %q is not an IPv4 address", address)
	}
	return ip
}

// TCPv4 builds the payload of a minimal IPv4 TCP segment. The checksums
// are left at zero: the data plane only ever updates them
// incrementally, so nothing along the way reads them.
func TCPv4(t *testing.T, src, dst string, sport, dport uint16) []byte {
	t.Helper()

	packet := make([]byte, 40)
	packet[0] = 0x45 // version 4, header length 5 words
	binary.BigEndian.PutUint16(packet[2:4], 40)
	packet[8] = 64 // ttl
	packet[9] = 6  // TCP
	copy(packet[12:16], ipv4Bytes(t, src))
	copy(packet[16:20], ipv4Bytes(t, dst))

	binary.BigEndian.PutUint16(packet[20:22], sport)
	binary.BigEndian.PutUint16(packet[22:24], dport)
	packet[32] = 5 << 4 // data offset: 5 words
	packet[33] = 0x10   // ACK
	return packet
}

// SourceAddress and SourcePort read back what a program left in an IPv4
// TCP frame, so a test can say what a rewrite turned it into.
func SourceAddress(t *testing.T, frame []byte) string {
	t.Helper()
	if len(frame) < 34 {
		t.Fatalf("bpftest: a frame of %d bytes carries no IPv4 header", len(frame))
	}
	return net.IP(frame[26:30]).String()
}

func SourcePort(t *testing.T, frame []byte) uint16 {
	t.Helper()
	if len(frame) < 38 {
		t.Fatalf("bpftest: a frame of %d bytes carries no TCP header", len(frame))
	}
	return binary.BigEndian.Uint16(frame[34:36])
}
