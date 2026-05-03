package packetplane

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// EthernetHeaderLen is the byte size of the Ethernet II header used
// throughout the packet plane (no VLAN, no PI prefix).
const EthernetHeaderLen = 14

// EtherTypeIPv4 is the EtherType for IPv4 frames in network byte
// order, ready to be written into ethhdr.h_proto.
const EtherTypeIPv4 = 0x0800

// IPv4HeaderLen is the byte size of an IPv4 header without options;
// the daemon never emits IP options for virtual service responses.
const IPv4HeaderLen = 20

// UDPHeaderLen is the byte size of the UDP header (fixed at 8).
const UDPHeaderLen = 8

// BuildUDPResponse constructs a complete Ethernet+IPv4+UDP frame for
// a virtual-service response. All header fields are derived from the
// request flow (so the response is symmetric: src ↔ dst swap, ports
// swap), the payload is appended verbatim, and both the IPv4 and UDP
// checksums are computed.
//
// The resulting frame is suitable for direct AF_PACKET sendto() on the
// Pod's host-side veth (frame[0..6) is the destination MAC). Callers
// own the returned slice.
//
// Limits:
//   - payload must fit in a single IP datagram. The packet plane
//     refuses to fragment; oversized DNS responses must set TC and
//     let the client retry over TCP.
//   - IPv4 only. IPv6 support requires a separate builder.
func BuildUDPResponse(flow Flow, payload []byte) ([]byte, error) {
	if !flow.ServiceIP.Is4() || !flow.ClientIP.Is4() {
		return nil, fmt.Errorf("packetplane: BuildUDPResponse needs IPv4 (svc=%s, client=%s)", flow.ServiceIP, flow.ClientIP)
	}
	if len(flow.ServiceMAC) != 6 || len(flow.PodMAC) != 6 {
		return nil, fmt.Errorf("packetplane: BuildUDPResponse needs 6-byte MACs (svc=%v, pod=%v)", flow.ServiceMAC, flow.PodMAC)
	}

	totalIP := IPv4HeaderLen + UDPHeaderLen + len(payload)
	if totalIP > 0xFFFF {
		return nil, fmt.Errorf("packetplane: response too large for single IP datagram: %d bytes", totalIP)
	}

	frame := make([]byte, EthernetHeaderLen+totalIP)

	// Ethernet header: dst = Pod MAC (the original sender), src =
	// service MAC (the address the Pod sent its request to). EtherType
	// = IPv4.
	copy(frame[0:6], flow.PodMAC)
	copy(frame[6:12], flow.ServiceMAC)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv4)

	// IPv4 header.
	ip := frame[EthernetHeaderLen : EthernetHeaderLen+IPv4HeaderLen]
	ip[0] = 0x45 // version 4, IHL 5
	ip[1] = 0    // DSCP / ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalIP))
	binary.BigEndian.PutUint16(ip[4:6], 0)      // identification: 0 — DF set, no fragmentation
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // flags=DF, frag offset=0
	ip[8] = 64                                  // TTL
	ip[9] = flow.Proto                          // IPPROTO_UDP for UDP
	binary.BigEndian.PutUint16(ip[10:12], 0)    // checksum filled in below
	srcIP := flow.ServiceIP.As4()
	dstIP := flow.ClientIP.As4()
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], onesComplementChecksum(ip))

	// UDP header.
	udp := frame[EthernetHeaderLen+IPv4HeaderLen : EthernetHeaderLen+IPv4HeaderLen+UDPHeaderLen]
	binary.BigEndian.PutUint16(udp[0:2], flow.ServicePort)
	binary.BigEndian.PutUint16(udp[2:4], flow.ClientPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(UDPHeaderLen+len(payload)))
	binary.BigEndian.PutUint16(udp[6:8], 0) // checksum filled in below

	// Payload.
	copy(frame[EthernetHeaderLen+IPv4HeaderLen+UDPHeaderLen:], payload)

	// UDP checksum over the pseudo-header + udp header + payload.
	udpCsum := udpChecksum(srcIP, dstIP, udp, payload)
	if udpCsum == 0 {
		// RFC 768: a transmitted checksum of 0 is replaced with
		// 0xffff to distinguish it from "no checksum supplied".
		udpCsum = 0xFFFF
	}
	binary.BigEndian.PutUint16(udp[6:8], udpCsum)

	return frame, nil
}

// onesComplementChecksum is the standard 16-bit one's-complement sum
// used for IPv4 / UDP / TCP checksums. Operates in place on the
// supplied bytes (the checksum field must be zero before calling).
func onesComplementChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum computes the UDP checksum over the IPv4 pseudo-header,
// the UDP header (with the checksum field zero), and the payload.
func udpChecksum(srcIP, dstIP [4]byte, udpHeader, payload []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[8] = 0
	pseudo[9] = 17 // IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udpHeader)+len(payload)))

	var sum uint32
	for _, chunk := range [][]byte{pseudo, udpHeader, payload} {
		for i := 0; i+1 < len(chunk); i += 2 {
			sum += uint32(chunk[i])<<8 | uint32(chunk[i+1])
		}
		if len(chunk)%2 == 1 {
			sum += uint32(chunk[len(chunk)-1]) << 8
		}
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// addrFromBytes turns a network-byte-order 4-byte slice into a
// netip.Addr. Used by parsers in the dispatcher.
func addrFromBytes(b []byte) netip.Addr {
	if len(b) != 4 {
		return netip.Addr{}
	}
	var arr [4]byte
	copy(arr[:], b)
	return netip.AddrFrom4(arr)
}
