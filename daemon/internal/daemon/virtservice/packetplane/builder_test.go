package packetplane

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func TestBuildUDPResponse(t *testing.T) {
	flow := Flow{
		ServiceIP:   netip.MustParseAddr("10.0.0.2"),
		ServicePort: 53,
		ClientIP:    netip.MustParseAddr("10.0.0.42"),
		ClientPort:  4711,
		Proto:       17,
		ServiceMAC:  net.HardwareAddr{0x02, 0x42, 0x0a, 0x00, 0x00, 0x02},
		PodMAC:      net.HardwareAddr{0x02, 0x42, 0x0a, 0x00, 0x00, 0x2a},
	}
	payload := []byte("hello-dns")

	frame, err := BuildUDPResponse(flow, payload)
	if err != nil {
		t.Fatalf("BuildUDPResponse: %v", err)
	}

	wantLen := EthernetHeaderLen + IPv4HeaderLen + UDPHeaderLen + len(payload)
	if len(frame) != wantLen {
		t.Fatalf("frame len = %d, want %d", len(frame), wantLen)
	}

	// Ethernet: dst=Pod, src=Service.
	if !macEq(frame[0:6], flow.PodMAC) {
		t.Errorf("eth dst = %v, want %v", frame[0:6], flow.PodMAC)
	}
	if !macEq(frame[6:12], flow.ServiceMAC) {
		t.Errorf("eth src = %v, want %v", frame[6:12], flow.ServiceMAC)
	}
	if et := binary.BigEndian.Uint16(frame[12:14]); et != EtherTypeIPv4 {
		t.Errorf("ethertype = 0x%04x, want 0x%04x", et, EtherTypeIPv4)
	}

	ip := frame[EthernetHeaderLen : EthernetHeaderLen+IPv4HeaderLen]
	if ip[0] != 0x45 {
		t.Errorf("ip vihl = 0x%02x, want 0x45", ip[0])
	}
	if total := binary.BigEndian.Uint16(ip[2:4]); int(total) != IPv4HeaderLen+UDPHeaderLen+len(payload) {
		t.Errorf("ip total len = %d", total)
	}
	if ttl := ip[8]; ttl != 64 {
		t.Errorf("ttl = %d, want 64", ttl)
	}
	if proto := ip[9]; proto != 17 {
		t.Errorf("ip proto = %d, want 17 (UDP)", proto)
	}
	wantSrc := flow.ServiceIP.As4()
	wantDst := flow.ClientIP.As4()
	if !bytesEq(ip[12:16], wantSrc[:]) {
		t.Errorf("ip src = %v, want %v", ip[12:16], wantSrc)
	}
	if !bytesEq(ip[16:20], wantDst[:]) {
		t.Errorf("ip dst = %v, want %v", ip[16:20], wantDst)
	}
	// IP checksum: zero the field, recompute, compare.
	ipCopy := append([]byte(nil), ip...)
	ipCopy[10] = 0
	ipCopy[11] = 0
	wantCsum := onesComplementChecksum(ipCopy)
	gotCsum := binary.BigEndian.Uint16(ip[10:12])
	if gotCsum != wantCsum {
		t.Errorf("ip csum = 0x%04x, want 0x%04x", gotCsum, wantCsum)
	}

	udp := frame[EthernetHeaderLen+IPv4HeaderLen : EthernetHeaderLen+IPv4HeaderLen+UDPHeaderLen]
	if sp := binary.BigEndian.Uint16(udp[0:2]); sp != flow.ServicePort {
		t.Errorf("udp src port = %d, want %d", sp, flow.ServicePort)
	}
	if dp := binary.BigEndian.Uint16(udp[2:4]); dp != flow.ClientPort {
		t.Errorf("udp dst port = %d, want %d", dp, flow.ClientPort)
	}
	if ulen := binary.BigEndian.Uint16(udp[4:6]); int(ulen) != UDPHeaderLen+len(payload) {
		t.Errorf("udp len = %d", ulen)
	}

	// UDP checksum: validate by recomputing over (pseudo, udp_header_with_zero_csum, payload)
	udpCopy := append([]byte(nil), udp...)
	udpCopy[6] = 0
	udpCopy[7] = 0
	wantUdpCsum := udpChecksum(wantSrc, wantDst, udpCopy, payload)
	if wantUdpCsum == 0 {
		wantUdpCsum = 0xFFFF
	}
	gotUdpCsum := binary.BigEndian.Uint16(udp[6:8])
	if gotUdpCsum != wantUdpCsum {
		t.Errorf("udp csum = 0x%04x, want 0x%04x", gotUdpCsum, wantUdpCsum)
	}

	// Payload bytes preserved.
	if !bytesEq(frame[EthernetHeaderLen+IPv4HeaderLen+UDPHeaderLen:], payload) {
		t.Errorf("payload mismatch")
	}
}

func TestBuildUDPResponseRejectsIPv6(t *testing.T) {
	flow := Flow{
		ServiceIP:   netip.MustParseAddr("fe80::1"),
		ClientIP:    netip.MustParseAddr("fe80::2"),
		ServiceMAC:  net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		PodMAC:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		Proto:       17,
		ServicePort: 53,
		ClientPort:  4711,
	}
	if _, err := BuildUDPResponse(flow, nil); err == nil {
		t.Fatal("BuildUDPResponse(IPv6) should error")
	}
}

func TestBuildUDPResponseRejectsBadMAC(t *testing.T) {
	flow := Flow{
		ServiceIP:   netip.MustParseAddr("10.0.0.2"),
		ClientIP:    netip.MustParseAddr("10.0.0.42"),
		ServiceMAC:  net.HardwareAddr{1, 2, 3}, // too short
		PodMAC:      net.HardwareAddr{0x02, 0x42, 0x0a, 0x00, 0x00, 0x2a},
		Proto:       17,
		ServicePort: 53,
		ClientPort:  4711,
	}
	if _, err := BuildUDPResponse(flow, nil); err == nil {
		t.Fatal("BuildUDPResponse(bad MAC) should error")
	}
}

func macEq(a []byte, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
