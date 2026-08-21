package convert

import (
	"encoding/binary"
	"fmt"
	"net"
)

// HardwareAddrToUint8Array copies a MAC address into a 6-byte array suitable
// for eBPF map values.
func HardwareAddrToUint8Array(mac net.HardwareAddr) ([6]uint8, error) {
	var arr [6]uint8
	if len(mac) != 6 {
		return arr, fmt.Errorf("invalid MAC address length: %d", len(mac))
	}
	copy(arr[:], mac)
	return arr, nil
}

// IPv4ToUint32 converts an IPv4 address to a big-endian uint32 (e.g.
// 10.16.0.1 -> 0x0a100001), the format used by most of our eBPF maps.
func IPv4ToUint32(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %v", ip)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

// Uint32ToIPv4 is the inverse of IPv4ToUint32. Use it to render a BPF
// map field back as a readable address.
func Uint32ToIPv4(value uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, value)
	return ip
}

// IPv4ToBPFNetworkOrder encodes an IPv4 address as a uint32 whose
// memory representation, on a little-endian host, is network byte
// order. Use this for any BPF map field declared as __be32 — direct
// comparison with iph->saddr / iph->daddr, bpf_skb_store_bytes into IP
// headers, or LPM trie keys all expect this layout. The naive
// binary.BigEndian.Uint32 would silently reverse the bytes on LE.
func IPv4ToBPFNetworkOrder(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %v", ip)
	}
	return binary.LittleEndian.Uint32(ip4), nil
}

// IPv4ToLPMTrieUint32 is an alias retained for the existing LPM trie
// call sites. Equivalent to IPv4ToBPFNetworkOrder.
func IPv4ToLPMTrieUint32(ip net.IP) (uint32, error) {
	return IPv4ToBPFNetworkOrder(ip)
}

// IPMaskToUint32 converts an IPv4 netmask to a big-endian uint32
// (e.g. /16 -> 0xffff0000).
func IPMaskToUint32(mask net.IPMask) (uint32, error) {
	if len(mask) != 4 {
		return 0, fmt.Errorf("invalid IPv4 mask length: %d", len(mask))
	}
	return binary.BigEndian.Uint32(mask), nil
}

// BPFNetworkOrderToIPv4 is the inverse of IPv4ToBPFNetworkOrder. Use it
// to render a BPF map field back as a readable address.
func BPFNetworkOrderToIPv4(value uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, value)
	return ip
}
