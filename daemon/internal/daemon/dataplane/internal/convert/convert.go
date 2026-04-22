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

// IPv4ToLPMTrieUint32 converts an IPv4 address to a little-endian uint32,
// the format used by BPF_MAP_TYPE_LPM_TRIE keys.
func IPv4ToLPMTrieUint32(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %v", ip)
	}
	return binary.LittleEndian.Uint32(ip4), nil
}

// IPMaskToUint32 converts an IPv4 netmask to a big-endian uint32
// (e.g. /16 -> 0xffff0000).
func IPMaskToUint32(mask net.IPMask) (uint32, error) {
	if len(mask) != 4 {
		return 0, fmt.Errorf("invalid IPv4 mask length: %d", len(mask))
	}
	return binary.BigEndian.Uint32(mask), nil
}
