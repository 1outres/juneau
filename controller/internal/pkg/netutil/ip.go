package netutil

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"net"
)

// Overlaps checks if there are any overlapping subnets in the given list.
func Overlaps(subnets []string) (bool, error) {
	nets := make([]*net.IPNet, 0, len(subnets))
	for _, s := range subnets {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return false, err
		}
		nets = append(nets, ipnet)
	}
	for i := 0; i < len(nets); i++ {
		for j := i + 1; j < len(nets); j++ {
			if subnetOverlap(nets[i], nets[j]) {
				return true, nil
			}
		}
	}
	return false, nil
}

func subnetOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// V4CapacityHosts returns the number of usable host addresses
// (excluding network and broadcast) for the given IPv4 subnet in CIDR notation.
// Subnets larger than /16 (i.e., prefix < 16) will return an error.
func V4CapacityHosts(cidr string) (uint64, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("invalid CIDR: %w", err)
	}
	return V4CapacityHostsNet(ipnet)
}

// V4CapacityHostsNet returns the number of usable host addresses
// (excluding network and broadcast) for the given IPv4 *net.IPNet.
// Subnets larger than /16 (i.e., prefix < 16) will return an error.
func V4CapacityHostsNet(ipnet *net.IPNet) (uint64, error) {
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("ipv4 only is supported")
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return 0, fmt.Errorf("ipv4 only is supported")
	}
	if ones < 16 {
		return 0, fmt.Errorf("subnet larger than /16 is not allowed: /%d", ones)
	}

	hostBits := uint(32 - ones)
	if hostBits <= 1 {
		return 0, nil
	}

	var two big.Int
	two.SetUint64(2)
	var pow big.Int
	pow.Exp(&two, big.NewInt(int64(hostBits)), nil)
	pow.Sub(&pow, big.NewInt(2))
	return pow.Uint64(), nil
}

// NthIPv4InSubnet returns the n-th IPv4 address in the given subnet,
// where n=1 means the first address after the network address.
// Subnets larger than /16 (i.e., prefix < 16) will return an error.
func NthIPv4InSubnet(cidr string, n uint32) (net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("ipv4 only is supported")
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("ipv4 only is supported")
	}
	if ones < 16 {
		return nil, fmt.Errorf("subnet larger than /16 is not allowed: /%d", ones)
	}

	// Convert base IP to uint32
	base := binary.BigEndian.Uint32(ip4)
	size := uint32(1 << (32 - ones))

	// n starts at 1 = first usable address
	if n == 0 || n >= size-1 {
		return nil, fmt.Errorf("n out of range (1 <= n <= %d)", size-2)
	}

	target := base + n
	result := make(net.IP, 4)
	binary.BigEndian.PutUint32(result, target)

	// Ensure it's inside the subnet
	if !ipnet.Contains(result) {
		return nil, fmt.Errorf("calculated IP is out of subnet")
	}

	return result, nil
}

// NextUsableIPv4InSubnet returns the next usable IPv4 host address within the given CIDR after the provided IPv4 address.
// It excludes the network and broadcast addresses. It returns (nil, false, nil) if the current address is at the last
// usable host. It returns an error for invalid inputs, non-IPv4, subnets larger than /16 (prefix < 16),
// addresses outside the subnet, or subnets with no usable hosts.
func NextUsableIPv4InSubnet(cidr string, current net.IP) (net.IP, bool, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid CIDR: %w", err)
	}

	ip4 := current.To4()
	if ip4 == nil {
		return nil, false, fmt.Errorf("ipv4 only is supported")
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, false, fmt.Errorf("ipv4 only is supported")
	}
	if ones < 16 {
		return nil, false, fmt.Errorf("subnet larger than /16 is not allowed: /%d", ones)
	}

	network := ipnet.IP.Mask(ipnet.Mask).To4()
	if network == nil {
		return nil, false, fmt.Errorf("invalid network address")
	}

	if !ipnet.Contains(ip4) {
		return nil, false, fmt.Errorf("ip is not inside the subnet")
	}

	size := uint32(1) << (32 - ones)
	if size <= 2 {
		return nil, false, fmt.Errorf("subnet has no usable hosts")
	}

	firstUsable := beToUint32(network) + 1
	lastUsable := beToUint32(network) + size - 2
	cur := beToUint32(ip4)

	if cur < firstUsable {
		out := make(net.IP, 4)
		binary.BigEndian.PutUint32(out, firstUsable)
		return out, true, nil
	}
	if cur >= beToUint32(network)+size-1 {
		return nil, false, fmt.Errorf("ip is broadcast address")
	}
	if cur >= lastUsable {
		return nil, false, nil
	}

	next := cur + 1
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, next)
	return out, true, nil
}

// RandomUsableIPv4InSubnet returns a random usable IPv4 host address within the given CIDR.
// It excludes the network and broadcast addresses. It returns an error for invalid inputs,
// non-IPv4, subnets larger than /16 (prefix < 16), or subnets with no usable hosts.
func RandomUsableIPv4InSubnet(cidr string) (net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("ipv4 only is supported")
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("ipv4 only is supported")
	}
	if ones < 16 {
		return nil, fmt.Errorf("subnet larger than /16 is not allowed: /%d", ones)
	}

	size := uint32(1) << (32 - ones)
	if size <= 2 {
		return nil, fmt.Errorf("subnet has no usable hosts")
	}

	network := ipnet.IP.Mask(ipnet.Mask).To4()
	firstUsable := beToUint32(network) + 1
	lastUsable := beToUint32(network) + size - 2

	random := firstUsable + uint32(rand.Intn(int(lastUsable-firstUsable+1)))

	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, random)
	return out, nil
}

// beToUint32 converts a 4-byte net.IP to a uint32 in big-endian.
func beToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}
