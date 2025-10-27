package netutil

import (
	"fmt"
	"math/big"
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

