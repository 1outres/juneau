package netutil

import (
	"net"
)

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

