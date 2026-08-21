package ownedaddr

import (
	"fmt"
	"net"
	"strings"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
)

// Key is one prefix of the external_address_pools LPM trie. Addr holds
// the network address in the byte order the trie expects; see
// convert.IPv4ToBPFNetworkOrder.
type Key struct {
	Prefixlen uint32
	Addr      uint32
}

// ParsePrefix reads a bare IPv4 address, which is taken as a /32, or an
// IPv4 CIDR. Host bits are masked off so that every spelling of the
// same prefix yields the same Key.
func ParsePrefix(raw string) (Key, error) {
	var key Key

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return key, fmt.Errorf("empty address")
	}

	var (
		ip    net.IP
		ipnet *net.IPNet
		err   error
	)
	if strings.Contains(raw, "/") {
		ip, ipnet, err = net.ParseCIDR(raw)
		if err != nil {
			return key, err
		}
		ip = ip.Mask(ipnet.Mask)
	} else {
		ip = net.ParseIP(raw)
		if ip == nil {
			return key, fmt.Errorf("invalid IP address")
		}
		ipnet = &net.IPNet{Mask: net.CIDRMask(32, 32)}
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return key, fmt.Errorf("IPv6 is not supported")
	}

	addr, err := convert.IPv4ToLPMTrieUint32(ip4)
	if err != nil {
		return key, err
	}
	prefixlen, _ := ipnet.Mask.Size()
	key.Prefixlen = uint32(prefixlen)
	key.Addr = addr

	return key, nil
}

func (k Key) String() string {
	return fmt.Sprintf("%s/%d", convert.BPFNetworkOrderToIPv4(k.Addr), k.Prefixlen)
}

func (k Key) bpfKey() bpf.PodEgressExternalAddressPoolsKey {
	return bpf.PodEgressExternalAddressPoolsKey{
		Prefixlen: k.Prefixlen,
		Addr:      k.Addr,
	}
}
