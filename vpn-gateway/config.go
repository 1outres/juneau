package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	interfaceID  = 42
	birdProtocol = "juneau_bgp"
)

var ikeIDPattern = regexp.MustCompile(`^[A-Za-z0-9@_.:-]+$`)

type Config struct {
	PublicIP         string
	LocalTunnelIP    string
	RemoteTunnelIP   string
	LocalASN         uint32
	RemoteASN        uint32
	PeerIKEID        string
	PSK              []byte
	RemoteRoutes     []string
	AdvertisedRoutes []string
}

func loadEnv() (Config, error) {
	var c Config
	c.PublicIP = os.Getenv("PUBLIC_IP")
	c.LocalTunnelIP = os.Getenv("LOCAL_TUNNEL_IP")
	c.RemoteTunnelIP = os.Getenv("REMOTE_TUNNEL_IP")
	c.PeerIKEID = os.Getenv("PEER_IKE_ID")
	var err error
	c.LocalASN, err = parseASN(os.Getenv("LOCAL_ASN"))
	if err != nil {
		return c, fmt.Errorf("LOCAL_ASN: %w", err)
	}
	c.RemoteASN, err = parseASN(os.Getenv("REMOTE_ASN"))
	if err != nil {
		return c, fmt.Errorf("REMOTE_ASN: %w", err)
	}
	pskPath := os.Getenv("VPN_PSK_FILE")
	if pskPath == "" {
		return c, errors.New("VPN_PSK_FILE is required")
	}
	c.PSK, err = os.ReadFile(pskPath)
	if err != nil {
		return c, fmt.Errorf("read PSK: %w", err)
	}
	if err = json.Unmarshal([]byte(os.Getenv("VPN_REMOTE_ROUTES")), &c.RemoteRoutes); err != nil {
		return c, fmt.Errorf("VPN_REMOTE_ROUTES: %w", err)
	}
	if err = json.Unmarshal([]byte(os.Getenv("VPN_ADVERTISED_ROUTES")), &c.AdvertisedRoutes); err != nil {
		return c, fmt.Errorf("VPN_ADVERTISED_ROUTES: %w", err)
	}
	if c.RemoteRoutes == nil || c.AdvertisedRoutes == nil {
		return c, errors.New("route lists must be JSON arrays")
	}
	return c, c.Validate()
}

func parseASN(raw string) (uint32, error) {
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid ASN %q", raw)
	}
	return uint32(n), nil
}

func ipv4(raw string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 address %q", raw)
	}
	return ip, nil
}

func parsePrefixes(values []string, allowDefault bool) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || !allowDefault && prefix.Bits() == 0 {
			return nil, fmt.Errorf("invalid IPv4 prefix %q", raw)
		}
		for _, prev := range prefixes {
			if prev == prefix || (prev.Overlaps(prefix) && (!allowDefault || prev.Bits() != 0 && prefix.Bits() != 0)) {
				return nil, fmt.Errorf("overlapping prefixes %s and %s", prev, prefix)
			}
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func (c Config) Validate() error {
	public, err := ipv4(c.PublicIP)
	if err != nil {
		return err
	}
	local, err := ipv4(c.LocalTunnelIP)
	if err != nil {
		return err
	}
	remote, err := ipv4(c.RemoteTunnelIP)
	if err != nil {
		return err
	}
	if local == remote || local == public || remote == public {
		return errors.New("tunnel and public addresses must differ")
	}
	if c.LocalASN == 0 || c.RemoteASN == 0 || c.LocalASN == c.RemoteASN {
		return errors.New("local and remote ASN must be nonzero and different")
	}
	if !ikeIDPattern.MatchString(c.PeerIKEID) {
		return errors.New("peer IKE ID has invalid characters")
	}
	if len(c.PSK) == 0 {
		return errors.New("PSK is empty")
	}
	remotes, err := parsePrefixes(c.RemoteRoutes, true)
	if err != nil {
		return fmt.Errorf("remote routes: %w", err)
	}
	advertised, err := parsePrefixes(c.AdvertisedRoutes, false)
	if err != nil {
		return fmt.Errorf("advertised routes: %w", err)
	}
	for _, a := range advertised {
		for _, r := range remotes {
			if r.Bits() != 0 && a.Overlaps(r) {
				return fmt.Errorf("advertised route %s overlaps remote route %s", a, r)
			}
		}
	}
	return nil
}

func renderSwanctl(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`connections {
  juneau {
    version = 2
    local_addrs = %s
    remote_addrs = %%any
    proposals = aes256gcm16-prfsha384-ecp384
    encap = yes
    mobike = no
    dpd_delay = 30s
    reauth_time = 0
    local {
      auth = psk
      id = %s
    }
    remote {
      auth = psk
      id = %s
    }
    children {
      juneau {
        local_ts = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        mode = tunnel
        if_id_in = %d
        if_id_out = %d
        esp_proposals = aes256gcm16-ecp384
        start_action = none
        close_action = none
        dpd_action = clear
      }
    }
  }
}
secrets {
  ike-juneau {
    id-local = %s
    id-remote = %s
    secret = 0x%s
  }
}
`, c.PublicIP, c.PublicIP, c.PeerIKEID, interfaceID, interfaceID, c.PublicIP, c.PeerIKEID, hex.EncodeToString(c.PSK)), nil
}

func renderBird(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	routes := slices.Clone(c.AdvertisedRoutes)
	slices.Sort(routes)
	var b strings.Builder
	fmt.Fprintf(&b, "router id %s;\nprotocol device {}\nprotocol kernel { ipv4 { import none; export none; }; }\nprotocol static advertised {\n  ipv4;\n", c.LocalTunnelIP)
	for _, route := range routes {
		fmt.Fprintf(&b, "  route %s blackhole;\n", route)
	}
	fmt.Fprintf(&b, `}
protocol bgp %s {
  local as %d;
  neighbor %s as %d;
  source address %s;
  multihop;
  ipv4 {
    import none;
    export filter {
      if proto = "advertised" then accept;
      reject;
    };
  };
}
`, birdProtocol, c.LocalASN, c.RemoteTunnelIP, c.RemoteASN, c.LocalTunnelIP)
	return b.String(), nil
}
