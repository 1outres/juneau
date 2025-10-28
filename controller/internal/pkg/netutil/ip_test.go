package netutil

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestOverlaps(t *testing.T) {
	tests := []struct {
		name    string
		subnets []string
		want    bool
		wantErr bool
	}{
		{
			name:    "no overlap - disjoint subnets",
			subnets: []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "overlap - one subnet contains another",
			subnets: []string{"10.0.0.0/16", "10.0.1.0/24"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "overlap - identical subnets",
			subnets: []string{"10.0.0.0/24", "10.0.0.0/24"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "overlap - partial overlap",
			subnets: []string{"192.168.0.0/23", "192.168.1.0/24"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "no overlap - adjacent subnets",
			subnets: []string{"192.168.0.0/24", "192.168.1.0/24"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "empty list",
			subnets: []string{},
			want:    false,
			wantErr: false,
		},
		{
			name:    "single subnet",
			subnets: []string{"10.0.0.0/24"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "invalid CIDR",
			subnets: []string{"10.0.0.0/24", "invalid"},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Overlaps(tt.subnets)
			if (err != nil) != tt.wantErr {
				t.Errorf("Overlaps() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Overlaps() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestV4CapacityHosts(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		want    uint64
		wantErr bool
	}{
		{
			name:    "/24 subnet",
			cidr:    "192.168.1.0/24",
			want:    254, // 2^8 - 2
			wantErr: false,
		},
		{
			name:    "/16 subnet",
			cidr:    "10.0.0.0/16",
			want:    65534, // 2^16 - 2
			wantErr: false,
		},
		{
			name:    "/28 subnet",
			cidr:    "192.168.1.0/28",
			want:    14, // 2^4 - 2
			wantErr: false,
		},
		{
			name:    "/30 subnet - minimal",
			cidr:    "192.168.1.0/30",
			want:    2, // 2^2 - 2
			wantErr: false,
		},
		{
			name:    "/31 subnet - no usable hosts",
			cidr:    "192.168.1.0/31",
			want:    0,
			wantErr: false,
		},
		{
			name:    "/32 subnet - single host",
			cidr:    "192.168.1.1/32",
			want:    0,
			wantErr: false,
		},
		{
			name:    "subnet larger than /16 - error",
			cidr:    "10.0.0.0/15",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			cidr:    "invalid",
			want:    0,
			wantErr: true,
		},
		{
			name:    "IPv6 CIDR - error",
			cidr:    "2001:db8::/64",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := V4CapacityHosts(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("V4CapacityHosts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("V4CapacityHosts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNthIPv4InSubnet(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		n       uint32
		want    string
		wantErr bool
	}{
		{
			name:    "first IP (n=1) in /24",
			cidr:    "192.168.1.0/24",
			n:       1,
			want:    "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "fifth IP (n=5) in /24",
			cidr:    "192.168.1.0/24",
			n:       5,
			want:    "192.168.1.5",
			wantErr: false,
		},
		{
			name:    "last usable IP in /24",
			cidr:    "192.168.1.0/24",
			n:       254,
			want:    "192.168.1.254",
			wantErr: false,
		},
		{
			name:    "n=0 - error",
			cidr:    "192.168.1.0/24",
			n:       0,
			want:    "",
			wantErr: true,
		},
		{
			name:    "n out of range - too large",
			cidr:    "192.168.1.0/24",
			n:       255,
			want:    "",
			wantErr: true,
		},
		{
			name:    "first IP in /28",
			cidr:    "192.168.1.0/28",
			n:       1,
			want:    "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "invalid CIDR",
			cidr:    "invalid",
			n:       1,
			want:    "",
			wantErr: true,
		},
		{
			name:    "subnet larger than /16",
			cidr:    "10.0.0.0/15",
			n:       1,
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NthIPv4InSubnet(tt.cidr, tt.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("NthIPv4InSubnet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.String() != tt.want {
				t.Errorf("NthIPv4InSubnet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNextUsableIPv4InSubnet(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		current   string
		wantIP    string
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "next IP in middle of range",
			cidr:      "192.168.1.0/24",
			current:   "192.168.1.10",
			wantIP:    "192.168.1.11",
			wantFound: true,
			wantErr:   false,
		},
		{
			name:      "last usable IP - no next",
			cidr:      "192.168.1.0/24",
			current:   "192.168.1.254",
			wantIP:    "",
			wantFound: false,
			wantErr:   false,
		},
		{
			name:      "before first usable - returns first",
			cidr:      "192.168.1.0/24",
			current:   "192.168.1.0",
			wantIP:    "192.168.1.1",
			wantFound: true,
			wantErr:   false,
		},
		{
			name:      "broadcast address - error",
			cidr:      "192.168.1.0/24",
			current:   "192.168.1.255",
			wantIP:    "",
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "IP outside subnet - error",
			cidr:      "192.168.1.0/24",
			current:   "192.168.2.10",
			wantIP:    "",
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "invalid CIDR",
			cidr:      "invalid",
			current:   "192.168.1.10",
			wantIP:    "",
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "IPv6 - error",
			cidr:      "2001:db8::/64",
			current:   "2001:db8::1",
			wantIP:    "",
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "/30 subnet - edge case",
			cidr:      "192.168.1.0/30",
			current:   "192.168.1.1",
			wantIP:    "192.168.1.2",
			wantFound: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := net.ParseIP(tt.current)
			got, found, err := NextUsableIPv4InSubnet(tt.cidr, current)
			if (err != nil) != tt.wantErr {
				t.Errorf("NextUsableIPv4InSubnet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if found != tt.wantFound {
				t.Errorf("NextUsableIPv4InSubnet() found = %v, want %v", found, tt.wantFound)
				return
			}
			if tt.wantFound && got.String() != tt.wantIP {
				t.Errorf("NextUsableIPv4InSubnet() = %v, want %v", got, tt.wantIP)
			}
		})
	}
}

func TestRandomUsableIPv4InSubnet(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{
			name:    "/24 subnet",
			cidr:    "192.168.1.0/24",
			wantErr: false,
		},
		{
			name:    "/28 subnet",
			cidr:    "192.168.1.0/28",
			wantErr: false,
		},
		{
			name:    "/30 subnet - minimal",
			cidr:    "192.168.1.0/30",
			wantErr: false,
		},
		{
			name:    "/31 subnet - no usable hosts",
			cidr:    "192.168.1.0/31",
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			cidr:    "invalid",
			wantErr: true,
		},
		{
			name:    "subnet larger than /16",
			cidr:    "10.0.0.0/15",
			wantErr: true,
		},
		{
			name:    "IPv6 - error",
			cidr:    "2001:db8::/64",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RandomUsableIPv4InSubnet(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("RandomUsableIPv4InSubnet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify the returned IP is valid and within range
				_, ipnet, _ := net.ParseCIDR(tt.cidr)
				if !ipnet.Contains(got) {
					t.Errorf("RandomUsableIPv4InSubnet() returned IP %v not in subnet %v", got, tt.cidr)
				}
				// Verify it's not network or broadcast address
				network := ipnet.IP.Mask(ipnet.Mask)
				ones, _ := ipnet.Mask.Size()
				size := uint32(1) << (32 - ones)
				broadcast := make(net.IP, 4)
				binary.BigEndian.PutUint32(broadcast, beToUint32(network)+size-1)

				if got.Equal(network) {
					t.Errorf("RandomUsableIPv4InSubnet() returned network address")
				}
				if got.Equal(broadcast) {
					t.Errorf("RandomUsableIPv4InSubnet() returned broadcast address")
				}
			}
		})
	}
}

func TestBeToUint32(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want uint32
	}{
		{
			name: "192.168.1.1",
			ip:   "192.168.1.1",
			want: 3232235777, // 192*256^3 + 168*256^2 + 1*256 + 1
		},
		{
			name: "10.0.0.1",
			ip:   "10.0.0.1",
			want: 167772161, // 10*256^3 + 0*256^2 + 0*256 + 1
		},
		{
			name: "255.255.255.255",
			ip:   "255.255.255.255",
			want: 4294967295,
		},
		{
			name: "0.0.0.0",
			ip:   "0.0.0.0",
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := beToUint32(ip); got != tt.want {
				t.Errorf("beToUint32() = %v, want %v", got, tt.want)
			}
		})
	}
}
