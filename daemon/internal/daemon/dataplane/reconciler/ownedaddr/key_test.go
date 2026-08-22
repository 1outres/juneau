package ownedaddr

import (
	"encoding/binary"
	"net"
	"testing"
)

func lpmUint32(t *testing.T, ip string) uint32 {
	t.Helper()
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		t.Fatalf("invalid test IP %q", ip)
	}
	return binary.LittleEndian.Uint32(parsed)
}

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantAddr   uint32
		wantPrefix uint32
		wantString string
		wantErr    bool
	}{
		{
			name:       "plain IPv4 becomes /32",
			raw:        "10.1.2.3",
			wantAddr:   lpmUint32(t, "10.1.2.3"),
			wantPrefix: 32,
			wantString: "10.1.2.3/32",
		},
		{
			name:       "CIDR is canonicalized to network address",
			raw:        "10.1.2.3/24",
			wantAddr:   lpmUint32(t, "10.1.2.0"),
			wantPrefix: 24,
			wantString: "10.1.2.0/24",
		},
		{
			name:       "whitespace is trimmed",
			raw:        "  10.1.2.3/24  ",
			wantAddr:   lpmUint32(t, "10.1.2.0"),
			wantPrefix: 24,
			wantString: "10.1.2.0/24",
		},
		{
			name:    "empty string is rejected",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "invalid IP is rejected",
			raw:     "not-an-ip",
			wantErr: true,
		},
		{
			name:    "malformed CIDR is rejected",
			raw:     "10.1.2.3/40",
			wantErr: true,
		},
		{
			name:    "IPv6 plain address is rejected",
			raw:     "fe80::1",
			wantErr: true,
		},
		{
			name:    "IPv6 CIDR is rejected",
			raw:     "fe80::/64",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePrefix(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got none (key=%+v)", key)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := key.String(); got != tt.wantString {
				t.Errorf("key.String() = %q, want %q", got, tt.wantString)
			}
			if key.Addr != tt.wantAddr {
				t.Errorf("key.Addr = %#x, want %#x", key.Addr, tt.wantAddr)
			}
			if key.Prefixlen != tt.wantPrefix {
				t.Errorf("key.Prefixlen = %d, want %d", key.Prefixlen, tt.wantPrefix)
			}
		})
	}
}

func TestParsePrefixIsIdempotentOverItsOwnOutput(t *testing.T) {
	first, err := ParsePrefix("10.1.2.3/24")
	if err != nil {
		t.Fatalf("ParsePrefix: %v", err)
	}
	second, err := ParsePrefix(first.String())
	if err != nil {
		t.Fatalf("ParsePrefix of %q: %v", first.String(), err)
	}
	if first != second {
		t.Errorf("reparsed key = %+v, want %+v", second, first)
	}
}
