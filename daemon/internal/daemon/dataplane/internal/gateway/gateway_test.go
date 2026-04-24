package gateway

import (
	"net"
	"testing"
)

func TestIsDefaultDst(t *testing.T) {
	tests := []struct {
		name string
		dst  *net.IPNet
		want bool
	}{
		{"nil", nil, false},
		{"0.0.0.0/0", &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, true},
		{"10.0.0.0/8", &net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)}, false},
		{"0.0.0.0/32", &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(32, 32)}, false},
		{"::/0", &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDefaultDst(tc.dst); got != tc.want {
				t.Errorf("isDefaultDst(%v) = %v, want %v", tc.dst, got, tc.want)
			}
		})
	}
}
