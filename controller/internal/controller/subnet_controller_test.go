/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"net"
	"net/netip"
	"testing"
)

func TestNextGateway(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{
		{"10.0.0.0/24", "10.0.0.1"},
		{"10.10.20.0/24", "10.10.20.1"},
		{"192.168.4.0/22", "192.168.4.1"},
		{"172.16.0.0/12", "172.16.0.1"},
		{"10.0.0.0/30", "10.0.0.1"},
	}
	for _, tc := range tests {
		_, ipnet, err := net.ParseCIDR(tc.cidr)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.cidr, err)
		}
		if got := nextGateway(ipnet); got != tc.want {
			t.Errorf("nextGateway(%q) = %q, want %q", tc.cidr, got, tc.want)
		}
	}
}

func TestNextDNSAddress(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{
		// Typical sizes: gw=.1, dns=.2 always falls inside the usable range.
		{"10.0.0.0/24", "10.0.0.2"},
		{"10.10.20.0/24", "10.10.20.2"},
		{"192.168.4.0/22", "192.168.4.2"},
		{"172.16.0.0/12", "172.16.0.2"},
		// /29 is the smallest prefix where .2 is still usable.
		{"10.0.0.0/29", "10.0.0.2"},
		// /30 has only .0 (network), .1 (gw), .2 (dns), .3 (broadcast).
		// The IP allocator treats .3 as the broadcast and skips it; .2
		// remains usable but the resulting Pod pool is empty. We still
		// expose it so the daemon has somewhere to bind DNS.
		{"10.0.0.0/30", "10.0.0.2"},
		// /31 (RFC 3021 point-to-point): two addresses, both endpoints,
		// no room for .2 → no DNS.
		{"10.0.0.0/31", ""},
		// /32 host route: nothing usable beyond the host itself.
		{"10.0.0.0/32", ""},
	}
	for _, tc := range tests {
		_, ipnet, err := net.ParseCIDR(tc.cidr)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.cidr, err)
		}
		if got := nextDNSAddress(ipnet); got != tc.want {
			t.Errorf("nextDNSAddress(%q) = %q, want %q", tc.cidr, got, tc.want)
		}
	}
}

func TestComputeSubnetExcluded(t *testing.T) {
	type tcase struct {
		cidr     string
		gateway  string
		dns      string
		want     []string
		describe string
	}

	tests := []tcase{
		{
			describe: "/24 reserves .1 .2 .3",
			cidr:     "10.0.0.0/24",
			gateway:  "10.0.0.1",
			dns:      "10.0.0.2",
			want:     []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			describe: "empty DNS still reserves .1 and .3 placeholder",
			cidr:     "10.0.0.0/24",
			gateway:  "10.0.0.1",
			dns:      "",
			want:     []string{"10.0.0.1", "10.0.0.3"},
		},
		{
			describe: "/29 has room for .1 .2 .3",
			cidr:     "10.0.0.0/29",
			gateway:  "10.0.0.1",
			dns:      "10.0.0.2",
			want:     []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			describe: "/30 .3 is broadcast and gets dropped",
			cidr:     "10.0.0.0/30",
			gateway:  "10.0.0.1",
			dns:      "10.0.0.2",
			want:     []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			describe: "/31 has no DNS and no .3",
			cidr:     "10.0.0.0/31",
			gateway:  "10.0.0.1",
			dns:      "",
			want:     []string{"10.0.0.1"},
		},
		{
			describe: "duplicate gateway / dns inputs are deduped",
			cidr:     "10.0.0.0/24",
			gateway:  "10.0.0.2",
			dns:      "10.0.0.2",
			want:     []string{"10.0.0.2", "10.0.0.3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.describe, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tc.cidr)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.cidr, err)
			}
			got := computeSubnetExcluded(prefix.Masked(), tc.gateway, tc.dns)
			if !equalStringSlices(got, tc.want) {
				t.Errorf("computeSubnetExcluded(%q, %q, %q) = %v, want %v", tc.cidr, tc.gateway, tc.dns, got, tc.want)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNewLAA(t *testing.T) {
	mac, err := newLAA()
	if err != nil {
		t.Fatalf("newLAA: %v", err)
	}
	if len(mac) != 6 {
		t.Fatalf("newLAA returned %d bytes, want 6", len(mac))
	}
	// I/G must be 0 (unicast), U/L must be 1 (locally administered).
	if mac[0]&0x01 != 0 {
		t.Errorf("newLAA returned multicast MAC %s (I/G bit set)", mac)
	}
	if mac[0]&0x02 == 0 {
		t.Errorf("newLAA returned non-LAA MAC %s (U/L bit clear)", mac)
	}
}
