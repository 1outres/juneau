/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"net/netip"
	"testing"
)

func TestPodElasticIPRouteTable(t *testing.T) {
	accepts := []struct {
		name    string
		address netip.Addr
		want    int64
	}{
		{name: "reads the address as a big-endian number", address: netip.MustParseAddr("203.0.113.10"), want: 3405803786},
		{name: "keeps the top of the range", address: netip.MustParseAddr("255.255.255.255"), want: 4294967295},
		{name: "takes the first number above the reserved tables", address: netip.MustParseAddr("0.0.1.0"), want: 256},
	}
	for _, tc := range accepts {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PodElasticIPRouteTable(tc.address)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("PodElasticIPRouteTable(%s) = %d, want %d", tc.address, got, tc.want)
			}
		})
	}

	rejects := []struct {
		name    string
		address netip.Addr
	}{
		{name: "an unset address", address: netip.Addr{}},
		{name: "an IPv6 address", address: netip.MustParseAddr("2001:db8::10")},
		{name: "an IPv4-mapped IPv6 address", address: netip.MustParseAddr("::ffff:198.51.100.7")},
		{name: "the address that maps to the unspecified table", address: netip.MustParseAddr("0.0.0.0")},
		{name: "the address that maps to the main table", address: netip.MustParseAddr("0.0.0.254")},
		{name: "the address that maps to the local table", address: netip.MustParseAddr("0.0.0.255")},
	}
	for _, tc := range rejects {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			if _, err := PodElasticIPRouteTable(tc.address); err == nil {
				t.Fatalf("expected an error for %s", tc.address)
			}
		})
	}
}

func TestPodElasticIPRouteTablesDoNotCollide(t *testing.T) {
	first, err := PodElasticIPRouteTable(netip.MustParseAddr("203.0.113.10"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := PodElasticIPRouteTable(netip.MustParseAddr("203.0.113.11"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first == second {
		t.Fatalf("two addresses share table %d", first)
	}
}
