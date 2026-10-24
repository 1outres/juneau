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

package controller

import (
	"math"
	"net/netip"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func usedSet(addrs ...string) map[netip.Addr]string {
	used := make(map[netip.Addr]string, len(addrs))
	for _, a := range addrs {
		used[netip.MustParseAddr(a)] = "holder"
	}
	return used
}

func TestCountPoolAddresses(t *testing.T) {
	tests := []struct {
		name string
		spec juneauv1alpha1.AllocationPoolIPSpec
		used map[netip.Addr]string
		want poolAddressCounts
	}{
		{
			name: "cidr skips network and broadcast",
			spec: juneauv1alpha1.AllocationPoolIPSpec{CIDRs: []string{"192.0.2.0/29"}},
			want: poolAddressCounts{total: 6, allocated: 0, available: 6},
		},
		{
			name: "cidr /31 and /32 keep every address",
			spec: juneauv1alpha1.AllocationPoolIPSpec{CIDRs: []string{"192.0.2.0/31", "192.0.2.8/32"}},
			want: poolAddressCounts{total: 3, allocated: 0, available: 3},
		},
		{
			name: "range keeps both bounds",
			spec: juneauv1alpha1.AllocationPoolIPSpec{Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "203.0.113.10", End: "203.0.113.20"}}},
			used: usedSet("203.0.113.10", "203.0.113.20"),
			want: poolAddressCounts{total: 11, allocated: 2, available: 9},
		},
		{
			name: "overlapping entries are counted once",
			spec: juneauv1alpha1.AllocationPoolIPSpec{
				CIDRs:  []string{"192.0.2.0/29"},
				Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "192.0.2.4", End: "192.0.2.10"}},
			},
			want: poolAddressCounts{total: 10, allocated: 0, available: 10},
		},
		{
			name: "excluded addresses leave the total",
			spec: juneauv1alpha1.AllocationPoolIPSpec{
				CIDRs:    []string{"192.0.2.0/29"},
				Excluded: []string{"192.0.2.1", "192.0.2.1", "192.0.2.0", "198.51.100.1"},
			},
			used: usedSet("192.0.2.1", "192.0.2.2"),
			want: poolAddressCounts{total: 5, allocated: 1, available: 4},
		},
		{
			name: "used addresses outside the allocatable space are ignored",
			spec: juneauv1alpha1.AllocationPoolIPSpec{CIDRs: []string{"192.0.2.0/29"}},
			used: usedSet("192.0.2.0", "192.0.2.7", "192.0.2.3", "10.0.0.1"),
			want: poolAddressCounts{total: 6, allocated: 1, available: 5},
		},
		{
			name: "huge ipv6 pool saturates",
			spec: juneauv1alpha1.AllocationPoolIPSpec{CIDRs: []string{"2001:db8::/32"}},
			used: usedSet("2001:db8::5"),
			want: poolAddressCounts{total: math.MaxInt64, allocated: 1, available: math.MaxInt64},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := countPoolAddresses(&tt.spec, tt.used)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCountPoolAddressesRejectsInvalidSpec(t *testing.T) {
	spec := juneauv1alpha1.AllocationPoolIPSpec{CIDRs: []string{"not-a-cidr"}}
	if _, err := countPoolAddresses(&spec, nil); err == nil {
		t.Fatal("expected an error")
	}
}
