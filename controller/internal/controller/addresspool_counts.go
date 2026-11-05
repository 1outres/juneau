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
	"math/big"
	"net/netip"
	"sort"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// poolAddressCounts is the number of addresses first-fit can hand out from a
// pool, split by whether they are taken. total == allocated + available unless
// a cap applies (see countPoolAddresses).
type poolAddressCounts struct {
	total     int64
	allocated int64
	available int64
}

// countPoolAddresses counts the addresses of an ip-typed pool with the same
// rules allocateIP applies: only allocatable addresses count, overlapping
// entries are merged and excluded addresses are removed. used holds the
// addresses taken by claims and leases; entries outside the allocatable space
// or in the excluded list are ignored because first-fit never hands them out
// anyway. A count that does not fit in int64 (a large IPv6 prefix) is capped
// at math.MaxInt64.
func countPoolAddresses(spec *juneauv1alpha1.AllocationPoolIPSpec, used map[netip.Addr]string) (poolAddressCounts, error) {
	candidates, err := parsePoolCandidates(spec)
	if err != nil {
		return poolAddressCounts{}, err
	}
	space := mergeRanges(candidates)

	excluded := make(map[netip.Addr]struct{}, len(spec.Excluded))
	for _, raw := range spec.Excluded {
		if addr, err := netip.ParseAddr(raw); err == nil && rangesContain(space, addr) {
			excluded[addr] = struct{}{}
		}
	}

	allocated := 0
	for addr := range used {
		if _, skip := excluded[addr]; skip {
			continue
		}
		if rangesContain(space, addr) {
			allocated++
		}
	}

	total := new(big.Int)
	for _, r := range space {
		total.Add(total, r.size())
	}
	total.Sub(total, big.NewInt(int64(len(excluded))))

	totalCapped := capInt64(total)
	allocatedCapped := int64(allocated)
	available := capInt64(new(big.Int).Sub(total, big.NewInt(allocatedCapped)))
	return poolAddressCounts{total: totalCapped, allocated: allocatedCapped, available: available}, nil
}

// mergeRanges returns the sorted, non-overlapping allocatable intervals of the
// candidates.
func mergeRanges(candidates []candidateRange) []ipRange {
	ranges := make([]ipRange, 0, len(candidates))
	for _, c := range candidates {
		ranges = append(ranges, c.allocatable)
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo.Compare(ranges[j].lo) < 0 })

	merged := make([]ipRange, 0, len(ranges))
	for _, r := range ranges {
		if last := len(merged) - 1; last >= 0 && r.lo.Compare(merged[last].hi) <= 0 {
			if r.hi.Compare(merged[last].hi) > 0 {
				merged[last].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

func rangesContain(ranges []ipRange, addr netip.Addr) bool {
	for _, r := range ranges {
		if r.contains(addr) {
			return true
		}
	}
	return false
}

// size returns the number of addresses in the interval, both bounds included.
func (r ipRange) size() *big.Int {
	lo, hi := r.lo.As16(), r.hi.As16()
	diff := new(big.Int).Sub(new(big.Int).SetBytes(hi[:]), new(big.Int).SetBytes(lo[:]))
	return diff.Add(diff, big.NewInt(1))
}

func capInt64(v *big.Int) int64 {
	if !v.IsInt64() {
		return math.MaxInt64
	}
	return v.Int64()
}
