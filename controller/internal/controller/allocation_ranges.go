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
	"fmt"
	"net/netip"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// ipRange is an inclusive address interval. Both bounds belong to the same
// address family.
type ipRange struct {
	lo netip.Addr
	hi netip.Addr
}

func (r ipRange) contains(addr netip.Addr) bool {
	return r.lo.Compare(addr) <= 0 && r.hi.Compare(addr) >= 0
}

func (r ipRange) covers(other ipRange) bool {
	return r.contains(other.lo) && r.contains(other.hi)
}

// candidateRange is one entry of an AllocationPool candidate address space.
// span holds every address the entry owns, allocatable holds the subset that
// first-fit hands out. They differ for CIDR entries: automatic allocation
// leaves the network and broadcast addresses alone, yet a caller may still
// pin them through requestedIP because a routed pool prefix has no address
// that is reserved by the wire protocol.
type candidateRange struct {
	span        ipRange
	allocatable ipRange
}

// candidateRangeFromPrefix converts a CIDR entry. Host bits are masked off so
// that "192.0.2.5/24" and "192.0.2.0/24" describe the same space.
func candidateRangeFromPrefix(p netip.Prefix) candidateRange {
	p = p.Masked()
	span := ipRange{lo: p.Addr(), hi: lastAddrInPrefix(p)}
	if !prefixReservesEdges(p) {
		return candidateRange{span: span, allocatable: span}
	}
	return candidateRange{
		span:        span,
		allocatable: ipRange{lo: span.lo.Next(), hi: span.hi.Prev()},
	}
}

// candidateRangeFromBounds converts an explicit start-end entry. Every
// address between the bounds is allocatable.
func candidateRangeFromBounds(start, end netip.Addr) (candidateRange, error) {
	if !start.IsValid() || !end.IsValid() {
		return candidateRange{}, fmt.Errorf("range %v-%v has an invalid bound", start, end)
	}
	start, end = start.Unmap(), end.Unmap()
	if start.BitLen() != end.BitLen() {
		return candidateRange{}, fmt.Errorf("range %v-%v mixes address families", start, end)
	}
	if start.Compare(end) > 0 {
		return candidateRange{}, fmt.Errorf("range %v-%v starts after it ends", start, end)
	}
	span := ipRange{lo: start, hi: end}
	return candidateRange{span: span, allocatable: span}, nil
}

// prefixReservesEdges reports whether the network and broadcast addresses of p
// are excluded from automatic allocation. A /31 or /32 (and the IPv6 /127 and
// /128) has no room for them.
func prefixReservesEdges(p netip.Prefix) bool {
	switch p.Addr().BitLen() {
	case 32:
		return p.Bits() < 31
	case 128:
		return p.Bits() < 127
	}
	return false
}

// lastAddrInPrefix returns the broadcast (all-ones) address of the prefix.
func lastAddrInPrefix(p netip.Prefix) netip.Addr {
	addr := p.Masked().Addr()
	bits := p.Bits()
	bs := addr.As16()
	totalBits := addr.BitLen()
	hostBits := totalBits - bits
	for i := 15; hostBits > 0 && i >= 0; i-- {
		flip := hostBits
		if flip > 8 {
			flip = 8
		}
		bs[i] |= byte(1<<flip - 1)
		hostBits -= flip
	}
	if addr.Is4() {
		return netip.AddrFrom4([4]byte{bs[12], bs[13], bs[14], bs[15]})
	}
	return netip.AddrFrom16(bs)
}

// parsePrefixCandidates converts a list of CIDR strings.
func parsePrefixCandidates(raws []string) ([]candidateRange, error) {
	out := make([]candidateRange, 0, len(raws))
	for _, raw := range raws {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		out = append(out, candidateRangeFromPrefix(p))
	}
	return out, nil
}

// parseRangeCandidates converts a list of start-end entries.
func parseRangeCandidates(raws []juneauloutresmev1alpha1.AllocationPoolIPRange) ([]candidateRange, error) {
	out := make([]candidateRange, 0, len(raws))
	for _, raw := range raws {
		start, err := netip.ParseAddr(raw.Start)
		if err != nil {
			return nil, fmt.Errorf("invalid range start %q: %w", raw.Start, err)
		}
		end, err := netip.ParseAddr(raw.End)
		if err != nil {
			return nil, fmt.Errorf("invalid range end %q: %w", raw.End, err)
		}
		candidate, err := candidateRangeFromBounds(start, end)
		if err != nil {
			return nil, err
		}
		out = append(out, candidate)
	}
	return out, nil
}

// parsePoolCandidates converts the whole candidate address space of an
// ip-typed pool. CIDR entries come first so that adding ranges to an existing
// pool never reorders what first-fit hands out.
func parsePoolCandidates(spec *juneauloutresmev1alpha1.AllocationPoolIPSpec) ([]candidateRange, error) {
	prefixes, err := parsePrefixCandidates(spec.CIDRs)
	if err != nil {
		return nil, err
	}
	ranges, err := parseRangeCandidates(spec.Ranges)
	if err != nil {
		return nil, err
	}
	return append(prefixes, ranges...), nil
}

// intersectCandidates returns the filter entries whose span is fully covered
// by at least one candidate. Partially covered filter entries are dropped: a
// consumer must not allocate outside the pool it targets.
func intersectCandidates(candidates, filter []candidateRange) []candidateRange {
	out := make([]candidateRange, 0, len(filter))
	for _, f := range filter {
		for _, c := range candidates {
			if c.span.covers(f.span) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// candidatesContain reports whether addr belongs to the candidate space,
// including the addresses that first-fit keeps reserved.
func candidatesContain(candidates []candidateRange, addr netip.Addr) bool {
	for _, c := range candidates {
		if c.span.contains(addr) {
			return true
		}
	}
	return false
}

// firstFitCandidate returns the lowest address that no holder in used has
// taken, scanning the candidates in order.
func firstFitCandidate(candidates []candidateRange, used map[netip.Addr]string) (netip.Addr, bool) {
	for _, c := range candidates {
		for addr := c.allocatable.lo; ; addr = addr.Next() {
			if _, taken := used[addr]; !taken {
				return addr, true
			}
			if addr == c.allocatable.hi {
				break
			}
		}
	}
	return netip.Addr{}, false
}
