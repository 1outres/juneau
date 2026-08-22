package controller

import (
	"net/netip"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// legacyFirstUsableAddr, legacyIsUsableInPrefix and legacyLastAddrInPrefix are
// verbatim copies of the pre-range implementation. They act as the oracle for
// the CIDR to range conversion so that a rewrite of the production helpers
// cannot silently change which addresses a CIDR pool hands out.
func legacyFirstUsableAddr(p netip.Prefix) netip.Addr {
	bits := p.Bits()
	switch p.Addr().BitLen() {
	case 32:
		if bits >= 31 {
			return p.Addr()
		}
	case 128:
		if bits >= 127 {
			return p.Addr()
		}
	}
	return p.Addr().Next()
}

func legacyIsUsableInPrefix(addr netip.Addr, p netip.Prefix) bool {
	bits := p.Bits()
	switch addr.BitLen() {
	case 32:
		if bits >= 31 {
			return true
		}
		return addr != legacyLastAddrInPrefix(p)
	case 128:
		if bits >= 127 {
			return true
		}
		return addr != legacyLastAddrInPrefix(p)
	}
	return true
}

func legacyLastAddrInPrefix(p netip.Prefix) netip.Addr {
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

func legacyUsableAddrs(p netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for addr := legacyFirstUsableAddr(p); p.Contains(addr); addr = addr.Next() {
		if !legacyIsUsableInPrefix(addr, p) {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func allocatableAddrs(c candidateRange) []netip.Addr {
	var out []netip.Addr
	for addr := c.allocatable.lo; ; addr = addr.Next() {
		out = append(out, addr)
		if addr == c.allocatable.hi {
			return out
		}
	}
}

func addrsEqual(a, b []netip.Addr) bool {
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

func TestCandidateRangeFromPrefixMatchesLegacyIteration(t *testing.T) {
	prefixes := []string{
		"192.0.2.0/24",
		"192.0.2.0/25",
		"198.51.100.128/26",
		"10.0.0.0/28",
		"192.0.2.0/29",
		"192.0.2.0/30",
		"192.0.2.0/31",
		"192.0.2.5/32",
		"2001:db8::/120",
		"2001:db8::/126",
		"2001:db8::/127",
		"2001:db8::1/128",
	}
	for _, raw := range prefixes {
		t.Run(raw, func(t *testing.T) {
			p := netip.MustParsePrefix(raw).Masked()
			want := legacyUsableAddrs(p)
			got := allocatableAddrs(candidateRangeFromPrefix(p))
			if !addrsEqual(got, want) {
				t.Fatalf("iteration mismatch for %s:\n got %v\nwant %v", raw, got, want)
			}
		})
	}
}

func TestCandidateRangeFromPrefixBounds(t *testing.T) {
	tests := []struct {
		prefix           string
		spanLo, spanHi   string
		allocLo, allocHi string
	}{
		{"10.0.0.0/8", "10.0.0.0", "10.255.255.255", "10.0.0.1", "10.255.255.254"},
		{"192.0.2.0/24", "192.0.2.0", "192.0.2.255", "192.0.2.1", "192.0.2.254"},
		{"192.0.2.0/30", "192.0.2.0", "192.0.2.3", "192.0.2.1", "192.0.2.2"},
		{"192.0.2.0/31", "192.0.2.0", "192.0.2.1", "192.0.2.0", "192.0.2.1"},
		{"192.0.2.5/32", "192.0.2.5", "192.0.2.5", "192.0.2.5", "192.0.2.5"},
		{"2001:db8::/126", "2001:db8::", "2001:db8::3", "2001:db8::1", "2001:db8::2"},
		{"2001:db8::/127", "2001:db8::", "2001:db8::1", "2001:db8::", "2001:db8::1"},
		{"2001:db8::1/128", "2001:db8::1", "2001:db8::1", "2001:db8::1", "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			c := candidateRangeFromPrefix(netip.MustParsePrefix(tt.prefix))
			if c.span.lo != netip.MustParseAddr(tt.spanLo) || c.span.hi != netip.MustParseAddr(tt.spanHi) {
				t.Errorf("span = %v-%v, want %s-%s", c.span.lo, c.span.hi, tt.spanLo, tt.spanHi)
			}
			if c.allocatable.lo != netip.MustParseAddr(tt.allocLo) || c.allocatable.hi != netip.MustParseAddr(tt.allocHi) {
				t.Errorf("allocatable = %v-%v, want %s-%s", c.allocatable.lo, c.allocatable.hi, tt.allocLo, tt.allocHi)
			}
		})
	}
}

func TestCandidateRangeFromPrefixMasksHostBits(t *testing.T) {
	c := candidateRangeFromPrefix(netip.MustParsePrefix("192.0.2.77/24"))
	if c.span.lo != netip.MustParseAddr("192.0.2.0") || c.span.hi != netip.MustParseAddr("192.0.2.255") {
		t.Fatalf("span = %v-%v, want 192.0.2.0-192.0.2.255", c.span.lo, c.span.hi)
	}
}

func TestParsePoolCandidatesKeepsCIDRsBeforeRanges(t *testing.T) {
	candidates, err := parsePoolCandidates(&juneauv1alpha1.AllocationPoolIPSpec{
		CIDRs: []string{"192.0.2.0/30", "198.51.100.0/30"},
		Ranges: []juneauv1alpha1.AllocationPoolIPRange{
			{Start: "203.0.113.10", End: "203.0.113.12"},
		},
	})
	if err != nil {
		t.Fatalf("parsePoolCandidates: %v", err)
	}
	if len(candidates) != 3 {
		t.Fatalf("len(candidates) = %d, want 3", len(candidates))
	}
	wantLo := []string{"192.0.2.1", "198.51.100.1", "203.0.113.10"}
	for i, want := range wantLo {
		if candidates[i].allocatable.lo != netip.MustParseAddr(want) {
			t.Errorf("candidates[%d].allocatable.lo = %v, want %s", i, candidates[i].allocatable.lo, want)
		}
	}
}

func TestParsePoolCandidatesSingleAddressRange(t *testing.T) {
	candidates, err := parsePoolCandidates(&juneauv1alpha1.AllocationPoolIPSpec{
		Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "192.0.2.9", End: "192.0.2.9"}},
	})
	if err != nil {
		t.Fatalf("parsePoolCandidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("len(candidates) = %d, want 1", len(candidates))
	}
	got := allocatableAddrs(candidates[0])
	if len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("allocatable = %v, want [192.0.2.9]", got)
	}
}

func TestParsePoolCandidatesRangeKeepsEveryAddress(t *testing.T) {
	candidates, err := parsePoolCandidates(&juneauv1alpha1.AllocationPoolIPSpec{
		Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "192.0.2.0", End: "192.0.2.3"}},
	})
	if err != nil {
		t.Fatalf("parsePoolCandidates: %v", err)
	}
	got := allocatableAddrs(candidates[0])
	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.0"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
	}
	if !addrsEqual(got, want) {
		t.Fatalf("allocatable = %v, want %v", got, want)
	}
}

func TestParsePoolCandidatesRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		spec juneauv1alpha1.AllocationPoolIPSpec
	}{
		{"invalid cidr", juneauv1alpha1.AllocationPoolIPSpec{CIDRs: []string{"192.0.2.0"}}},
		{"start after end", juneauv1alpha1.AllocationPoolIPSpec{
			Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "192.0.2.20", End: "192.0.2.10"}},
		}},
		{"invalid start", juneauv1alpha1.AllocationPoolIPSpec{
			Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "not-an-ip", End: "192.0.2.10"}},
		}},
		{"invalid end", juneauv1alpha1.AllocationPoolIPSpec{
			Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "192.0.2.10", End: ""}},
		}},
		{"mixed families", juneauv1alpha1.AllocationPoolIPSpec{
			Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "192.0.2.10", End: "2001:db8::1"}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePoolCandidates(&tt.spec); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestFirstFitCandidateScansInOrder(t *testing.T) {
	candidates, err := parsePoolCandidates(&juneauv1alpha1.AllocationPoolIPSpec{
		CIDRs: []string{"192.0.2.0/30"},
		Ranges: []juneauv1alpha1.AllocationPoolIPRange{
			{Start: "203.0.113.10", End: "203.0.113.11"},
			{Start: "203.0.113.40", End: "203.0.113.40"},
		},
	})
	if err != nil {
		t.Fatalf("parsePoolCandidates: %v", err)
	}

	used := map[netip.Addr]string{}
	want := []string{"192.0.2.1", "192.0.2.2", "203.0.113.10", "203.0.113.11", "203.0.113.40"}
	for _, expected := range want {
		addr, ok := firstFitCandidate(candidates, used)
		if !ok {
			t.Fatalf("firstFitCandidate returned no address, want %s", expected)
		}
		if addr != netip.MustParseAddr(expected) {
			t.Fatalf("firstFitCandidate = %v, want %s", addr, expected)
		}
		used[addr] = "holder"
	}
	if _, ok := firstFitCandidate(candidates, used); ok {
		t.Fatal("expected the candidate space to be exhausted")
	}
}

func TestFirstFitCandidateSkipsUsedAddresses(t *testing.T) {
	candidates, err := parsePoolCandidates(&juneauv1alpha1.AllocationPoolIPSpec{
		Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "192.0.2.10", End: "192.0.2.13"}},
	})
	if err != nil {
		t.Fatalf("parsePoolCandidates: %v", err)
	}
	used := map[netip.Addr]string{
		netip.MustParseAddr("192.0.2.10"): "excluded",
		netip.MustParseAddr("192.0.2.11"): "claim-a",
	}
	addr, ok := firstFitCandidate(candidates, used)
	if !ok || addr != netip.MustParseAddr("192.0.2.12") {
		t.Fatalf("firstFitCandidate = %v (ok=%v), want 192.0.2.12", addr, ok)
	}
}

func TestFirstFitCandidateStopsAtTheTopOfTheAddressSpace(t *testing.T) {
	candidates, err := parsePoolCandidates(&juneauv1alpha1.AllocationPoolIPSpec{
		Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "255.255.255.254", End: "255.255.255.255"}},
	})
	if err != nil {
		t.Fatalf("parsePoolCandidates: %v", err)
	}
	used := map[netip.Addr]string{
		netip.MustParseAddr("255.255.255.254"): "claim-a",
		netip.MustParseAddr("255.255.255.255"): "claim-b",
	}
	if _, ok := firstFitCandidate(candidates, used); ok {
		t.Fatal("expected the candidate space to be exhausted")
	}
}

func TestCandidatesContainCoversReservedPrefixEdges(t *testing.T) {
	candidates, err := parsePoolCandidates(&juneauv1alpha1.AllocationPoolIPSpec{
		CIDRs:  []string{"192.0.2.0/24"},
		Ranges: []juneauv1alpha1.AllocationPoolIPRange{{Start: "203.0.113.10", End: "203.0.113.20"}},
	})
	if err != nil {
		t.Fatalf("parsePoolCandidates: %v", err)
	}
	tests := []struct {
		addr string
		want bool
	}{
		{"192.0.2.0", true},
		{"192.0.2.1", true},
		{"192.0.2.255", true},
		{"192.0.3.1", false},
		{"203.0.113.10", true},
		{"203.0.113.20", true},
		{"203.0.113.21", false},
		{"203.0.113.9", false},
		{"2001:db8::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := candidatesContain(candidates, netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Fatalf("candidatesContain(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestIntersectCandidates(t *testing.T) {
	mustPrefixes := func(raws ...string) []candidateRange {
		out, err := parsePrefixCandidates(raws)
		if err != nil {
			t.Fatalf("parsePrefixCandidates: %v", err)
		}
		return out
	}
	mustRange := func(start, end string) []candidateRange {
		out, err := parseRangeCandidates([]juneauv1alpha1.AllocationPoolIPRange{{Start: start, End: end}})
		if err != nil {
			t.Fatalf("parseRangeCandidates: %v", err)
		}
		return out
	}

	tests := []struct {
		name       string
		candidates []candidateRange
		filter     []candidateRange
		wantAlloc  [][2]string
	}{
		{
			name:       "narrower filter prefix keeps its own reserved edges",
			candidates: mustPrefixes("192.0.2.0/24"),
			filter:     mustPrefixes("192.0.2.0/26"),
			wantAlloc:  [][2]string{{"192.0.2.1", "192.0.2.62"}},
		},
		{
			name:       "filter wider than the pool is dropped",
			candidates: mustPrefixes("192.0.2.0/25"),
			filter:     mustPrefixes("192.0.2.0/24"),
			wantAlloc:  nil,
		},
		{
			name:       "filter outside the pool is dropped",
			candidates: mustPrefixes("192.0.2.0/24"),
			filter:     mustPrefixes("198.51.100.0/26"),
			wantAlloc:  nil,
		},
		{
			name:       "filter covered by a range pool is kept",
			candidates: mustRange("192.0.2.0", "192.0.2.255"),
			filter:     mustPrefixes("192.0.2.16/28"),
			wantAlloc:  [][2]string{{"192.0.2.17", "192.0.2.30"}},
		},
		{
			name:       "filter only partially covered by a range pool is dropped",
			candidates: mustRange("192.0.2.10", "192.0.2.20"),
			filter:     mustPrefixes("192.0.2.16/28"),
			wantAlloc:  nil,
		},
		{
			name:       "each filter entry is matched independently",
			candidates: mustPrefixes("192.0.2.0/24", "198.51.100.0/24"),
			filter:     mustPrefixes("198.51.100.0/28", "203.0.113.0/28"),
			wantAlloc:  [][2]string{{"198.51.100.1", "198.51.100.14"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intersectCandidates(tt.candidates, tt.filter)
			if len(got) != len(tt.wantAlloc) {
				t.Fatalf("len(got) = %d, want %d", len(got), len(tt.wantAlloc))
			}
			for i, want := range tt.wantAlloc {
				if got[i].allocatable.lo != netip.MustParseAddr(want[0]) || got[i].allocatable.hi != netip.MustParseAddr(want[1]) {
					t.Errorf("got[%d].allocatable = %v-%v, want %s-%s", i, got[i].allocatable.lo, got[i].allocatable.hi, want[0], want[1])
				}
			}
		})
	}
}
