package addressrange

import (
	"net/netip"
	"testing"
)

func mustRange(start, end string) Range {
	return Range{Start: netip.MustParseAddr(start), End: netip.MustParseAddr(end)}
}

func TestPrefixRange(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   Range
	}{
		{"slash 24", "10.210.0.0/24", mustRange("10.210.0.0", "10.210.0.255")},
		{"host bits are masked off", "10.210.0.77/24", mustRange("10.210.0.0", "10.210.0.255")},
		{"slash 30", "10.210.0.4/30", mustRange("10.210.0.4", "10.210.0.7")},
		{"slash 32", "10.210.0.9/32", mustRange("10.210.0.9", "10.210.0.9")},
		{"slash 8", "10.0.0.0/8", mustRange("10.0.0.0", "10.255.255.255")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PrefixRange(netip.MustParsePrefix(tt.prefix))
			if got != tt.want {
				t.Fatalf("PrefixRange(%s) = %v, want %v", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestRangeIntersect(t *testing.T) {
	tests := []struct {
		name  string
		a     Range
		b     Range
		want  Range
		share bool
	}{
		{"same range", mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.10", "10.0.0.20"), true},
		{"b inside a", mustRange("10.0.0.0", "10.0.0.255"), mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.10", "10.0.0.20"), true},
		{"a inside b", mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.0", "10.0.0.255"), mustRange("10.0.0.10", "10.0.0.20"), true},
		{"tail of a meets head of b", mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.15", "10.0.0.30"), mustRange("10.0.0.15", "10.0.0.20"), true},
		{"head of a meets tail of b", mustRange("10.0.0.15", "10.0.0.30"), mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.15", "10.0.0.20"), true},
		{"one shared edge address", mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.20", "10.0.0.30"), mustRange("10.0.0.20", "10.0.0.20"), true},
		{"single address inside", mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.12", "10.0.0.12"), mustRange("10.0.0.12", "10.0.0.12"), true},
		{"adjacent ranges", mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.21", "10.0.0.30"), Range{}, false},
		{"b before a", mustRange("10.0.0.10", "10.0.0.20"), mustRange("10.0.0.0", "10.0.0.9"), Range{}, false},
		{"far apart", mustRange("10.0.0.10", "10.0.0.20"), mustRange("192.0.2.0", "192.0.2.255"), Range{}, false},
		{"other address family", mustRange("0.0.0.0", "255.255.255.255"), mustRange("::", "::ffff"), Range{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, share := tt.a.Intersect(tt.b)
			if share != tt.share {
				t.Fatalf("%v.Intersect(%v) share = %v, want %v", tt.a, tt.b, share, tt.share)
			}
			if got != tt.want {
				t.Fatalf("%v.Intersect(%v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestRangeString(t *testing.T) {
	tests := []struct {
		name  string
		input Range
		want  string
	}{
		{"wide range", mustRange("10.0.0.10", "10.0.0.20"), "10.0.0.10-10.0.0.20"},
		{"single address", mustRange("10.0.0.12", "10.0.0.12"), "10.0.0.12"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.String(); got != tt.want {
				t.Fatalf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
