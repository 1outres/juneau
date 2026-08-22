package addressrange

import (
	"errors"
	"net/netip"
	"testing"
)

func TestParseIPv4Range(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		start string
		end   string
	}{
		{"plain range", "10.210.0.10-10.210.0.20", "10.210.0.10", "10.210.0.20"},
		{"single address range", "10.210.0.10-10.210.0.10", "10.210.0.10", "10.210.0.10"},
		{"surrounding spaces", " 10.210.0.10 - 10.210.0.20 ", "10.210.0.10", "10.210.0.20"},
		{"ipv4-mapped ipv6 form", "::ffff:10.210.0.10-::ffff:10.210.0.20", "10.210.0.10", "10.210.0.20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := ParseIPv4Range(tt.raw)
			if err != nil {
				t.Fatalf("ParseIPv4Range(%q): %v", tt.raw, err)
			}
			if start != netip.MustParseAddr(tt.start) {
				t.Errorf("start = %v, want %s", start, tt.start)
			}
			if end != netip.MustParseAddr(tt.end) {
				t.Errorf("end = %v, want %s", end, tt.end)
			}
		})
	}
}

func TestParseIPv4RangeErrors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"no separator", "10.210.0.10", ErrMalformed},
		{"too many separators", "10.210.0.10-10.210.0.20-10.210.0.30", ErrMalformed},
		{"empty", "", ErrMalformed},
		{"unparsable start", "nope-10.210.0.20", ErrNotIPv4},
		{"unparsable end", "10.210.0.10-nope", ErrNotIPv4},
		{"ipv6 bounds", "2001:db8::1-2001:db8::2", ErrNotIPv4},
		{"start after end", "10.210.0.20-10.210.0.10", ErrReversed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseIPv4Range(tt.raw)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseIPv4Range(%q) = %v, want %v", tt.raw, err, tt.want)
			}
		})
	}
}

func TestParseIPv4RangeErrorMessages(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrMalformed, "must be in start-end format"},
		{ErrNotIPv4, "must be IPv4 range"},
		{ErrReversed, "range start must be <= end"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.err.Error() != tt.want {
				t.Fatalf("error message = %q, want %q", tt.err.Error(), tt.want)
			}
		})
	}
}
