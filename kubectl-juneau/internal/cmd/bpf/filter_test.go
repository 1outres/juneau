package bpf

import (
	"testing"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

func TestParseFilters(t *testing.T) {
	cases := []struct {
		in     string
		name   string
		assert func(t *testing.T, f *debugpb.BPFMapField)
	}{
		{"vpc_id=2", "vpc_id", func(t *testing.T, f *debugpb.BPFMapField) {
			t.Helper()
			if f.GetU64() != 2 {
				t.Errorf("u64=%d, want 2", f.GetU64())
			}
		}},
		{"saddr=10.0.0.5", "saddr", func(t *testing.T, f *debugpb.BPFMapField) {
			t.Helper()
			if f.GetIpv4() != "10.0.0.5" {
				t.Errorf("ipv4=%q", f.GetIpv4())
			}
		}},
		{"gw_mac=aa:bb:cc:dd:ee:ff", "gw_mac", func(t *testing.T, f *debugpb.BPFMapField) {
			t.Helper()
			if f.GetMac() != "aa:bb:cc:dd:ee:ff" {
				t.Errorf("mac=%q", f.GetMac())
			}
		}},
		{"action=CT_ACTION_DNAT", "action", func(t *testing.T, f *debugpb.BPFMapField) {
			t.Helper()
			if f.GetLabel() != "CT_ACTION_DNAT" {
				t.Errorf("label=%q", f.GetLabel())
			}
		}},
		{"flags=0x3", "flags", func(t *testing.T, f *debugpb.BPFMapField) {
			t.Helper()
			if f.GetU64() != 3 {
				t.Errorf("u64=%d, want 3 (hex parse)", f.GetU64())
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			fs, err := parseFilters([]string{tc.in})
			if err != nil {
				t.Fatalf("parseFilters: %v", err)
			}
			if len(fs) != 1 {
				t.Fatalf("got %d fields, want 1", len(fs))
			}
			if fs[0].Name != tc.name {
				t.Errorf("name=%q, want %q", fs[0].Name, tc.name)
			}
			tc.assert(t, fs[0])
		})
	}
}

func TestParseFiltersErrors(t *testing.T) {
	for _, raw := range []string{"", "novalue", "=value", " "} {
		if _, err := parseFilters([]string{raw}); err == nil {
			t.Errorf("parseFilters(%q) expected error", raw)
		}
	}
}
