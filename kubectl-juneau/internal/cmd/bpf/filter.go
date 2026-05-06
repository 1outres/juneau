package bpf

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

// parseFilters turns a list of "name=value" strings into BPFMapField
// protos. Value is parsed as ipv4 if it contains a dot, mac if it
// contains a colon, otherwise interpreted as a numeric (decimal or
// 0x-prefixed hex) or a label.
//
// We deliberately keep the heuristic narrow and predictable:
//
//   - "10.0.0.1"               → ipv4
//   - "aa:bb:cc:dd:ee:ff"      → mac
//   - "0x42" / "42" / "1234"   → uint64
//   - everything else          → label (lets users say
//                                "proto=TCP" or "action=CT_ACTION_DNAT")
//
// A label form is meaningful only when the daemon's schema marks the
// field as enum; the codec on the daemon side rejects mismatches with
// InvalidArgument so the user sees a clear failure.
func parseFilters(raw []string) ([]*debugpb.BPFMapField, error) {
	out := make([]*debugpb.BPFMapField, 0, len(raw))
	for _, r := range raw {
		f, err := parseOneFilter(r)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func parseOneFilter(s string) (*debugpb.BPFMapField, error) {
	idx := strings.IndexByte(s, '=')
	if idx <= 0 {
		return nil, fmt.Errorf("filter %q: expected name=value", s)
	}
	name := strings.TrimSpace(s[:idx])
	val := strings.TrimSpace(s[idx+1:])
	if name == "" {
		return nil, fmt.Errorf("filter %q: empty field name", s)
	}
	out := &debugpb.BPFMapField{Name: name}
	switch {
	case strings.Contains(val, ":") && !strings.Contains(val, "."):
		out.Value = &debugpb.BPFMapField_Mac{Mac: val}
	case strings.Contains(val, "."):
		out.Value = &debugpb.BPFMapField_Ipv4{Ipv4: val}
	default:
		// numeric (decimal / hex) → u64; otherwise label.
		if x, err := strconv.ParseUint(val, 0, 64); err == nil {
			out.Value = &debugpb.BPFMapField_U64{U64: x}
		} else {
			out.Value = &debugpb.BPFMapField_Label{Label: val}
		}
	}
	return out, nil
}
