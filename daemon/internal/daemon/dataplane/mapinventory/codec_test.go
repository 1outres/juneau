package mapinventory

import (
	"bytes"
	"errors"
	"testing"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

// roundTrip exercises EncodeFields → DecodeFields and asserts the
// decoded protos surface the same logical values that went in. Field
// width parity with Schema.Width is verified separately in
// TestSchemaWidth.
func roundTrip(t *testing.T, s Schema, in []*debugpb.BPFMapField) []*debugpb.BPFMapField {
	t.Helper()
	raw, err := EncodeFields(s, in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got := len(raw); got != s.Width() {
		t.Fatalf("encoded width %d, schema width %d", got, s.Width())
	}
	return DecodeFields(s, raw)
}

func mapField(name string, v interface{}) *debugpb.BPFMapField {
	out := &debugpb.BPFMapField{Name: name}
	switch v := v.(type) {
	case uint64:
		out.Value = &debugpb.BPFMapField_U64{U64: v}
	case int:
		out.Value = &debugpb.BPFMapField_U64{U64: uint64(v)}
	case string:
		// Heuristic for tests: contains '.' → ipv4, contains ':' → mac.
		if hasDot(v) {
			out.Value = &debugpb.BPFMapField_Ipv4{Ipv4: v}
			break
		}
		if hasColon(v) {
			out.Value = &debugpb.BPFMapField_Mac{Mac: v}
			break
		}
		out.Value = &debugpb.BPFMapField_Label{Label: v}
	case []byte:
		out.Value = &debugpb.BPFMapField_Raw{Raw: v}
	}
	return out
}

func hasDot(s string) bool   { return bytes.IndexByte([]byte(s), '.') >= 0 }
func hasColon(s string) bool { return bytes.IndexByte([]byte(s), ':') >= 0 }

func TestRoundTripCTKey(t *testing.T) {
	s := Schema{Fields: []Field{
		FieldEnumNamed("scope", 4, CTScopeEnum),
		FieldIPv4BENamed("saddr"),
		FieldIPv4BENamed("daddr"),
		FieldPortNamed("sport"),
		FieldPortNamed("dport"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(3),
	}}
	if w := s.Width(); w != 20 {
		t.Fatalf("ct_key width=%d, want 20", w)
	}

	got := roundTrip(t, s, []*debugpb.BPFMapField{
		mapField("scope", uint64(0)),
		mapField("saddr", "10.0.0.1"),
		mapField("daddr", "10.96.0.1"),
		mapField("sport", uint64(40000)),
		mapField("dport", uint64(443)),
		mapField("proto", uint64(6)), // TCP
	})

	expect := map[string]string{
		"scope": "label:CT_SCOPE_HOST",
		"saddr": "ipv4:10.0.0.1",
		"daddr": "ipv4:10.96.0.1",
		"sport": "u64:40000",
		"dport": "u64:443",
		"proto": "label:TCP",
	}
	gotMap := mapByName(got)
	for k, want := range expect {
		assertField(t, gotMap[k], want)
	}
}

func TestRoundTripSubnetVal(t *testing.T) {
	s := Schema{Fields: []Field{
		FieldU32Named("table_id"),
		FieldU32Named("vpc_id"),
		FieldMACNamed("gw_mac"),
		FieldPadOf(2),
		FieldIPv4BENamed("gw_addr"),
		FieldU32Named("mask"),
		FieldU32Named("acl_id"),
	}}
	if w := s.Width(); w != 28 {
		t.Fatalf("subnet_val width=%d, want 28", w)
	}

	got := roundTrip(t, s, []*debugpb.BPFMapField{
		mapField("table_id", uint64(7)),
		mapField("vpc_id", uint64(2)),
		mapField("gw_mac", "aa:bb:cc:dd:ee:ff"),
		mapField("gw_addr", "10.16.0.1"),
		mapField("mask", uint64(24)),
		mapField("acl_id", uint64(0)),
	})

	gotMap := mapByName(got)
	assertField(t, gotMap["table_id"], "u64:7")
	assertField(t, gotMap["vpc_id"], "u64:2")
	assertField(t, gotMap["gw_mac"], "mac:aa:bb:cc:dd:ee:ff")
	assertField(t, gotMap["gw_addr"], "ipv4:10.16.0.1")
}

func TestRoundTripServiceFlags(t *testing.T) {
	s := Schema{Fields: []Field{
		FieldU32Named("owner_vpc_id"),
		FieldU32Named("backend_count"),
		FieldU32Named("affinity_sec"),
		FieldFlagsNamed("flags", 4, SVCFlagDict),
	}}
	got := roundTrip(t, s, []*debugpb.BPFMapField{
		mapField("owner_vpc_id", uint64(1)),
		mapField("backend_count", uint64(3)),
		mapField("affinity_sec", uint64(0)),
		mapField("flags", SVCFlagDict.bits[0].mask|SVCFlagDict.bits[1].mask),
	})
	flagsField := mapByName(got)["flags"]
	if flagsField == nil {
		t.Fatalf("flags field missing")
	}
	if flagsField.GetU64() != 0x3 {
		t.Errorf("flags u64=%x, want 0x3", flagsField.GetU64())
	}
	want := []string{"SVC_FLAG_SHARED", "SVC_FLAG_HAS_ACL"}
	if got := flagsField.Flags; !sliceEq(got, want) {
		t.Errorf("flags labels=%v, want %v", got, want)
	}
}

func TestRoundTripVirtualServiceKey(t *testing.T) {
	// dst_port is FieldPortBE — verify that "53" round-trips through
	// network byte order without ending up byte-swapped.
	s := Schema{Fields: []Field{
		FieldU32Named("subnet_id"),
		FieldIPv4BENamed("dst_ip"),
		FieldPortBENamed("dst_port"),
		FieldEnumNamed("proto", 1, IPProtoEnum),
		FieldPadOf(1),
	}}
	got := roundTrip(t, s, []*debugpb.BPFMapField{
		mapField("subnet_id", uint64(1)),
		mapField("dst_ip", "10.16.0.2"),
		mapField("dst_port", uint64(53)),
		mapField("proto", uint64(17)),
	})
	gotMap := mapByName(got)
	assertField(t, gotMap["dst_port"], "u64:53")
	assertField(t, gotMap["dst_ip"], "ipv4:10.16.0.2")
	assertField(t, gotMap["proto"], "label:UDP")
}

func TestEncodeRejectsUnknownField(t *testing.T) {
	s := Schema{Fields: []Field{FieldU32Named("subnet_id")}}
	_, err := EncodeFields(s, []*debugpb.BPFMapField{mapField("nope", uint64(0))})
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("err=%v, want ErrUnknownField", err)
	}
}

func TestEncodeOverflow(t *testing.T) {
	s := Schema{Fields: []Field{FieldU8Named("x")}}
	_, err := EncodeFields(s, []*debugpb.BPFMapField{mapField("x", uint64(256))})
	if !errors.Is(err, ErrFieldOverflow) {
		t.Fatalf("err=%v, want ErrFieldOverflow", err)
	}
}

func TestFilterCoversKey(t *testing.T) {
	s := Schema{Fields: []Field{
		FieldU32Named("vpc_id"),
		FieldIPv4BENamed("ipv4"),
		FieldPadOf(0),
	}}
	cases := []struct {
		name   string
		filter []*debugpb.BPFMapField
		want   bool
	}{
		{"empty", nil, false},
		{"partial", []*debugpb.BPFMapField{mapField("vpc_id", uint64(1))}, false},
		{"complete", []*debugpb.BPFMapField{
			mapField("vpc_id", uint64(1)),
			mapField("ipv4", "10.0.0.1"),
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FilterCoversKey(s, tc.filter); got != tc.want {
				t.Fatalf("FilterCoversKey=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatchesFilter(t *testing.T) {
	s := Schema{Fields: []Field{
		FieldU32Named("vpc_id"),
		FieldIPv4BENamed("ipv4"),
	}}
	raw, err := EncodeFields(s, []*debugpb.BPFMapField{
		mapField("vpc_id", uint64(2)),
		mapField("ipv4", "10.16.0.5"),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if !MatchesFilter(s, raw, []*debugpb.BPFMapField{
		mapField("vpc_id", uint64(2)),
	}) {
		t.Errorf("expected partial match")
	}
	if MatchesFilter(s, raw, []*debugpb.BPFMapField{
		mapField("vpc_id", uint64(99)),
	}) {
		t.Errorf("unexpected match on wrong vpc_id")
	}
	if !MatchesFilter(s, raw, []*debugpb.BPFMapField{
		mapField("ipv4", "10.16.0.5"),
	}) {
		t.Errorf("expected ipv4 match")
	}
	if MatchesFilter(s, raw, []*debugpb.BPFMapField{
		mapField("ipv4", "10.16.0.6"),
	}) {
		t.Errorf("unexpected ipv4 match")
	}
}

// ----- helpers -----------------------------------------------------------

func mapByName(fs []*debugpb.BPFMapField) map[string]*debugpb.BPFMapField {
	m := map[string]*debugpb.BPFMapField{}
	for _, f := range fs {
		m[f.Name] = f
	}
	return m
}

func assertField(t *testing.T, f *debugpb.BPFMapField, want string) {
	t.Helper()
	if f == nil {
		t.Fatalf("field missing, want %q", want)
	}
	got := encodeFieldForAssert(f)
	if got != want {
		t.Errorf("field=%q, want %q", got, want)
	}
}

func encodeFieldForAssert(f *debugpb.BPFMapField) string {
	switch v := f.Value.(type) {
	case *debugpb.BPFMapField_U64:
		return formatU("u64", v.U64)
	case *debugpb.BPFMapField_Ipv4:
		return "ipv4:" + v.Ipv4
	case *debugpb.BPFMapField_Mac:
		return "mac:" + v.Mac
	case *debugpb.BPFMapField_Label:
		return "label:" + v.Label
	case *debugpb.BPFMapField_Raw:
		return "raw:" + FormatHex(v.Raw)
	}
	return "<empty>"
}

func formatU(prefix string, v uint64) string {
	return prefix + ":" + uitoa(v)
}

func uitoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for v > 0 {
		pos--
		b[pos] = byte('0' + v%10)
		v /= 10
	}
	return string(b[pos:])
}

func sliceEq(a, b []string) bool {
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
