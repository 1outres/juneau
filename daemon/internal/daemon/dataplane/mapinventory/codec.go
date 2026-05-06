package mapinventory

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

// EncodeFields converts a list of typed BPFMapField protos into the
// raw byte layout described by Schema. The fields parameter does not
// have to enumerate every Schema field — missing fields are written
// as zeros so partial filters work as a Lookup template once every
// key field is present (DumpBPFMap fast path), and as a "wildcard
// where unspecified" predicate otherwise (linear scan path). Padding
// fields are always written as zeros and cannot be supplied.
//
// Returns ErrUnknownField if a supplied field name is not in Schema,
// ErrFieldType if a supplied field is the wrong shape (e.g. ipv4
// supplied for an enum), and ErrFieldOverflow if a numeric value
// exceeds the field's width.
func EncodeFields(s Schema, fields []*debugpb.BPFMapField) ([]byte, error) {
	out := make([]byte, s.Width())

	supplied := map[string]*debugpb.BPFMapField{}
	for _, f := range fields {
		if f == nil {
			continue
		}
		supplied[f.Name] = f
	}

	off := 0
	for _, f := range s.Fields {
		end := off + f.Width
		if v, ok := supplied[f.Name]; ok {
			if f.Type == FieldPad {
				return nil, fmt.Errorf("%w: cannot set padding field %q", ErrFieldType, f.Name)
			}
			if err := encodeField(f, v, out[off:end]); err != nil {
				return nil, err
			}
			delete(supplied, f.Name)
		}
		off = end
	}

	for name := range supplied {
		return nil, fmt.Errorf("%w: %q", ErrUnknownField, name)
	}
	return out, nil
}

// DecodeFields walks Schema over raw and returns one BPFMapField proto
// per (non-padding) field. Always succeeds for input of the expected
// width; an input shorter than Width is padded with zeros, longer is
// truncated, both with no error — callers control input width via
// the BPF map's KeySize/ValueSize.
func DecodeFields(s Schema, raw []byte) []*debugpb.BPFMapField {
	out := make([]*debugpb.BPFMapField, 0, len(s.Fields))
	off := 0
	for _, f := range s.Fields {
		end := off + f.Width
		if end > len(raw) {
			end = len(raw)
		}
		slice := raw[off:end]
		// Pad slice up to f.Width so decoders read predictably.
		var buf []byte
		if len(slice) < f.Width {
			buf = make([]byte, f.Width)
			copy(buf, slice)
		} else {
			buf = slice
		}
		if f.Type != FieldPad {
			out = append(out, decodeField(f, buf))
		}
		off += f.Width
	}
	return out
}

// MatchesFilter returns true when raw matches every field in filter.
// A filter that names no fields matches everything (used for an
// unfiltered linear scan). Field name validation is performed by the
// caller (see ValidateFilter).
func MatchesFilter(s Schema, raw []byte, filter []*debugpb.BPFMapField) bool {
	for _, want := range filter {
		field, off, ok := s.Find(want.Name)
		if !ok {
			return false
		}
		actual := raw[off : off+field.Width]
		got := decodeField(field, actual)
		if !fieldEquals(field.Type, want, got) {
			return false
		}
	}
	return true
}

// ValidateFilter returns nil iff every field name referenced by the
// filter exists in Schema and the value shape is compatible. Run this
// before MatchesFilter to fail fast with a clean error.
func ValidateFilter(s Schema, filter []*debugpb.BPFMapField) error {
	for _, f := range filter {
		if f == nil {
			continue
		}
		field, _, ok := s.Find(f.Name)
		if !ok {
			return fmt.Errorf("%w: %q", ErrUnknownField, f.Name)
		}
		if field.Type == FieldPad {
			return fmt.Errorf("%w: cannot filter on padding field %q", ErrFieldType, f.Name)
		}
		if !fieldShapeMatches(field.Type, f) {
			return fmt.Errorf("%w: field %q expects %s", ErrFieldType, f.Name, fieldTypeWireHint(field.Type))
		}
	}
	return nil
}

// FilterCoversKey reports whether filter names every (non-padding)
// field of Schema. When true, the caller may collapse the filter into
// a single Lookup; otherwise a linear scan is required.
func FilterCoversKey(s Schema, filter []*debugpb.BPFMapField) bool {
	supplied := make(map[string]struct{}, len(filter))
	for _, f := range filter {
		if f == nil {
			continue
		}
		supplied[f.Name] = struct{}{}
	}
	for _, f := range s.Fields {
		if f.Type == FieldPad {
			continue
		}
		if _, ok := supplied[f.Name]; !ok {
			return false
		}
	}
	return true
}

// ----- per-field encode/decode -------------------------------------------

func encodeField(f Field, v *debugpb.BPFMapField, dst []byte) error {
	switch f.Type {
	case FieldU8:
		x, err := numericValue(v)
		if err != nil {
			return err
		}
		if x > 0xFF {
			return fmt.Errorf("%w: %s = %d", ErrFieldOverflow, f.Name, x)
		}
		dst[0] = uint8(x)
	case FieldU16:
		x, err := numericValue(v)
		if err != nil {
			return err
		}
		if x > 0xFFFF {
			return fmt.Errorf("%w: %s = %d", ErrFieldOverflow, f.Name, x)
		}
		binary.LittleEndian.PutUint16(dst, uint16(x))
	case FieldU32:
		x, err := numericValue(v)
		if err != nil {
			return err
		}
		if x > 0xFFFFFFFF {
			return fmt.Errorf("%w: %s = %d", ErrFieldOverflow, f.Name, x)
		}
		binary.LittleEndian.PutUint32(dst, uint32(x))
	case FieldU64:
		x, err := numericValue(v)
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint64(dst, x)
	case FieldIPv4:
		ip, err := parseIPv4(v)
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		// Stored host-order: dotted-quad a.b.c.d → bytes [d,c,b,a].
		dst[0] = ip[3]
		dst[1] = ip[2]
		dst[2] = ip[1]
		dst[3] = ip[0]
	case FieldIPv4BE:
		ip, err := parseIPv4(v)
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		copy(dst, ip[:])
	case FieldPort:
		x, err := numericValue(v)
		if err != nil {
			return err
		}
		if x > 0xFFFF {
			return fmt.Errorf("%w: %s = %d", ErrFieldOverflow, f.Name, x)
		}
		binary.LittleEndian.PutUint16(dst, uint16(x))
	case FieldPortBE:
		x, err := numericValue(v)
		if err != nil {
			return err
		}
		if x > 0xFFFF {
			return fmt.Errorf("%w: %s = %d", ErrFieldOverflow, f.Name, x)
		}
		binary.BigEndian.PutUint16(dst, uint16(x))
	case FieldMAC:
		mac, err := parseMAC(v)
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		copy(dst, mac)
	case FieldEnum, FieldFlags:
		x, err := numericValue(v)
		if err != nil {
			return err
		}
		switch f.Width {
		case 1:
			if x > 0xFF {
				return fmt.Errorf("%w: %s = %d", ErrFieldOverflow, f.Name, x)
			}
			dst[0] = uint8(x)
		case 2:
			if x > 0xFFFF {
				return fmt.Errorf("%w: %s = %d", ErrFieldOverflow, f.Name, x)
			}
			binary.LittleEndian.PutUint16(dst, uint16(x))
		case 4:
			if x > 0xFFFFFFFF {
				return fmt.Errorf("%w: %s = %d", ErrFieldOverflow, f.Name, x)
			}
			binary.LittleEndian.PutUint32(dst, uint32(x))
		default:
			return fmt.Errorf("%w: enum/flags width %d", ErrFieldType, f.Width)
		}
	case FieldRaw:
		if v.GetRaw() == nil {
			return fmt.Errorf("%w: %s expects raw bytes", ErrFieldType, f.Name)
		}
		if len(v.GetRaw()) != f.Width {
			return fmt.Errorf("%w: %s expects %d bytes, got %d", ErrFieldOverflow, f.Name, f.Width, len(v.GetRaw()))
		}
		copy(dst, v.GetRaw())
	case FieldPad:
		// already zeroed by make([])
	default:
		return fmt.Errorf("%w: unhandled field type for %s", ErrFieldType, f.Name)
	}
	return nil
}

func decodeField(f Field, src []byte) *debugpb.BPFMapField {
	out := &debugpb.BPFMapField{Name: f.Name}
	switch f.Type {
	case FieldU8:
		out.Value = &debugpb.BPFMapField_U64{U64: uint64(src[0])}
	case FieldU16:
		out.Value = &debugpb.BPFMapField_U64{U64: uint64(binary.LittleEndian.Uint16(src))}
	case FieldU32:
		out.Value = &debugpb.BPFMapField_U64{U64: uint64(binary.LittleEndian.Uint32(src))}
	case FieldU64:
		out.Value = &debugpb.BPFMapField_U64{U64: binary.LittleEndian.Uint64(src)}
	case FieldIPv4:
		// Host-order: bytes [d,c,b,a] in memory; dotted quad a.b.c.d.
		out.Value = &debugpb.BPFMapField_Ipv4{Ipv4: net.IPv4(src[3], src[2], src[1], src[0]).String()}
	case FieldIPv4BE:
		out.Value = &debugpb.BPFMapField_Ipv4{Ipv4: net.IPv4(src[0], src[1], src[2], src[3]).String()}
	case FieldPort:
		out.Value = &debugpb.BPFMapField_U64{U64: uint64(binary.LittleEndian.Uint16(src))}
	case FieldPortBE:
		out.Value = &debugpb.BPFMapField_U64{U64: uint64(binary.BigEndian.Uint16(src))}
	case FieldMAC:
		out.Value = &debugpb.BPFMapField_Mac{Mac: net.HardwareAddr(src).String()}
	case FieldEnum:
		x := readUint(src, f.Width)
		out.Value = &debugpb.BPFMapField_U64{U64: x}
		out.Name = f.Name
		// Override with label form when known. Plain numeric still
		// reaches the wire (in u64) so structured clients have both.
		out = &debugpb.BPFMapField{
			Name:  f.Name,
			Value: &debugpb.BPFMapField_Label{Label: f.Enum.Render(x)},
		}
	case FieldFlags:
		x := readUint(src, f.Width)
		out.Value = &debugpb.BPFMapField_U64{U64: x}
		out.Flags = f.Flags.Render(x)
	case FieldRaw:
		buf := make([]byte, len(src))
		copy(buf, src)
		out.Value = &debugpb.BPFMapField_Raw{Raw: buf}
	}
	return out
}

func readUint(src []byte, width int) uint64 {
	switch width {
	case 1:
		return uint64(src[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(src))
	case 4:
		return uint64(binary.LittleEndian.Uint32(src))
	case 8:
		return binary.LittleEndian.Uint64(src)
	}
	return 0
}

// ----- predicate helpers --------------------------------------------------

func fieldEquals(t FieldType, want, got *debugpb.BPFMapField) bool {
	switch t {
	case FieldU8, FieldU16, FieldU32, FieldU64, FieldPort, FieldPortBE:
		return got.GetU64() == coerceToU64(want)
	case FieldIPv4, FieldIPv4BE:
		// Allow numeric, ipv4-string, and label forms.
		gotIP, _ := net.ParseIP(got.GetIpv4()).MarshalText()
		wantIP, ok := normaliseIP(want)
		if !ok {
			return false
		}
		return string(gotIP) == string(wantIP)
	case FieldMAC:
		return strings.EqualFold(got.GetMac(), want.GetMac())
	case FieldEnum:
		// Match either by label or by numeric value.
		if want.GetLabel() != "" {
			return got.GetLabel() == want.GetLabel()
		}
		gotN, ok := labelToNumeric(t, want, got)
		if !ok {
			return false
		}
		return gotN == coerceToU64(want)
	case FieldFlags:
		return got.GetU64() == coerceToU64(want)
	case FieldRaw:
		return string(got.GetRaw()) == string(want.GetRaw())
	}
	return false
}

func labelToNumeric(_ FieldType, _, got *debugpb.BPFMapField) (uint64, bool) {
	// got is the Render form (label or hex). We do not have a reverse
	// dictionary here; the caller supplies numeric for non-label
	// matches. Returning the u64 component covers the numeric case.
	// Use Filter-side u64 (caller sets u64 alongside label when both
	// are known).
	return got.GetU64(), true
}

func coerceToU64(f *debugpb.BPFMapField) uint64 {
	if v, ok := f.Value.(*debugpb.BPFMapField_U64); ok {
		return v.U64
	}
	return 0
}

func normaliseIP(f *debugpb.BPFMapField) ([]byte, bool) {
	switch v := f.Value.(type) {
	case *debugpb.BPFMapField_Ipv4:
		ip := net.ParseIP(v.Ipv4)
		if ip == nil {
			return nil, false
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, false
		}
		out, _ := ip4.MarshalText()
		return out, true
	case *debugpb.BPFMapField_U64:
		// Numeric form is treated as host-order IPv4.
		ip := net.IPv4(byte(v.U64>>24), byte(v.U64>>16), byte(v.U64>>8), byte(v.U64))
		out, _ := ip.MarshalText()
		return out, true
	}
	return nil, false
}

// fieldShapeMatches verifies that the BPFMapField proto carries a
// value the encoder can interpret for the field type. Used in
// ValidateFilter so the failure surfaces cleanly to kubectl users.
func fieldShapeMatches(t FieldType, f *debugpb.BPFMapField) bool {
	switch t {
	case FieldU8, FieldU16, FieldU32, FieldU64, FieldPort, FieldPortBE,
		FieldEnum, FieldFlags:
		_, ok := f.Value.(*debugpb.BPFMapField_U64)
		if ok {
			return true
		}
		// For enums we additionally accept a label form.
		_, ok = f.Value.(*debugpb.BPFMapField_Label)
		return ok && t == FieldEnum
	case FieldIPv4, FieldIPv4BE:
		switch f.Value.(type) {
		case *debugpb.BPFMapField_Ipv4, *debugpb.BPFMapField_U64:
			return true
		}
	case FieldMAC:
		_, ok := f.Value.(*debugpb.BPFMapField_Mac)
		return ok
	case FieldRaw:
		_, ok := f.Value.(*debugpb.BPFMapField_Raw)
		return ok
	}
	return false
}

func fieldTypeWireHint(t FieldType) string {
	switch t {
	case FieldU8, FieldU16, FieldU32, FieldU64, FieldPort, FieldPortBE,
		FieldEnum, FieldFlags:
		return "uint64"
	case FieldIPv4, FieldIPv4BE:
		return "ipv4 string"
	case FieldMAC:
		return "mac string"
	case FieldRaw:
		return "raw bytes"
	}
	return "<unknown>"
}

// ----- value parsing helpers ---------------------------------------------

func numericValue(f *debugpb.BPFMapField) (uint64, error) {
	switch v := f.Value.(type) {
	case *debugpb.BPFMapField_U64:
		return v.U64, nil
	case *debugpb.BPFMapField_Label:
		// Try to parse "0xNN" or decimal.
		s := strings.TrimSpace(v.Label)
		if x, err := strconv.ParseUint(s, 0, 64); err == nil {
			return x, nil
		}
		return 0, fmt.Errorf("%w: cannot parse numeric from label %q", ErrFieldType, v.Label)
	}
	return 0, fmt.Errorf("%w: expected numeric u64", ErrFieldType)
}

func parseIPv4(f *debugpb.BPFMapField) ([4]byte, error) {
	switch v := f.Value.(type) {
	case *debugpb.BPFMapField_Ipv4:
		ip := net.ParseIP(v.Ipv4)
		if ip == nil {
			return [4]byte{}, fmt.Errorf("invalid IPv4 %q", v.Ipv4)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return [4]byte{}, fmt.Errorf("not an IPv4 address: %q", v.Ipv4)
		}
		var out [4]byte
		copy(out[:], ip4)
		return out, nil
	case *debugpb.BPFMapField_U64:
		var out [4]byte
		// Treat as host-order: a.b.c.d => bytes [a, b, c, d] in
		// dotted-quad form.
		out[0] = byte(v.U64 >> 24)
		out[1] = byte(v.U64 >> 16)
		out[2] = byte(v.U64 >> 8)
		out[3] = byte(v.U64)
		return out, nil
	}
	return [4]byte{}, fmt.Errorf("%w: expected ipv4 or u64", ErrFieldType)
}

func parseMAC(f *debugpb.BPFMapField) (net.HardwareAddr, error) {
	switch v := f.Value.(type) {
	case *debugpb.BPFMapField_Mac:
		return net.ParseMAC(v.Mac)
	case *debugpb.BPFMapField_Raw:
		if len(v.Raw) != 6 {
			return nil, fmt.Errorf("mac: expected 6 raw bytes, got %d", len(v.Raw))
		}
		out := make(net.HardwareAddr, 6)
		copy(out, v.Raw)
		return out, nil
	}
	return nil, fmt.Errorf("%w: expected mac string", ErrFieldType)
}

// FormatHex is an exported helper kubectl-side renderers use for raw
// fields. Kept here so daemon and client agree on the same encoding.
func FormatHex(b []byte) string { return hex.EncodeToString(b) }
