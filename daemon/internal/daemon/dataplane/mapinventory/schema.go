// Package mapinventory describes the daemon's BPF maps in a form
// kubectl-juneau can render generically. Each map registered here
// declares an ordered list of named Fields for both key and value
// (mirroring the C struct in daemon/bpf/maps.h). The codec turns
// raw bytes from the BPF map into typed BPFMapField protobufs and
// back, so daemon-side handlers never have to hand-roll
// encoding/binary calls per map.
//
// Adding a new map is a four-step exercise:
//
//  1. Pick or define an enum / flag dictionary in enums.go.
//  2. Describe key + value fields with the helpers in this file.
//  3. Wire the *ebpf.Map handle into the descriptor in register.go.
//  4. Add a unit test in codec_test.go and a layout assertion.
//
// The Field types are intentionally narrow. New shapes (IPv6, large
// blobs) become new FieldType constants; existing decoders ignore
// unknown values, and ListBPFMaps surfaces them as raw bytes so
// older clients keep working.
package mapinventory

// FieldType enumerates the supported field shapes. Each value pins
// both a byte width and a rendering strategy. The wire encoding in
// debug.proto stays stable: numeric → BPFMapField.u64, address →
// BPFMapField.ipv4, etc.
type FieldType int

const (
	// FieldUnknown is the zero value; a Field with this type is
	// rejected by the registry. It exists so missing initialisation
	// is loud rather than silently coercing to U8.
	FieldUnknown FieldType = iota

	// Numeric little-endian (host byte order). Width selects width.
	FieldU8
	FieldU16
	FieldU32
	FieldU64

	// IPv4 in host byte order (decoder reorders to dotted-quad).
	FieldIPv4
	// IPv4 in network byte order (matches __be32 / iph->daddr).
	FieldIPv4BE
	// L4 port in host byte order.
	FieldPort
	// L4 port in network byte order (__be16).
	FieldPortBE
	// 6-byte MAC (octets in transmission order).
	FieldMAC

	// Padding: emitted as zero bytes, never surfaced to the client,
	// never parseable as a filter. Width is the byte count.
	FieldPad

	// Enum: numeric stored as u8/u16/u32 (Width selects), rendered
	// via Enum dictionary lookup. Falls back to "0xNN" if absent.
	FieldEnum

	// Flags: bitmask stored as u8/u16/u32, expanded via Flags
	// dictionary. The numeric value is also surfaced so users see
	// both `flags=[A,B]` and `raw=0x3`.
	FieldFlags

	// Raw: opaque byte slice (Width selects). For maps where the
	// binary payload has no useful Go-side decoder yet.
	FieldRaw
)

// Field describes one element of a key or value tuple.
type Field struct {
	// Name is what kubectl shows in column headers and what users
	// supply on --filter. Must be unique within Schema.Fields.
	Name string

	// Type controls width and rendering.
	Type FieldType

	// Width is set automatically for fixed-width types and supplied
	// by the caller for FieldEnum, FieldFlags, FieldPad, FieldRaw.
	Width int

	// Description is an optional one-liner shown next to the field
	// in `bpf list -o tree` output. Intended to help users reading
	// the schema in isolation.
	Description string

	// Enum is consulted when Type=FieldEnum. Width is mandatory.
	Enum *EnumDict

	// Flags is consulted when Type=FieldFlags. Width is mandatory.
	Flags *FlagDict
}

// fixedWidth returns the byte width baked into the type, or -1 for
// types whose width is caller-provided.
func (t FieldType) fixedWidth() int {
	switch t {
	case FieldU8:
		return 1
	case FieldU16:
		return 2
	case FieldU32, FieldIPv4, FieldIPv4BE:
		return 4
	case FieldU64:
		return 8
	case FieldPort, FieldPortBE:
		return 2
	case FieldMAC:
		return 6
	}
	return -1
}

// Schema is an ordered list of Fields plus the total bytes the
// fields occupy. The byte total must match the actual BPF map's
// KeySize / ValueSize at registration time; a mismatch is a
// programming error and surfaces from RegisterDescriptor.
type Schema struct {
	Fields []Field
}

// Width sums the per-field widths. Cheap; called once per map at
// registration.
func (s Schema) Width() int {
	n := 0
	for _, f := range s.Fields {
		n += f.Width
	}
	return n
}

// Find returns the field with the given name and its byte offset
// within the layout. Returns ok=false when not present.
func (s Schema) Find(name string) (Field, int, bool) {
	off := 0
	for _, f := range s.Fields {
		if f.Name == name {
			return f, off, true
		}
		off += f.Width
	}
	return Field{}, 0, false
}

// userVisibleFields returns only fields the client cares about
// (excludes padding). Helper for schema serialisation.
func (s Schema) userVisibleFields() []Field {
	out := make([]Field, 0, len(s.Fields))
	for _, f := range s.Fields {
		if f.Type == FieldPad {
			continue
		}
		out = append(out, f)
	}
	return out
}

// ----- Field constructors -------------------------------------------------
//
// Tiny helpers that bake in the right Width so call sites stay a
// readable list of fields. Prefer these over building Field literals
// directly — easier to grep and harder to misuse.

func FieldU8Named(name string, desc ...string) Field {
	return Field{Name: name, Type: FieldU8, Width: 1, Description: optDesc(desc)}
}
func FieldU16Named(name string, desc ...string) Field {
	return Field{Name: name, Type: FieldU16, Width: 2, Description: optDesc(desc)}
}
func FieldU32Named(name string, desc ...string) Field {
	return Field{Name: name, Type: FieldU32, Width: 4, Description: optDesc(desc)}
}
func FieldU64Named(name string, desc ...string) Field {
	return Field{Name: name, Type: FieldU64, Width: 8, Description: optDesc(desc)}
}

func FieldIPv4Named(name string, desc ...string) Field {
	return Field{Name: name, Type: FieldIPv4, Width: 4, Description: optDesc(desc)}
}
func FieldIPv4BENamed(name string, desc ...string) Field {
	return Field{Name: name, Type: FieldIPv4BE, Width: 4, Description: optDesc(desc)}
}

func FieldPortNamed(name string, desc ...string) Field {
	return Field{Name: name, Type: FieldPort, Width: 2, Description: optDesc(desc)}
}
func FieldPortBENamed(name string, desc ...string) Field {
	return Field{Name: name, Type: FieldPortBE, Width: 2, Description: optDesc(desc)}
}

func FieldMACNamed(name string, desc ...string) Field {
	return Field{Name: name, Type: FieldMAC, Width: 6, Description: optDesc(desc)}
}

// FieldPadOf reserves Width bytes for padding. Padding bytes are not
// rendered to clients and not exposed for filter parsing.
func FieldPadOf(width int) Field {
	return Field{Name: "_pad", Type: FieldPad, Width: width}
}

// FieldEnumNamed describes an enum-style numeric whose label
// dictionary translates value → name. Width must be 1, 2, or 4.
func FieldEnumNamed(name string, width int, dict *EnumDict, desc ...string) Field {
	return Field{Name: name, Type: FieldEnum, Width: width, Enum: dict, Description: optDesc(desc)}
}

// FieldFlagsNamed describes a bitmask field. Width must be 1, 2, or 4.
func FieldFlagsNamed(name string, width int, dict *FlagDict, desc ...string) Field {
	return Field{Name: name, Type: FieldFlags, Width: width, Flags: dict, Description: optDesc(desc)}
}

// FieldRawNamed reserves Width opaque bytes. Useful for fields the
// daemon hasn't bothered to model yet.
func FieldRawNamed(name string, width int, desc ...string) Field {
	return Field{Name: name, Type: FieldRaw, Width: width, Description: optDesc(desc)}
}

func optDesc(d []string) string {
	if len(d) == 0 {
		return ""
	}
	return d[0]
}
