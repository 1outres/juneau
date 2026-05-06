// Package bpfmap is the kubectl-juneau-side domain layer for the
// `juneau bpf` command family. The Daemon is the source of truth for
// every map's name and field schema; this package translates the
// gRPC types in debugpb into rendering-friendly DTOs and provides the
// node-fan-out machinery `bpf list` and `bpf dump` need.
//
// Design notes:
//
//   - DTOs are intentionally lossless mirrors of the proto. The
//     command layer stays free of *debugpb.* types so future wire
//     evolution doesn't ripple.
//   - Renderers are split per format (tree / table / json / yaml)
//     and selected at the cmd layer through output.PrintFlags. This
//     mirrors the `describe` command convention.
//   - Node fan-out is implemented as a small Aggregator type so unit
//     tests can substitute a fake MapClient without touching gRPC.
package bpfmap

import (
	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

// Schema is the kubectl-side mirror of debugpb.BPFMapSchema.
type Schema struct {
	Name             string
	Kind             string
	MaxEntries       uint32
	KeySchema        []FieldSchema
	ValueSchema      []FieldSchema
	RequiresInnerKey bool
	InnerKeySchema   []FieldSchema
	InnerValueSchema []FieldSchema
}

// FieldSchema mirrors debugpb.BPFMapFieldSchema.
type FieldSchema struct {
	Name        string
	Type        string
	Description string
}

// Field carries one decoded element of a key or value.
type Field struct {
	Name string
	// Render returns the user-facing string. The rendering is
	// type-aware: numerics print as base-10, ipv4 stays dotted-quad,
	// labels print verbatim. Always returns a non-empty string.
	Value string
	// Numeric is the raw u64 (when applicable) so structured callers
	// can still filter / threshold without re-parsing Value.
	Numeric uint64
	HasNum  bool
	// Flags is the populated set of bitmask labels (only set for
	// FieldFlags fields).
	Flags []string
}

// Entry is the kubectl-side mirror of debugpb.BPFMapEntry.
type Entry struct {
	// Node is the daemon node this entry came from. Empty when the
	// caller did not request multi-node aggregation.
	Node  string
	Key   []Field
	Value []Field
}

// FromSchemaProto translates one wire schema into a domain Schema.
// Defensive about nil input so callers do not have to guard every
// access — the empty result is an empty Schema with the supplied
// name preserved if any.
func FromSchemaProto(s *debugpb.BPFMapSchema) Schema {
	if s == nil {
		return Schema{}
	}
	return Schema{
		Name:             s.Name,
		Kind:             s.Kind,
		MaxEntries:       s.MaxEntries,
		KeySchema:        toFieldSchemas(s.KeySchema),
		ValueSchema:      toFieldSchemas(s.ValueSchema),
		RequiresInnerKey: s.RequiresInnerKey,
		InnerKeySchema:   toFieldSchemas(s.InnerKeySchema),
		InnerValueSchema: toFieldSchemas(s.InnerValueSchema),
	}
}

// FromEntryProto translates one wire entry into a domain Entry. node
// is propagated as-is for multi-node renderers.
func FromEntryProto(node string, e *debugpb.BPFMapEntry) Entry {
	return Entry{
		Node:  node,
		Key:   toFields(e.GetKey()),
		Value: toFields(e.GetValue()),
	}
}

func toFieldSchemas(in []*debugpb.BPFMapFieldSchema) []FieldSchema {
	out := make([]FieldSchema, 0, len(in))
	for _, f := range in {
		if f == nil {
			continue
		}
		out = append(out, FieldSchema{Name: f.Name, Type: f.Type, Description: f.Description})
	}
	return out
}

func toFields(in []*debugpb.BPFMapField) []Field {
	out := make([]Field, 0, len(in))
	for _, f := range in {
		if f == nil {
			continue
		}
		out = append(out, fromFieldProto(f))
	}
	return out
}

func fromFieldProto(f *debugpb.BPFMapField) Field {
	out := Field{Name: f.Name, Flags: append([]string(nil), f.Flags...)}
	switch v := f.Value.(type) {
	case *debugpb.BPFMapField_U64:
		out.Numeric = v.U64
		out.HasNum = true
		out.Value = formatU64(v.U64, f.Flags)
	case *debugpb.BPFMapField_Ipv4:
		out.Value = v.Ipv4
	case *debugpb.BPFMapField_Mac:
		out.Value = v.Mac
	case *debugpb.BPFMapField_Label:
		out.Value = v.Label
	case *debugpb.BPFMapField_Raw:
		out.Value = formatRaw(v.Raw)
	default:
		out.Value = ""
	}
	return out
}
