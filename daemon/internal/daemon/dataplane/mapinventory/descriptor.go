package mapinventory

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

// Descriptor binds a logical map (its name, key/value Schema) to the
// runtime *ebpf.Map handle. For HASH_OF_MAPS, InnerKey/InnerValue
// describe the inner map; the InnerProto field is consulted to derive
// max_entries for the schema response, since cilium/ebpf hides this
// behind ebpf.MapSpec rather than the *ebpf.Map handle.
type Descriptor struct {
	Name string

	// Map is the live BPF handle. Required for non-HASH_OF_MAPS maps;
	// for HASH_OF_MAPS the outer Map handle is required AND the
	// InnerProto descriptor must be supplied so the daemon can open
	// inner maps on demand.
	Map *ebpf.Map

	// Key + Value are the byte-layout schemas the codec understands.
	Key   Schema
	Value Schema

	// HashOfMaps marks this entry as a HASH_OF_MAPS. When true,
	// InnerKey/InnerValue/InnerProto must also be set.
	HashOfMaps bool

	// InnerKey/InnerValue describe the inner map's layout. Used both
	// to advertise the schema and to decode entries on dump.
	InnerKey   Schema
	InnerValue Schema

	// InnerProto holds the prototype MapSpec (from bpf2go's MapSpecs)
	// for the inner map. The daemon derives MaxEntries from it.
	InnerProto *ebpf.MapSpec
}

// Inventory is a name-keyed registry of Descriptors. Empty values are
// rejected by Register so the daemon refuses to start with a broken
// descriptor table.
type Inventory struct {
	byName map[string]*Descriptor
	order  []string
}

// NewInventory returns an empty Inventory. Use Register to populate.
func NewInventory() *Inventory {
	return &Inventory{byName: make(map[string]*Descriptor)}
}

// Register adds d to the inventory. Returns an error when the name
// is already taken, when the schema width does not match the live
// map's key/value size, or when required fields are missing.
//
// Schema-vs-map width verification is the load-bearing check: a
// mismatch means the daemon would happily decode the wrong bytes,
// silently producing garbage. Bail out at startup instead.
func (inv *Inventory) Register(d *Descriptor) error {
	if d == nil {
		return errors.New("mapinventory: nil descriptor")
	}
	if d.Name == "" {
		return errors.New("mapinventory: descriptor missing Name")
	}
	if _, dup := inv.byName[d.Name]; dup {
		return fmt.Errorf("mapinventory: %q already registered", d.Name)
	}
	if d.Map == nil {
		return fmt.Errorf("mapinventory: %q missing Map handle", d.Name)
	}
	if d.HashOfMaps {
		if d.InnerProto == nil {
			return fmt.Errorf("mapinventory: %q missing InnerProto", d.Name)
		}
		if len(d.InnerKey.Fields) == 0 || len(d.InnerValue.Fields) == 0 {
			return fmt.Errorf("mapinventory: %q missing InnerKey/InnerValue", d.Name)
		}
	}

	keyW := uint32(d.Key.Width())
	valW := uint32(d.Value.Width())

	info, err := d.Map.Info()
	if err != nil {
		return fmt.Errorf("%q: read map info: %w", d.Name, err)
	}
	if info.KeySize != keyW {
		return fmt.Errorf("%w: %q key schema=%d bytes, map=%d", ErrSchemaMismatch, d.Name, keyW, info.KeySize)
	}
	// HASH_OF_MAPS values are u32 fd handles in the kernel; the inner
	// schema's width must match the inner proto's value size, not the
	// outer's. cilium/ebpf reports the outer ValueSize as 4 (the
	// inner-fd size), so we skip the outer ValueSize check for
	// HASH_OF_MAPS and verify the inner side.
	if d.HashOfMaps {
		if d.InnerProto.KeySize != uint32(d.InnerKey.Width()) {
			return fmt.Errorf("%w: %q inner key schema=%d bytes, proto=%d",
				ErrSchemaMismatch, d.Name, d.InnerKey.Width(), d.InnerProto.KeySize)
		}
		if d.InnerProto.ValueSize != uint32(d.InnerValue.Width()) {
			return fmt.Errorf("%w: %q inner value schema=%d bytes, proto=%d",
				ErrSchemaMismatch, d.Name, d.InnerValue.Width(), d.InnerProto.ValueSize)
		}
	} else {
		if info.ValueSize != valW {
			return fmt.Errorf("%w: %q value schema=%d bytes, map=%d", ErrSchemaMismatch, d.Name, valW, info.ValueSize)
		}
	}

	inv.byName[d.Name] = d
	inv.order = append(inv.order, d.Name)
	return nil
}

// Lookup returns the descriptor for name. Returns ErrMapNotFound
// when missing.
func (inv *Inventory) Lookup(name string) (*Descriptor, error) {
	if inv == nil {
		return nil, ErrMapNotFound
	}
	d, ok := inv.byName[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrMapNotFound, name)
	}
	return d, nil
}

// Names returns the registered map names in registration order. Used
// for iteration and for ListBPFMaps response stability.
func (inv *Inventory) Names() []string {
	out := make([]string, len(inv.order))
	copy(out, inv.order)
	return out
}

// SchemaProto serialises one descriptor into the wire form. Padding
// fields are dropped so kubectl never sees them.
func SchemaProto(d *Descriptor) *debugpb.BPFMapSchema {
	info, _ := d.Map.Info()
	maxEntries := uint32(0)
	if info != nil {
		maxEntries = info.MaxEntries
	}
	out := &debugpb.BPFMapSchema{
		Name:       d.Name,
		Kind:       mapTypeName(info),
		MaxEntries: maxEntries,
		KeySchema:  fieldsToProto(d.Key.userVisibleFields()),
		ValueSchema: func() []*debugpb.BPFMapFieldSchema {
			if d.HashOfMaps {
				return nil
			}
			return fieldsToProto(d.Value.userVisibleFields())
		}(),
		RequiresInnerKey: d.HashOfMaps,
	}
	if d.HashOfMaps {
		out.InnerKeySchema = fieldsToProto(d.InnerKey.userVisibleFields())
		out.InnerValueSchema = fieldsToProto(d.InnerValue.userVisibleFields())
	}
	return out
}

func fieldsToProto(fs []Field) []*debugpb.BPFMapFieldSchema {
	out := make([]*debugpb.BPFMapFieldSchema, 0, len(fs))
	for _, f := range fs {
		out = append(out, &debugpb.BPFMapFieldSchema{
			Name:        f.Name,
			Type:        fieldTypeName(f),
			Description: f.Description,
		})
	}
	return out
}

func fieldTypeName(f Field) string {
	switch f.Type {
	case FieldU8:
		return "u8"
	case FieldU16:
		return "u16"
	case FieldU32:
		return "u32"
	case FieldU64:
		return "u64"
	case FieldIPv4:
		return "ipv4"
	case FieldIPv4BE:
		return "ipv4be"
	case FieldPort:
		return "port"
	case FieldPortBE:
		return "portbe"
	case FieldU16BE:
		return "u16be"
	case FieldMAC:
		return "mac"
	case FieldEnum:
		if f.Enum != nil {
			return "enum:" + f.Enum.Name
		}
		return "enum"
	case FieldFlags:
		if f.Flags != nil {
			return "flags:" + f.Flags.Name
		}
		return "flags"
	case FieldRaw:
		return fmt.Sprintf("raw:%d", f.Width)
	case FieldPad:
		return "pad"
	}
	return "unknown"
}

func mapTypeName(info *ebpf.MapInfo) string {
	if info == nil {
		return "UNKNOWN"
	}
	return info.Type.String()
}
