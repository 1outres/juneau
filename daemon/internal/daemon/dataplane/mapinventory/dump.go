package mapinventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

// EntryEmitter is the callback DumpMap drives once per matched entry.
// Returning an error stops the iteration and propagates the error to
// the caller. The grpc-side handler implements this by sending the
// proto on the server stream.
type EntryEmitter func(*debugpb.BPFMapEntry) error

// DumpOptions tweaks DumpMap behaviour. KeyFilter and InnerKey are
// the same shape as the gRPC request fields. Limit is the per-call
// cap; 0 disables the cap, non-zero stops emission once Limit
// matches have been delivered.
type DumpOptions struct {
	KeyFilter []*debugpb.BPFMapField
	InnerKey  []*debugpb.BPFMapField
	Limit     uint32
}

// DumpMap iterates one descriptor and invokes emit for each entry that
// matches the filter. The iteration honours ctx cancellation between
// entries so a long scan exits promptly.
//
// Behaviour by map shape:
//
//   - Plain HASH/LRU_HASH/ARRAY: Iterate the map. If the filter covers
//     every key field, fall through to a single Lookup instead.
//   - LPM_TRIE: same as plain HASH; entries are returned with their
//     stored prefix lengths.
//   - HASH_OF_MAPS: InnerKey must resolve to a programmed inner map.
//     The inner is opened, iterated, and closed. The outer key fields
//     are echoed as part of the response so kubectl can render them.
func DumpMap(ctx context.Context, d *Descriptor, opts DumpOptions, emit EntryEmitter) error {
	if d == nil {
		return ErrMapNotFound
	}

	if d.HashOfMaps {
		return dumpHashOfMaps(ctx, d, opts, emit)
	}
	return dumpFlat(ctx, d, opts, emit)
}

func dumpFlat(ctx context.Context, d *Descriptor, opts DumpOptions, emit EntryEmitter) error {
	if err := ValidateFilter(d.Key, opts.KeyFilter); err != nil {
		return err
	}

	emitted := uint32(0)
	emitOne := func(rawKey, rawVal []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !MatchesFilter(d.Key, rawKey, opts.KeyFilter) {
			return nil
		}
		entry := &debugpb.BPFMapEntry{
			Key:   DecodeFields(d.Key, rawKey),
			Value: DecodeFields(d.Value, rawVal),
		}
		if err := emit(entry); err != nil {
			return err
		}
		emitted++
		return nil
	}

	if FilterCoversKey(d.Key, opts.KeyFilter) {
		// Fast path: build the key bytes and Lookup once.
		key, err := EncodeFields(d.Key, opts.KeyFilter)
		if err != nil {
			return err
		}
		val := make([]byte, d.Value.Width())
		if err := d.Map.Lookup(key, val); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return fmt.Errorf("lookup %s: %w", d.Name, err)
		}
		return emitOne(key, val)
	}

	return iterateFlat(d.Map, d.Key.Width(), d.Value.Width(), opts.Limit, func(k, v []byte) (bool, error) {
		if err := emitOne(k, v); err != nil {
			return false, err
		}
		if opts.Limit != 0 && emitted >= opts.Limit {
			return false, nil
		}
		return true, nil
	})
}

func dumpHashOfMaps(ctx context.Context, d *Descriptor, opts DumpOptions, emit EntryEmitter) error {
	if len(opts.InnerKey) == 0 {
		return ErrInnerKeyMissing
	}
	if err := ValidateFilter(d.Key, opts.InnerKey); err != nil {
		return err
	}
	if !FilterCoversKey(d.Key, opts.InnerKey) {
		return fmt.Errorf("%w: every outer key field is required", ErrInnerKeyMissing)
	}
	if err := ValidateFilter(d.InnerKey, opts.KeyFilter); err != nil {
		return err
	}

	outerKey, err := EncodeFields(d.Key, opts.InnerKey)
	if err != nil {
		return err
	}

	var innerID ebpf.MapID
	if err := d.Map.Lookup(outerKey, &innerID); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ErrInnerKeyInvalid
		}
		return fmt.Errorf("lookup outer %s: %w", d.Name, err)
	}
	inner, err := ebpf.NewMapFromID(innerID)
	if err != nil {
		return fmt.Errorf("open inner map (id=%d): %w", innerID, err)
	}
	defer inner.Close()

	emitted := uint32(0)
	return iterateFlat(inner, d.InnerKey.Width(), d.InnerValue.Width(), opts.Limit, func(k, v []byte) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if !MatchesFilter(d.InnerKey, k, opts.KeyFilter) {
			return true, nil
		}
		entry := &debugpb.BPFMapEntry{
			Key: append(
				DecodeFields(d.Key, outerKey),
				DecodeFields(d.InnerKey, k)...,
			),
			Value: DecodeFields(d.InnerValue, v),
		}
		if err := emit(entry); err != nil {
			return false, err
		}
		emitted++
		if opts.Limit != 0 && emitted >= opts.Limit {
			return false, nil
		}
		return true, nil
	})
}

// iterateFlat walks every entry of m using the cilium/ebpf MapIterator.
// The cb returns (continue, error). Iteration order is implementation
// defined (HASH/LRU_HASH/LPM_TRIE all share this iteration semantics).
func iterateFlat(m *ebpf.Map, keyW, valW int, _ uint32, cb func(k, v []byte) (bool, error)) error {
	key := make([]byte, keyW)
	val := make([]byte, valW)

	it := m.Iterate()
	for it.Next(&key, &val) {
		cont, err := cb(key, val)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate: %w", err)
	}
	return nil
}
