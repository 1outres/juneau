package grpc

import (
	"context"
	"errors"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/mapinventory"
	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

// DefaultMapDumpLimit caps DumpBPFMap when the client supplies 0.
// Picks a value that fits a reasonable terminal scroll buffer; users
// who want more pass --limit explicitly. The server-side ceiling is
// enforced even when the client supplies a non-zero value.
const DefaultMapDumpLimit uint32 = 4096

// MaxMapDumpLimit caps the maximum a client can request. Prevents a
// rogue client from forcing the daemon to walk an LRU map of 524k
// ct entries in one stream.
const MaxMapDumpLimit uint32 = 65536

// ListBPFMaps returns the descriptor schema for every registered map.
// Names are sorted lexicographically so the output is stable across
// daemon restarts.
func (d *DebugServer) ListBPFMaps(_ context.Context, _ *debugpb.ListBPFMapsRequest) (*debugpb.ListBPFMapsResponse, error) {
	if d.inv == nil {
		return nil, status.Error(codes.FailedPrecondition, "BPF map inventory not initialised")
	}
	names := d.inv.Names()
	sort.Strings(names)

	out := &debugpb.ListBPFMapsResponse{
		Maps: make([]*debugpb.BPFMapSchema, 0, len(names)),
	}
	for _, name := range names {
		desc, err := d.inv.Lookup(name)
		if err != nil {
			// inv.Names guarantees the name exists; defensive
			// fallthrough so a fluke doesn't crash the daemon.
			continue
		}
		out.Maps = append(out.Maps, mapinventory.SchemaProto(desc))
	}
	return out, nil
}

// DumpBPFMap streams entries to the client. Filter validation,
// inner-key handling, and the limit cap are all delegated to
// mapinventory; this handler is just transport plumbing.
func (d *DebugServer) DumpBPFMap(req *debugpb.DumpBPFMapRequest, srv debugpb.Debug_DumpBPFMapServer) error {
	if d.inv == nil {
		return status.Error(codes.FailedPrecondition, "BPF map inventory not initialised")
	}
	if req.GetName() == "" {
		return status.Error(codes.InvalidArgument, "map name is required")
	}
	desc, err := d.inv.Lookup(req.Name)
	if err != nil {
		return status.Errorf(codes.NotFound, "%v", err)
	}

	limit := req.GetLimit()
	if limit == 0 {
		limit = DefaultMapDumpLimit
	}
	if limit > MaxMapDumpLimit {
		limit = MaxMapDumpLimit
	}

	ctx := srv.Context()
	emit := func(entry *debugpb.BPFMapEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return srv.Send(entry)
	}

	err = mapinventory.DumpMap(ctx, desc, mapinventory.DumpOptions{
		KeyFilter: req.KeyFilter,
		InnerKey:  req.InnerKey,
		Limit:     limit,
	}, emit)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mapinventory.ErrUnknownField),
		errors.Is(err, mapinventory.ErrFieldType),
		errors.Is(err, mapinventory.ErrFieldOverflow):
		return status.Errorf(codes.InvalidArgument, "%v", err)
	case errors.Is(err, mapinventory.ErrInnerKeyMissing):
		return status.Errorf(codes.InvalidArgument, "%v", err)
	case errors.Is(err, mapinventory.ErrInnerKeyInvalid):
		return status.Errorf(codes.NotFound, "%v", err)
	case errors.Is(err, mapinventory.ErrMapNotFound):
		return status.Errorf(codes.NotFound, "%v", err)
	case errors.Is(err, context.Canceled):
		return nil
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

// SetMapInventory injects the descriptor table. Constructed off the
// debug server's lifecycle so the daemon can build the inventory from
// dataplane.Manager (which owns the BPF programs) and then attach it.
// Idempotent — calling twice replaces the previous inventory.
func (d *DebugServer) SetMapInventory(inv *mapinventory.Inventory) {
	d.inv = inv
}

// hasMapInventory reports whether SetMapInventory has been called.
func (d *DebugServer) hasMapInventory() bool { return d.inv != nil }
