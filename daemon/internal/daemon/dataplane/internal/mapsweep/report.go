package mapsweep

import (
	"math"
	"slices"

	"go.uber.org/zap"
)

// NearlyFull is the occupancy from which a pass is logged as a
// warning. A HASH map that fills up refuses new keys, so the warning
// has to come while there is still room.
const NearlyFull = 0.8

// Report is the log line about one pass over one map.
type Report struct {
	// Map names the map in the line.
	Map   string
	Stats Stats
	// Err is what stopped the pass, if anything did.
	Err error
	// Fields are more key-value pairs for the line.
	Fields []any
	// Warnings are problems the caller found that Stats does not show.
	Warnings []string
}

// Log writes the report as one line. It is a warning when the pass
// failed, when the map is nearly full, or when the caller added a
// warning. Otherwise it is a debug line: the sweeps run every few
// seconds, and a healthy pass is not news.
func (r Report) Log(component string) {
	occupancy := r.Stats.Occupancy()
	fields := []any{
		"map", r.Map,
		"capacity", r.Stats.Capacity,
		"read", r.Stats.Read,
		"removed", r.Stats.Removed,
		"kept", r.Stats.Kept,
		"occupancyPercent", math.Round(occupancy*1000) / 10,
	}
	fields = append(fields, r.Fields...)

	warnings := slices.Clone(r.Warnings)
	if occupancy >= NearlyFull {
		warnings = append(warnings, "map nearly full")
	}
	if len(warnings) > 0 {
		fields = append(fields, "warnings", warnings)
	}

	switch {
	case r.Err != nil:
		zap.S().Warnw(component+": sweep failed", append(fields, "err", r.Err)...)
	case len(warnings) > 0:
		zap.S().Warnw(component+": swept", fields...)
	default:
		zap.S().Debugw(component+": swept", fields...)
	}
}
