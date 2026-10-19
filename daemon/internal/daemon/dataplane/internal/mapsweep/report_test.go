package mapsweep

import (
	"errors"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func logged(t *testing.T, r Report) observer.LoggedEntry {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	restore := zap.ReplaceGlobals(zap.New(core))
	defer restore()

	r.Log("test gc")

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("logged %d lines, want one", len(entries))
	}
	return entries[0]
}

func TestReportOfAHealthyPassIsADebugLine(t *testing.T) {
	entry := logged(t, Report{
		Map:    "some_map",
		Stats:  Stats{Capacity: 100, Read: 79, Removed: map[Reason]int{"expired": 3}, Kept: 1},
		Fields: []any{"vni", 7},
	})

	if entry.Level != zapcore.DebugLevel {
		t.Errorf("level = %s, want debug", entry.Level)
	}
	want := map[string]any{
		"map":              "some_map",
		"capacity":         uint32(100),
		"read":             int64(79),
		"kept":             int64(1),
		"occupancyPercent": 79.0,
		"vni":              int64(7),
	}
	fields := entry.ContextMap()
	for key, value := range want {
		if fields[key] != value {
			t.Errorf("%s = %#v, want %#v", key, fields[key], value)
		}
	}
	if removed, ok := fields["removed"].(map[Reason]int); !ok || removed["expired"] != 3 {
		t.Errorf("removed = %#v, want the counts by reason", fields["removed"])
	}
}

// A HASH map that fills up refuses new keys, so the warning has to
// come while there is still room.
func TestReportOfANearlyFullMapIsAWarning(t *testing.T) {
	entry := logged(t, Report{Map: "some_map", Stats: Stats{Capacity: 100, Read: 80}})
	if entry.Level != zapcore.WarnLevel {
		t.Errorf("level = %s, want warn", entry.Level)
	}
}

func TestReportWithAWarningOfTheCallerIsAWarning(t *testing.T) {
	entry := logged(t, Report{Map: "some_map", Stats: Stats{Capacity: 100}, Warnings: []string{"something broke"}})
	if entry.Level != zapcore.WarnLevel {
		t.Errorf("level = %s, want warn", entry.Level)
	}
}

func TestReportOfAFailedPassIsAWarning(t *testing.T) {
	entry := logged(t, Report{Map: "some_map", Stats: Stats{Capacity: 100}, Err: errors.New("boom")})
	if entry.Level != zapcore.WarnLevel {
		t.Errorf("level = %s, want warn", entry.Level)
	}
	if _, ok := entry.ContextMap()["err"]; !ok {
		t.Error("the line does not carry the error")
	}
}
