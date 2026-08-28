package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleLog = "processed 662664 insns (limit 1000000) max_states_per_insn 53 " +
	"total_states 26990 peak_states 5921 mark_read 0\n"

func TestParseStatsReadsTheCounters(t *testing.T) {
	got, err := parseStats(sampleLog)
	if err != nil {
		t.Fatalf("parseStats: %v", err)
	}
	if got.processed != 662664 {
		t.Errorf("processed=%d, want 662664", got.processed)
	}
	if got.limit != 1000000 {
		t.Errorf("limit=%d, want 1000000", got.limit)
	}
}

func TestParseStatsRejectsALogWithoutTheCounters(t *testing.T) {
	// Reporting a made-up number would hide the one thing this command
	// exists to report, so a log the kernel words differently is an
	// error.
	if _, err := parseStats("func#0 @0\n0: R1=ctx()\n"); err == nil {
		t.Fatal("parseStats accepted a log with no instruction count")
	}
}

func TestCreatePinDirRefusesAnExistingPath(t *testing.T) {
	// Removing a directory this run did not create could take out the
	// pinned maps of a running daemon.
	path := t.TempDir()

	err := createPinDir(path)
	if err == nil {
		t.Fatal("createPinDir accepted a path that already exists")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the path", err)
	}
}

func TestCreatePinDirCreatesAndRemoves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins")

	if err := createPinDir(path); err != nil {
		t.Fatalf("createPinDir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat after createPinDir: %v", err)
	}

	if err := removePinDir(path); err != nil {
		t.Fatalf("removePinDir: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat after removePinDir = %v, want not-exist", err)
	}
}

func TestWriteReportShowsTheInstructionCount(t *testing.T) {
	var out strings.Builder

	err := writeReport(&out, targetReport{
		target: "pod_egress",
		programs: []programReport{
			{name: "tc_pod_egress", stats: verifierStats{processed: 662664, limit: 1000000}},
		},
	})
	if err != nil {
		t.Fatalf("writeReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{"pod_egress", "tc_pod_egress", "662664", "1000000"} {
		if !strings.Contains(got, want) {
			t.Errorf("report %q does not mention %q", got, want)
		}
	}
}

func TestWriteReportShowsTheFailure(t *testing.T) {
	var out strings.Builder

	err := writeReport(&out, targetReport{
		target: "pod_egress",
		err:    errors.New("BPF program is too large. Processed 1000001 insn"),
	})
	if err != nil {
		t.Fatalf("writeReport: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "BPF program is too large") {
		t.Errorf("report %q does not carry the load error", got)
	}
}

func TestTargetsCoverEveryAttachedProgram(t *testing.T) {
	// A program missing from this list is a program nobody checks
	// before it reaches a cluster.
	want := []string{"pod_egress", "pod_ingress", "vxlan_ingress", "node_ingress", "l2_egress", "l2_ingress"}

	got := make([]string, 0, len(targets()))
	for _, tg := range targets() {
		got = append(got, tg.name)
	}

	if len(got) != len(want) {
		t.Fatalf("targets=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("targets[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}
