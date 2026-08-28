// Package bpftest runs the generated eBPF objects against packets a
// test builds by hand.
//
// The data plane has parts whose behaviour is state, not arithmetic:
// what a segment has learned, which ports a frame was copied to,
// whether a frame that came in over the overlay was sent back out.
// From an end-to-end test those can only be guessed at through packet
// counters. Here a test says what is in the maps, hands the program one
// frame, and reads back both the verdict and the maps.
//
// The kernel runs the program for real, so every helper it calls runs
// for real too. bpf_clone_redirect really hands a copy to the device it
// names, which is why the tests build devices of their own and count
// what arrives on them. bpf_redirect is the exception: BPF_PROG_TEST_RUN
// stops at the verdict and never carries the frame out, so a test can
// see that a program chose to redirect but not where to. Where that
// matters, put exactly one candidate in the map and let the verdict
// speak.
//
// Everything here needs root: loading a program, minting a map and
// building a network device all do. Call Require first and the test
// skips instead of failing where that is not true.
package bpftest

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TC verdicts, so a test can name what a program returned instead of
// comparing numbers.
const (
	ActOK       = 0
	ActShot     = 2
	ActRedirect = 7
)

// Require skips the test unless this process can load BPF objects and
// build network devices. Both need root, and the packet tests are slow
// enough to be worth leaving out of a short run.
func Require(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("bpftest: skipped in short mode; it loads BPF programs and builds network devices")
	}
	if os.Geteuid() != 0 {
		t.Skip("bpftest: needs root to load BPF programs and build network devices")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("bpftest: cannot lift the memlock limit: %v", err)
	}
}

// Objects is one generated object file loaded into the kernel with
// maps of its own.
type Objects struct {
	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection
}

// Load builds a fresh copy of one generated object. Pinning is
// stripped first: the daemon shares maps between programs by pinning
// them under one path, and a test that did the same would inherit
// whatever a previous test — or a daemon on this host — had left in
// them.
func Load(t *testing.T, load func() (*ebpf.CollectionSpec, error)) *Objects {
	t.Helper()

	spec, err := load()
	if err != nil {
		t.Fatalf("bpftest: read the object: %v", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("bpftest: load the object: %+v", err)
	}
	t.Cleanup(collection.Close)

	return &Objects{spec: spec, collection: collection}
}

// Program returns the program of the given name.
func (o *Objects) Program(t *testing.T, name string) *ebpf.Program {
	t.Helper()
	prog, ok := o.collection.Programs[name]
	if !ok {
		t.Fatalf("bpftest: the object has no program %q", name)
	}
	return prog
}

// Map returns the map of the given name.
func (o *Objects) Map(t *testing.T, name string) *ebpf.Map {
	t.Helper()
	m, ok := o.collection.Maps[name]
	if !ok {
		t.Fatalf("bpftest: the object has no map %q", name)
	}
	return m
}

// MapSpec returns a copy of the layout of a map, which is what the
// per-VNI tables mint their inner maps from.
func (o *Objects) MapSpec(t *testing.T, name string) *ebpf.MapSpec {
	t.Helper()
	spec, ok := o.spec.Maps[name]
	if !ok {
		t.Fatalf("bpftest: the object has no map %q", name)
	}
	return spec.Copy()
}
