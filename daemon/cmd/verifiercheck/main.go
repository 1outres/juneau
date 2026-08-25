// Command verifiercheck loads every eBPF object the daemon attaches
// into the running kernel and reports what the verifier had to do with
// it.
//
// It answers one question: do these programs load at all. The
// verifier walks at most 1,000,000 instructions per program, and the
// data plane is close enough to that ceiling that a small change can
// go over it. Nothing in the build catches that, so without this
// command the first sign is a daemon in crashloop on a cluster.
//
// Usage:
//
//	make -C daemon generate-bpf
//	cd daemon && go build -o /tmp/verifiercheck ./cmd/verifiercheck
//	sudo /tmp/verifiercheck
//
// Root is required (BPF_PROG_LOAD and pinning need CAP_BPF and
// CAP_SYS_ADMIN) and bpffs has to be mounted. The maps are pinned in a
// directory of the command's own, which must not exist yet and is
// removed at the end, so a daemon running on the same host keeps its
// maps.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cilium/ebpf/rlimit"
)

// defaultPinDir is deliberately not the daemon's pin path. The run
// deletes this directory when it finishes.
const defaultPinDir = "/sys/fs/bpf/juneau-verifiercheck"

func main() {
	pinDir := flag.String("pin-dir", defaultPinDir,
		"directory to pin the maps in. It must not exist yet: the run creates it and removes it again. Never point this at the pin path of a running daemon.")
	flag.Parse()

	if err := run(os.Stdout, *pinDir); err != nil {
		fmt.Fprintln(os.Stderr, "verifiercheck:", err)
		os.Exit(1)
	}
}

// run reports a failure to remove the pin dir alongside the verifier
// result. Pins left behind make the next run refuse to start, so it is
// not something to print and move on from.
func run(w io.Writer, pinDir string) (err error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("raise the memlock limit: %w", err)
	}
	if err := createPinDir(pinDir); err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, removePinDir(pinDir))
	}()

	var rejected []string
	for _, t := range targets() {
		report := checkTarget(t, pinDir)
		if err := writeReport(w, report); err != nil {
			return fmt.Errorf("report on %s: %w", t.name, err)
		}
		if report.err != nil {
			rejected = append(rejected, t.name)
		}
	}
	if len(rejected) > 0 {
		return fmt.Errorf("%s did not load", strings.Join(rejected, ", "))
	}
	return nil
}
