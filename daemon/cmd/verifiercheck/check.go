package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// target is one generated object file the check loads. The daemon
// attaches all of them, so all of them have to pass the verifier.
type target struct {
	name string
	load func() (*ebpf.CollectionSpec, error)
}

// targets lists every eBPF object the data plane loads. Keep it in
// step with dataplane/program.
func targets() []target {
	return []target{
		{name: "pod_egress", load: bpf.LoadPodEgress},
		{name: "pod_ingress", load: bpf.LoadPodIngress},
		{name: "vxlan_ingress", load: bpf.LoadVxlanIngress},
		{name: "node_ingress", load: bpf.LoadNodeIngress},
	}
}

// verifierStats is what the verifier reports about one program: how
// many instructions it walked, and how many it was allowed to walk.
// The distance between the two is the headroom left for new code.
type verifierStats struct {
	processed int
	limit     int
}

// programReport is the outcome for one program inside a target.
type programReport struct {
	name  string
	stats verifierStats
}

// targetReport is the outcome for one object file. err is the load
// error exactly as the kernel and cilium/ebpf produced it: it is never
// wrapped, because a wrapped *ebpf.VerifierError prints without the
// log lines that say which instruction was rejected.
type targetReport struct {
	target   string
	programs []programReport
	err      error
}

// statsPattern matches the summary line the verifier prints at
// LogLevelStats.
var statsPattern = regexp.MustCompile(`processed (\d+) insns \(limit (\d+)\)`)

// parseStats pulls the instruction counts out of a verifier log.
// A log without that line means the kernel words the summary
// differently than expected, and reporting a number that was not read
// would defeat the point of the command.
func parseStats(log string) (verifierStats, error) {
	m := statsPattern.FindStringSubmatch(log)
	if m == nil {
		return verifierStats{}, errors.New("verifier log has no \"processed N insns (limit M)\" line")
	}
	processed, err := strconv.Atoi(m[1])
	if err != nil {
		return verifierStats{}, fmt.Errorf("read the instruction count %q: %w", m[1], err)
	}
	limit, err := strconv.Atoi(m[2])
	if err != nil {
		return verifierStats{}, fmt.Errorf("read the instruction limit %q: %w", m[2], err)
	}
	return verifierStats{processed: processed, limit: limit}, nil
}

// checkTarget loads one object into the kernel and reports what the
// verifier had to do. The collection is closed again right away: this
// command only answers "does it load", never "does it work".
func checkTarget(t target, pinDir string) targetReport {
	report := targetReport{target: t.name}

	spec, err := t.load()
	if err != nil {
		report.err = err
		return report
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps:     ebpf.MapOptions{PinPath: pinDir},
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		report.err = err
		return report
	}
	defer coll.Close()

	for name, prog := range coll.Programs {
		stats, err := parseStats(prog.VerifierLog)
		if err != nil {
			report.err = fmt.Errorf("program %s: %w", name, err)
			return report
		}
		report.programs = append(report.programs, programReport{name: name, stats: stats})
	}
	slices.SortFunc(report.programs, func(a, b programReport) int {
		return cmp.Compare(a.name, b.name)
	})
	return report
}

func writeReport(w io.Writer, report targetReport) error {
	if report.err != nil {
		if _, err := fmt.Fprintf(w, "FAIL %s\n", report.target); err != nil {
			return err
		}
		return writeLoadError(w, report.err)
	}
	for _, prog := range report.programs {
		_, err := fmt.Fprintf(w, "OK   %s: %s processed %d insns (limit %d, %.1f%% used)\n",
			report.target, prog.name, prog.stats.processed, prog.stats.limit,
			prog.stats.usage())
		if err != nil {
			return err
		}
	}
	return nil
}

// usage is the share of the verifier budget the program spent.
func (s verifierStats) usage() float64 {
	if s.limit == 0 {
		return 0
	}
	return float64(s.processed) / float64(s.limit) * 100
}

// writeLoadError prints a load failure in full. A *ebpf.VerifierError
// only prints the rejected instruction and the lines around it under
// %+v; %v cuts the log down to the last few lines and drops exactly
// the part worth reading.
func writeLoadError(w io.Writer, err error) error {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		_, writeErr := fmt.Fprintf(w, "%+v\n", verr)
		return writeErr
	}
	_, writeErr := fmt.Fprintf(w, "%v\n", err)
	return writeErr
}

// createPinDir makes the directory the run pins its maps in. The path
// must not exist yet, because removePinDir deletes it afterwards and
// deleting a directory this run did not create could take out the
// pinned maps of a running daemon.
func createPinDir(path string) error {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return fmt.Errorf("pin dir %s already exists: pass a path this run can create and delete on its own", path)
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("stat pin dir %s: %w", path, err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create pin dir %s: %w", path, err)
	}
	return nil
}

func removePinDir(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove pin dir %s: %w", path, err)
	}
	return nil
}
