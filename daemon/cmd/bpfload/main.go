package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

func tryLoad(name string, fn func() (*ebpf.CollectionSpec, error)) {
	fmt.Printf("=== %s ===\n", name)
	spec, err := fn()
	if err != nil {
		fmt.Printf("  spec load failed: %v\n", err)
		return
	}
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "bpfload-*")
	if err != nil {
		fmt.Printf("  mktemp error: %v\n", err)
		return
	}
	defer os.RemoveAll(pinDir)
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps:     ebpf.MapOptions{PinPath: pinDir},
		Programs: ebpf.ProgramOptions{LogDisabled: true},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("  verifier error: %s\n", verr.Error())
			for _, line := range verr.Log {
				fmt.Println("    " + line)
			}
		} else {
			fmt.Printf("  load error (type %T): %+v\n", err, err)
			// Try loading each program individually to localize the failure
			for progName, progSpec := range spec.Programs {
				prog, perr := ebpf.NewProgramWithOptions(progSpec, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction, LogSizeStart: 1 << 24})
				if perr == nil {
					fmt.Printf("    [program %s OK]\n", progName)
					prog.Close()
					continue
				}
				var pverr *ebpf.VerifierError
				if errors.As(perr, &pverr) {
					fmt.Printf("    [program %s] verifier error:\n", progName)
					for _, line := range pverr.Log {
						fmt.Println("      " + line)
					}
				} else {
					fmt.Printf("    [program %s] error (type %T): %+v\n", progName, perr, perr)
				}
			}
		}
		return
	}
	defer coll.Close()
	fmt.Printf("  OK\n")
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Printf("rlimit error: %v\n", err)
		os.Exit(1)
	}
	tryLoad("PodEgress", bpf.LoadPodEgress)
	tryLoad("PodIngress", bpf.LoadPodIngress)
	tryLoad("VxlanIngress", bpf.LoadVxlanIngress)
	tryLoad("NodeIngress", bpf.LoadNodeIngress)
}
