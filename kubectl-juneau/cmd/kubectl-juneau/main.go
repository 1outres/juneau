// kubectl-juneau is the kubectl plugin entrypoint for Juneau
// troubleshooting commands. The binary name is intentionally
// `kubectl-juneau` so that invoking `kubectl juneau ...` resolves to
// this executable through kubectl's plugin discovery mechanism.
//
// All command logic lives under internal/. main.go only owns process
// boundaries (argv, IOStreams, exit codes).
package main

import (
	"os"

	"k8s.io/cli-runtime/pkg/genericiooptions"

	rootcmd "github.com/1outres/juneau/kubectl-juneau/internal/cmd"
)

func main() {
	streams := genericiooptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}
	if err := rootcmd.NewRootCommand(streams).Execute(); err != nil {
		// Cobra has already printed the error via SilenceErrors=false.
		os.Exit(1)
	}
}
