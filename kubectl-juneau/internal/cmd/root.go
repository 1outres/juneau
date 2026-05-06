// Package cmd assembles the cobra command tree for kubectl-juneau.
// The root command owns global flag wiring (kubeconfig, context, …)
// via cli-runtime's ConfigFlags so users get the exact same flag
// surface as kubectl itself, then delegates to leaf packages
// (describe/, version/, …) for actual work.
package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"

	bpfcmd "github.com/1outres/juneau/kubectl-juneau/internal/cmd/bpf"
	describecmd "github.com/1outres/juneau/kubectl-juneau/internal/cmd/describe"
	tracecmd "github.com/1outres/juneau/kubectl-juneau/internal/cmd/trace"
	versioncmd "github.com/1outres/juneau/kubectl-juneau/internal/cmd/version"
	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
)

// NewRootCommand returns the kubectl-juneau root command. The IOStreams
// argument lets tests intercept stdout/stderr.
func NewRootCommand(streams genericiooptions.IOStreams) *cobra.Command {
	configFlags := genericclioptions.NewConfigFlags(true)
	f := factory.New(configFlags, streams)

	root := &cobra.Command{
		Use:   "kubectl-juneau",
		Short: "Troubleshoot Juneau networking from kubectl",
		Long: `kubectl-juneau is a kubectl plugin for inspecting Juneau networking state.

Tier 1 commands focus on declarative state:
  describe  — show the resource chain attached to a Pod / Vpc / Subnet / Service / NetworkInterface
  version   — print build identity

Tier 2 (data-plane) commands talk to per-Node juneaud over portforward:
  trace     — drive a TraceSession and stream decision-point events
  bpf       — list and dump the BPF maps the daemon owns
`,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
	}
	configFlags.AddFlags(root.PersistentFlags())

	root.AddCommand(versioncmd.NewCommand(f))
	root.AddCommand(describecmd.NewCommand(f))
	root.AddCommand(tracecmd.NewCommand(f))
	root.AddCommand(bpfcmd.NewCommand(f))
	return root
}
