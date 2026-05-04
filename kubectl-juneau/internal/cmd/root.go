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

	describecmd "github.com/1outres/juneau/kubectl-juneau/internal/cmd/describe"
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

Future tiers will add data-plane (BPF map / CT) and reachability commands.`,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
	}
	configFlags.AddFlags(root.PersistentFlags())

	root.AddCommand(versioncmd.NewCommand(f))
	root.AddCommand(describecmd.NewCommand(f))
	return root
}
