// Package describe implements the `kubectl juneau describe` family of
// subcommands. Each kind (pod, vpc, subnet, service, networkinterface)
// is its own file so the cobra wiring + presenter for one kind stays
// isolated and easy to evolve.
//
// The parent command (this file) only registers children; it has no
// behaviour of its own. Adding a new kind is a one-line change here
// plus a new file with newXxxCommand and presentXxxTree.
package describe

import (
	"github.com/spf13/cobra"

	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
)

// NewCommand returns the parent describe command with all kinds wired
// up.
func NewCommand(f factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "describe",
		Short: "Describe Juneau networking context attached to a resource",
		Long: `Describe walks the Juneau resource graph rooted at the named object
and prints the connected Vpc / Subnet / RouteTable / NetworkACL /
SecurityGroup / NATGateway / ElasticIP context.

It is read-only and queries the Kubernetes API server only — no per-Node
BPF state is consulted. A future tier will add a --with-bpf flag that
augments the output with data-plane facts pulled from juneaud.`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newPodCommand(f))
	cmd.AddCommand(newVpcCommand(f))
	cmd.AddCommand(newSubnetCommand(f))
	cmd.AddCommand(newServiceCommand(f))
	cmd.AddCommand(newNetworkInterfaceCommand(f))
	cmd.AddCommand(newLoadBalancerCommand(f))
	return cmd
}
