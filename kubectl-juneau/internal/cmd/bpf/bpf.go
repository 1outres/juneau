// Package bpf implements `kubectl juneau bpf`, the operator-facing
// command family for inspecting BPF maps the daemon owns. The parent
// command only registers children; per-kind logic lives in list.go
// and dump.go.
//
// Layered design:
//
//   - cmd/bpf/*.go              cobra wiring + flag parsing
//   - internal/bpfmap/          domain logic (gRPC client, fan-out,
//                               renderers).
//   - daemon/.../mapinventory   schema source of truth.
//
// Flow for `bpf dump`: cmd parses --filter → bpfmap.Client.DumpMap
// (per node) → per-Entry callback → renderer.
package bpf

import (
	"github.com/spf13/cobra"

	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
)

// NewCommand returns the bpf parent command with list and dump
// subcommands registered. Adding a new subcommand (e.g. `bpf stats`)
// is a one-line change here.
func NewCommand(f factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bpf",
		Short: "Inspect BPF maps owned by the Juneau daemon",
		Long: `bpf provides read-only access to the BPF maps the Juneau daemon
maintains on every node. Use ` + "`bpf list`" + ` to see the maps a daemon
exposes (with field schemas), and ` + "`bpf dump <map>`" + ` to stream entries.

The daemon publishes a schema for each map; kubectl renders entries
generically against that schema, so a new map added on the daemon
side becomes visible without a kubectl-juneau release.

Examples:

  # List every map and its key/value schema, aggregated across nodes.
  kubectl juneau bpf list

  # Dump the conntrack table on a specific node, filtered by VPC.
  kubectl juneau bpf dump ct_map --node worker-1 --filter scope=2

  # Dump a HASH_OF_MAPS inner table.
  kubectl juneau bpf dump fib_map --inner-key table_id=5
`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newListCommand(f))
	cmd.AddCommand(newDumpCommand(f))
	return cmd
}
