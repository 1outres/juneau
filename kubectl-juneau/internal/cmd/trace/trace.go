// Package trace implements `kubectl juneau trace`, the operator-
// facing command that drives a TraceSession across the cluster's
// juneaud daemons and renders the resulting event timeline.
//
// The command is intentionally ephemeral: a TraceSession CRD is
// created on entry, daemons program local BPF state in response, the
// command streams events back, and the CRD is deleted on exit
// (defer + signal handler). Persistent flavours (--keep-session,
// --output-file) are explicit opt-ins.
package trace

import (
	"github.com/spf13/cobra"

	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
)

// NewCommand returns the trace command with its flag surface
// configured. The actual work lives in run.go; this file only wires
// cobra and the option struct.
func NewCommand(f factory.Factory) *cobra.Command {
	o := newOptions(f)
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace a packet through the Juneau dataplane",
		Long: `trace creates a temporary TraceSession, programs local BPF state on
every juneaud, and streams decision-point events back to your terminal.
Use it to answer:

  - did the packet enter the dataplane?
  - which eBPF hooks did it pass?
  - which maps / policies / NAT paths were consulted?
  - where was it redirected, or where did it drop and why?

The default workflow is fully ephemeral: the TraceSession is deleted on
exit and daemons remove all per-session BPF entries. Persistent
behaviour requires explicit opt-in (--keep-session / --output-file).

Examples:

  # Watch real traffic from a Pod to a Service. ObserveOnly is the
  # safe default for production.
  kubectl juneau trace pod default/client \
    --to service default/api --proto tcp --port 443 --observe-only

  # Trace by raw 5-tuple (no Kubernetes objects on either side).
  kubectl juneau trace --from-ip 10.0.1.10 --to-ip 10.0.2.8 \
    --proto udp --port 53 --observe-only

  # Trace a second NIC. --interface says which network the Pod is on
  # there, and the addresses say what to follow: an L2Network without
  # a CIDR hands out none, so the workload picked them and only you
  # know what they are.
  kubectl juneau trace --from-pod default/lab-a --interface eth1 \
    --from-ip 192.168.60.1 \
    --to-pod default/lab-b --to-interface eth1 --to-ip 192.168.60.2 \
    --proto icmp`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run(c.Context())
		},
	}
	o.AddFlags(cmd)
	return cmd
}
