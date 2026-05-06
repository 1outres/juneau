package bpf

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/1outres/juneau/kubectl-juneau/internal/bpfmap"
	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
	"github.com/1outres/juneau/kubectl-juneau/internal/output"
)

type listOptions struct {
	Factory    factory.Factory
	PrintFlags *output.PrintFlags

	Node     string
	AllNodes bool
}

func newListCommand(f factory.Factory) *cobra.Command {
	o := &listOptions{Factory: f, PrintFlags: output.NewPrintFlags()}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List BPF maps the daemon exposes (with key/value schema)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run(c.Context())
		},
	}
	cmd.Flags().StringVar(&o.Node, "node", "", "Query a single node only.")
	cmd.Flags().BoolVar(&o.AllNodes, "all-nodes", false, "Query every node and report schema drift if any.")
	o.PrintFlags.AddFlags(cmd)
	return cmd
}

func (o *listOptions) Validate() error {
	if o.Node != "" && o.AllNodes {
		return fmt.Errorf("--node and --all-nodes are mutually exclusive")
	}
	_, err := o.PrintFlags.Format()
	return err
}

func (o *listOptions) Run(ctx context.Context) error {
	cli := bpfmap.NewFactoryClient(o.Factory)

	nodes, err := o.resolveNodes(ctx, cli)
	if err != nil {
		return err
	}

	per, warnings := bpfmap.AggregateListMaps(ctx, cli, nodes)
	res := bpfmap.ListResult{
		Nodes:    nodes,
		PerNode:  per,
		Warnings: warnings,
	}

	renderer, err := output.ResolveRenderer[bpfmap.ListResult](
		o.PrintFlags,
		output.RendererFunc[bpfmap.ListResult](func(w io.Writer, r bpfmap.ListResult) error {
			return bpfmap.RenderListTree(w, r)
		}),
	)
	if err != nil {
		return err
	}
	if err := renderer.Render(o.Factory.Streams().Out, res); err != nil {
		return err
	}
	for _, w := range warnings {
		_, _ = fmt.Fprintf(o.Factory.Streams().ErrOut, "warning: node %s: %v\n", w.Node, w.Err)
	}
	return nil
}

// resolveNodes picks the list of nodes to query. Default behaviour is
// "all nodes"; --node restricts to one. Unlike trace, list is cheap
// per node so all-nodes is a sensible default.
func (o *listOptions) resolveNodes(ctx context.Context, cli bpfmap.Client) ([]string, error) {
	if o.Node != "" {
		return []string{o.Node}, nil
	}
	return cli.ListNodes(ctx)
}
