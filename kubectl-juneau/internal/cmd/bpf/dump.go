package bpf

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/spf13/cobra"

	"github.com/1outres/juneau/kubectl-juneau/internal/bpfmap"
	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
	"github.com/1outres/juneau/kubectl-juneau/internal/output"
)

// formatTable is the default for `bpf dump`. Selecting it here
// instead of changing the global Format default keeps `describe`
// behaviour untouched.
const formatTable output.Format = "table"

type dumpOptions struct {
	Factory    factory.Factory
	PrintFlags *dumpPrintFlags

	MapName  string
	Node     string
	AllNodes bool
	Filter   []string
	InnerKey []string
	Limit    uint32
}

// dumpPrintFlags wraps output.PrintFlags so we can add the `table`
// format on top of the shared tree/json/yaml set without polluting
// PrintFlags with format names that only `bpf dump` uses.
type dumpPrintFlags struct {
	Inner *output.PrintFlags
}

func newDumpPrintFlags() *dumpPrintFlags {
	return &dumpPrintFlags{Inner: output.NewPrintFlags()}
}

func (p *dumpPrintFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&p.Inner.OutputFormat, "output", "o", string(formatTable),
		"Output format. One of: table|tree|json|yaml",
	)
}

func (p *dumpPrintFlags) Format() (output.Format, error) {
	switch f := output.Format(p.Inner.OutputFormat); f {
	case formatTable:
		return f, nil
	default:
		return p.Inner.Format()
	}
}

func newDumpCommand(f factory.Factory) *cobra.Command {
	o := &dumpOptions{Factory: f, PrintFlags: newDumpPrintFlags()}
	cmd := &cobra.Command{
		Use:   "dump MAP",
		Short: "Stream entries of one BPF map",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			o.MapName = args[0]
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run(c.Context())
		},
	}
	cmd.Flags().StringVar(&o.Node, "node", "", "Query a single node only.")
	cmd.Flags().BoolVar(&o.AllNodes, "all-nodes", false, "Aggregate entries across every daemon node.")
	cmd.Flags().StringSliceVar(&o.Filter, "filter", nil, "Restrict to entries matching every name=value (repeatable).")
	cmd.Flags().StringSliceVar(&o.InnerKey, "inner-key", nil, "Inner-map key selector for HASH_OF_MAPS dumps (repeatable).")
	cmd.Flags().Uint32Var(&o.Limit, "limit", 0, "Per-node entry cap. 0 uses the daemon default.")
	o.PrintFlags.AddFlags(cmd)
	return cmd
}

func (o *dumpOptions) Validate() error {
	if o.Node != "" && o.AllNodes {
		return fmt.Errorf("--node and --all-nodes are mutually exclusive")
	}
	if _, err := o.PrintFlags.Format(); err != nil {
		return err
	}
	return nil
}

func (o *dumpOptions) Run(ctx context.Context) error {
	keyFilter, err := parseFilters(o.Filter)
	if err != nil {
		return err
	}
	innerKey, err := parseFilters(o.InnerKey)
	if err != nil {
		return err
	}

	cli := bpfmap.NewFactoryClient(o.Factory)

	nodes, err := o.resolveNodes(ctx, cli)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return fmt.Errorf("no daemon nodes resolved")
	}

	// Schema is needed for the table renderer's column layout. Pull
	// it from the first reachable node; daemons in the same cluster
	// run the same schema so picking one is fine.
	schema, err := o.fetchSchema(ctx, cli, nodes)
	if err != nil {
		return err
	}

	var (
		mu      sync.Mutex
		entries []bpfmap.Entry
	)
	emit := func(e bpfmap.Entry) error {
		mu.Lock()
		entries = append(entries, e)
		mu.Unlock()
		return nil
	}
	dumpOpts := bpfmap.DumpOptions{
		KeyFilter: keyFilter,
		InnerKey:  innerKey,
		Limit:     o.Limit,
	}
	warnings := bpfmap.AggregateDumpMap(ctx, cli, nodes, o.MapName, dumpOpts, emit)

	// Stable order: by node then by key.
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Node != entries[j].Node {
			return entries[i].Node < entries[j].Node
		}
		return entryKeyString(entries[i]) < entryKeyString(entries[j])
	})

	res := bpfmap.DumpResult{
		Schema:    schema,
		Entries:   entries,
		MultiNode: len(nodes) > 1,
		Warnings:  warnings,
	}

	if err := o.render(o.Factory.Streams().Out, res); err != nil {
		return err
	}
	for _, w := range warnings {
		_, _ = fmt.Fprintf(o.Factory.Streams().ErrOut, "warning: node %s: %v\n", w.Node, w.Err)
	}
	return nil
}

// resolveNodes mirrors the list command: --node restricts to one,
// otherwise we query every reachable daemon. Override --all-nodes
// kept for explicitness even though it's the default; users may
// use it to fail loud if no nodes are reachable.
func (o *dumpOptions) resolveNodes(ctx context.Context, cli bpfmap.Client) ([]string, error) {
	if o.Node != "" {
		return []string{o.Node}, nil
	}
	return cli.ListNodes(ctx)
}

// fetchSchema returns the per-map schema from one of the nodes.
// Tries them in order and surfaces the first error if every node
// fails — kubectl is dead-on-arrival without a schema since the
// renderer needs it for column headers.
func (o *dumpOptions) fetchSchema(ctx context.Context, cli bpfmap.Client, nodes []string) (bpfmap.Schema, error) {
	var firstErr error
	for _, node := range nodes {
		schemas, err := cli.ListMaps(ctx, node)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, s := range schemas {
			if s.Name == o.MapName {
				return s, nil
			}
		}
		return bpfmap.Schema{}, fmt.Errorf("map %q not found on node %s", o.MapName, node)
	}
	if firstErr != nil {
		return bpfmap.Schema{}, fmt.Errorf("no daemon reachable: %w", firstErr)
	}
	return bpfmap.Schema{}, fmt.Errorf("no daemon reachable")
}

// render dispatches on the chosen format. Table is the default and
// is bpf-dump-specific; the others go through ResolveRenderer.
func (o *dumpOptions) render(w io.Writer, r bpfmap.DumpResult) error {
	f, err := o.PrintFlags.Format()
	if err != nil {
		return err
	}
	switch f {
	case formatTable:
		return bpfmap.RenderDumpTable(w, r)
	}
	renderer, err := output.ResolveRenderer[bpfmap.DumpResult](
		o.PrintFlags.Inner,
		output.RendererFunc[bpfmap.DumpResult](func(w io.Writer, r bpfmap.DumpResult) error {
			return bpfmap.RenderDumpTree(w, r)
		}),
	)
	if err != nil {
		return err
	}
	return renderer.Render(w, r)
}

// entryKeyString builds a stable string for sort ordering.
func entryKeyString(e bpfmap.Entry) string {
	out := ""
	for _, f := range e.Key {
		out += f.Name + "=" + f.Value + "/"
	}
	return out
}
