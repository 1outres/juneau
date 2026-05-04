package output

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// PrintFlags exposes the user-facing -o / --output flag and resolves it
// into a Renderer[T] that the command applies to its result. One
// PrintFlags per command instance; AddFlags wires it onto cobra.
type PrintFlags struct {
	OutputFormat string
}

// NewPrintFlags returns flags defaulting to tree output.
func NewPrintFlags() *PrintFlags {
	return &PrintFlags{OutputFormat: string(FormatTree)}
}

// AddFlags registers -o on the supplied command. Call once per command
// during NewCommand wiring.
func (p *PrintFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&p.OutputFormat, "output", "o", p.OutputFormat,
		fmt.Sprintf("Output format. One of: %s", joinFormats(AllFormats())),
	)
}

// Format returns the parsed format value, validating it on the way
// out. Commands should call this from Validate() so bad values fail
// before any cluster I/O.
func (p *PrintFlags) Format() (Format, error) {
	f := Format(p.OutputFormat)
	if err := f.Validate(); err != nil {
		return "", err
	}
	return f, nil
}

// ResolveRenderer composes the per-format Renderer[T] for the chosen
// output. The caller supplies the tree presenter; JSON and YAML are
// shared. This keeps each command's presenter file focused on the
// human-readable form, with structured formats handled centrally.
func ResolveRenderer[T any](p *PrintFlags, tree Renderer[T]) (Renderer[T], error) {
	f, err := p.Format()
	if err != nil {
		return nil, err
	}
	switch f {
	case FormatTree:
		if tree == nil {
			return nil, fmt.Errorf("tree renderer is not provided for this command")
		}
		return tree, nil
	case FormatJSON:
		return RendererFunc[T](func(w io.Writer, v T) error { return RenderJSON(w, v) }), nil
	case FormatYAML:
		return RendererFunc[T](func(w io.Writer, v T) error { return RenderYAML(w, v) }), nil
	}
	return nil, fmt.Errorf("unhandled format %q", string(f))
}

func joinFormats(fs []Format) string {
	out := ""
	for i, f := range fs {
		if i > 0 {
			out += "|"
		}
		out += string(f)
	}
	return out
}
