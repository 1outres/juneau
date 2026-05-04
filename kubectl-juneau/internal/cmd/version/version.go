// Package version implements the `kubectl juneau version` subcommand.
// It is the simplest subcommand in the tree, so it doubles as the
// reference for the Complete/Validate/Run pattern other subcommands
// follow.
package version

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/1outres/juneau/kubectl-juneau/internal/factory"
	"github.com/1outres/juneau/kubectl-juneau/internal/output"
	versioninfo "github.com/1outres/juneau/kubectl-juneau/internal/version"
)

// Options holds the parsed flags + injected dependencies for the
// version command. Each subcommand defines its own Options to keep
// ownership clear.
type Options struct {
	Factory    factory.Factory
	PrintFlags *output.PrintFlags
}

// NewCommand wires the cobra command for `version`.
func NewCommand(f factory.Factory) *cobra.Command {
	o := &Options{Factory: f, PrintFlags: output.NewPrintFlags()}
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print kubectl-juneau version",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run(c.Context())
		},
	}
	o.PrintFlags.AddFlags(cmd)
	return cmd
}

// Validate checks flag combinations. The version command has no
// arguments, so the only thing to validate is -o.
func (o *Options) Validate() error {
	if _, err := o.PrintFlags.Format(); err != nil {
		return err
	}
	return nil
}

// Run produces the output. Domain "logic" is just version.Get();
// rendering is delegated to output via the resolved Renderer.
func (o *Options) Run(_ context.Context) error {
	info := versioninfo.Get()
	renderer, err := output.ResolveRenderer[versioninfo.Info](o.PrintFlags, output.RendererFunc[versioninfo.Info](renderTree))
	if err != nil {
		return err
	}
	return renderer.Render(o.Factory.Streams().Out, info)
}

// renderTree is the human-readable presenter. It is intentionally
// minimal — the value of -o tree on `version` is to look familiar to
// kubectl, not to be richly nested.
func renderTree(w io.Writer, v versioninfo.Info) error {
	if v.GitTag != "" {
		if _, err := fmt.Fprintf(w, "GitTag:    %s\n", v.GitTag); err != nil {
			return err
		}
	}
	if v.GitCommit != "" {
		if _, err := fmt.Fprintf(w, "GitCommit: %s\n", v.GitCommit); err != nil {
			return err
		}
	}
	if v.BuildDate != "" {
		if _, err := fmt.Fprintf(w, "BuildDate: %s\n", v.BuildDate); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "Go:        %s\n", v.GoVersion); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Platform:  %s\n", v.Platform)
	return err
}
