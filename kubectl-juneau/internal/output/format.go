// Package output is the rendering layer. Domain types (PodContext,
// VpcContext, …) are produced by the topology package and rendered to
// text by this package, never the other way around. This split keeps
// CRD walk logic free of formatting decisions and lets us add output
// formats (e.g. -o dot) without touching domain code.
//
// Three contracts compose the layer:
//
//   - Format identifies a user-selectable rendering ("tree", "json",
//     …). Validate() rejects unknown values up front so commands fail
//     before doing any work.
//
//   - Renderer[T] is what each command's "presenter" implements: turn
//     a typed view into bytes on a writer. Generics keep call sites
//     type-safe; one Renderer per (T, format) pair.
//
//   - PrintFlags wires the user-facing -o flag onto a cobra command.
//     Each command builds a Renderer[T] from PrintFlags via
//     ResolveRenderer, supplying the tree presenter callback.
//
// JSON / YAML rendering is generic across types and lives in this
// package; tree rendering varies per type and is supplied by callers.
package output

import (
	"fmt"
	"io"
	"strings"
)

// Format names a rendering strategy. Values are user-visible; bumping
// or removing a value is a breaking change for `-o` users.
type Format string

const (
	FormatTree Format = "tree"
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
)

// AllFormats returns the supported formats in user-help order.
func AllFormats() []Format { return []Format{FormatTree, FormatJSON, FormatYAML} }

// Validate rejects unknown formats with a list of supported values.
func (f Format) Validate() error {
	for _, ok := range AllFormats() {
		if f == ok {
			return nil
		}
	}
	names := make([]string, 0, len(AllFormats()))
	for _, x := range AllFormats() {
		names = append(names, string(x))
	}
	return fmt.Errorf("unsupported output format %q (supported: %s)", string(f), strings.Join(names, ", "))
}

// Renderer renders a typed value to a writer. One implementation per
// (T, Format) pair. Stateless — no fields, just behaviour.
type Renderer[T any] interface {
	Render(w io.Writer, v T) error
}

// rendererFunc adapts a plain function into a Renderer.
type rendererFunc[T any] func(io.Writer, T) error

func (f rendererFunc[T]) Render(w io.Writer, v T) error { return f(w, v) }

// RendererFunc is the canonical way to construct a Renderer from a
// closure. Prefer this over a bare struct: it makes the file produce a
// Renderer rather than a private type with a Render method.
func RendererFunc[T any](fn func(io.Writer, T) error) Renderer[T] { return rendererFunc[T](fn) }
