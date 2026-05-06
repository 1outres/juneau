package bpfmap

import (
	"fmt"
	"io"
	"strings"

	"github.com/1outres/juneau/kubectl-juneau/internal/output"
)

// DumpResult bundles the entries plus the schema kubectl resolved
// from the daemon. The schema is needed for the table renderer to
// compute column widths up front (so streaming output can be written
// without buffering every row first when the user opted into a
// no-buffer mode in future).
type DumpResult struct {
	Schema  Schema
	Entries []Entry
	// MultiNode is set when the result aggregates more than one
	// node; renderers add a Node column up front in that case.
	MultiNode bool
	Warnings  []NodeError
}

// RenderDumpTable writes a fixed-column table. Column widths are
// computed from the actual entries so misaligned formats from
// future field shapes do not silently chop content.
func RenderDumpTable(w io.Writer, r DumpResult) error {
	headers := tableHeaders(r)
	rows := tableRows(r, len(headers))

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	writeRow := func(row []string) error {
		parts := make([]string, len(row))
		for i, cell := range row {
			parts[i] = padRight(cell, widths[i])
		}
		_, err := fmt.Fprintln(w, strings.Join(parts, "  "))
		return err
	}

	if err := writeRow(headers); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writeRow(row); err != nil {
			return err
		}
	}
	if len(r.Entries) == 0 {
		if _, err := fmt.Fprintln(w, "(no entries)"); err != nil {
			return err
		}
	}
	// Warnings are surfaced by the cmd layer (they belong on stderr)
	// so the table renderer keeps stdout clean for piping.
	return nil
}

// RenderDumpTree groups entries by node (or by some other axis when
// MultiNode is false) so the user can scroll one entry at a time.
// Useful for dump runs that exceed the comfortable row budget of the
// table form.
func RenderDumpTree(w io.Writer, r DumpResult) error {
	root := output.NewNode(fmt.Sprintf("%s  (%d entries)", r.Schema.Name, len(r.Entries)))
	if r.MultiNode {
		byNode := groupByNode(r.Entries)
		for node, entries := range byNode {
			n := root.Childf("Node %s  (%d)", node, len(entries))
			for _, e := range entries {
				appendEntryNode(n, e)
			}
		}
	} else {
		for _, e := range r.Entries {
			appendEntryNode(root, e)
		}
	}
	if len(r.Warnings) > 0 {
		warn := root.Child("Warnings")
		for _, ne := range r.Warnings {
			warn.Childf("%s: %v", ne.Node, ne.Err)
		}
	}
	return output.WriteTree(w, root)
}

func appendEntryNode(parent *output.Node, e Entry) {
	header := "entry"
	if len(e.Key) > 0 {
		header = renderFieldList(e.Key)
	}
	n := parent.Child(header)
	if len(e.Value) > 0 {
		n.Childf("value: %s", renderFieldList(e.Value))
	}
}

func renderFieldList(fs []Field) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, fmt.Sprintf("%s=%s", f.Name, f.Value))
	}
	return strings.Join(parts, " ")
}

// ----- table helpers ----------------------------------------------------

func tableHeaders(r DumpResult) []string {
	headers := []string{}
	if r.MultiNode {
		headers = append(headers, "NODE")
	}
	if r.Schema.RequiresInnerKey {
		// Outer keys are echoed first, then inner keys.
		for _, f := range r.Schema.KeySchema {
			headers = append(headers, headerName(f))
		}
		for _, f := range r.Schema.InnerKeySchema {
			headers = append(headers, headerName(f))
		}
		for _, f := range r.Schema.InnerValueSchema {
			headers = append(headers, headerName(f))
		}
		return headers
	}
	for _, f := range r.Schema.KeySchema {
		headers = append(headers, headerName(f))
	}
	for _, f := range r.Schema.ValueSchema {
		headers = append(headers, headerName(f))
	}
	return headers
}

func tableRows(r DumpResult, ncol int) [][]string {
	rows := make([][]string, 0, len(r.Entries))
	for _, e := range r.Entries {
		row := make([]string, 0, ncol)
		if r.MultiNode {
			row = append(row, e.Node)
		}
		for _, f := range e.Key {
			row = append(row, f.Value)
		}
		for _, f := range e.Value {
			row = append(row, f.Value)
		}
		// Pad to header width in case a field decoded to nothing.
		for len(row) < ncol {
			row = append(row, "")
		}
		if len(row) > ncol {
			row = row[:ncol]
		}
		rows = append(rows, row)
	}
	return rows
}

func headerName(f FieldSchema) string {
	return strings.ToUpper(f.Name)
}

func padRight(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

func groupByNode(entries []Entry) map[string][]Entry {
	out := map[string][]Entry{}
	for _, e := range entries {
		key := e.Node
		if key == "" {
			key = "(local)"
		}
		out[key] = append(out[key], e)
	}
	return out
}
