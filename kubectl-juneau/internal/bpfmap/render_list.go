package bpfmap

import (
	"fmt"
	"io"
	"sort"

	"github.com/1outres/juneau/kubectl-juneau/internal/output"
)

// ListResult is the full payload `bpf list` builds before rendering.
// Per-node so the renderer can flag schema drift between daemon
// versions; nodes with errors are surfaced as Warnings.
type ListResult struct {
	Nodes    []string
	PerNode  map[string][]Schema
	Warnings []NodeError
}

// RenderListTree produces the human-readable form. When all nodes
// agree on the schema, the tree collapses into a single block;
// otherwise we render per-node sections so divergence is visible.
func RenderListTree(w io.Writer, r ListResult) error {
	root := output.NewNode("BPF Maps")
	if len(r.Nodes) == 0 {
		root.Child("(no daemons reachable)")
	}

	// Detect uniform vs divergent schemas by counting distinct
	// (name, kind, key fields, value fields) signatures.
	if uniform, common := uniformSchemas(r); uniform {
		appendSchemaBlock(root, common)
		if len(r.Nodes) > 1 {
			root.Childf("(consistent across %d nodes)", len(r.Nodes))
		}
	} else {
		for _, node := range r.Nodes {
			schemas, ok := r.PerNode[node]
			if !ok {
				continue
			}
			n := root.Childf("Node %s", node)
			appendSchemaBlock(n, schemas)
		}
	}

	if len(r.Warnings) > 0 {
		warn := root.Child("Warnings")
		for _, w := range r.Warnings {
			warn.Childf("%s: %v", w.Node, w.Err)
		}
	}
	return output.WriteTree(w, root)
}

func appendSchemaBlock(parent *output.Node, schemas []Schema) {
	sortedNames := make([]string, 0, len(schemas))
	byName := map[string]Schema{}
	for _, s := range schemas {
		sortedNames = append(sortedNames, s.Name)
		byName[s.Name] = s
	}
	sort.Strings(sortedNames)
	for _, name := range sortedNames {
		s := byName[name]
		title := fmt.Sprintf("%s  (kind: %s, max: %d)", s.Name, s.Kind, s.MaxEntries)
		if s.RequiresInnerKey {
			title += "  [HASH_OF_MAPS]"
		}
		mNode := parent.Child(title)
		appendFieldList(mNode, "key", s.KeySchema)
		if s.RequiresInnerKey {
			appendFieldList(mNode, "inner-key", s.InnerKeySchema)
			appendFieldList(mNode, "inner-value", s.InnerValueSchema)
		} else {
			appendFieldList(mNode, "value", s.ValueSchema)
		}
	}
}

func appendFieldList(parent *output.Node, label string, fields []FieldSchema) {
	if len(fields) == 0 {
		parent.Childf("%s: (empty)", label)
		return
	}
	g := parent.Childf("%s", label)
	for _, f := range fields {
		if f.Description != "" {
			g.Childf("%s: %s  -- %s", f.Name, f.Type, f.Description)
		} else {
			g.Childf("%s: %s", f.Name, f.Type)
		}
	}
}

// uniformSchemas reports whether every node returned the same map
// list with the same field shapes. Returns the schema list to use
// when uniform.
func uniformSchemas(r ListResult) (bool, []Schema) {
	if len(r.PerNode) == 0 {
		return true, nil
	}
	var first []Schema
	signature := ""
	for _, node := range r.Nodes {
		schemas, ok := r.PerNode[node]
		if !ok {
			continue
		}
		if first == nil {
			first = schemas
			signature = schemaSignature(schemas)
			continue
		}
		if schemaSignature(schemas) != signature {
			return false, nil
		}
	}
	return true, first
}

func schemaSignature(s []Schema) string {
	cp := make([]Schema, len(s))
	copy(cp, s)
	sort.Slice(cp, func(i, j int) bool { return cp[i].Name < cp[j].Name })
	out := ""
	for _, m := range cp {
		out += m.Name + "/" + m.Kind + "|"
		for _, f := range m.KeySchema {
			out += f.Name + ":" + f.Type + ","
		}
		out += "->"
		for _, f := range m.ValueSchema {
			out += f.Name + ":" + f.Type + ","
		}
		out += ";"
	}
	return out
}
