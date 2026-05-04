package output

import (
	"fmt"
	"io"
)

// Node is the building block of the tree-format output. Commands build
// up a Node from their domain type and pass it to WriteTree. Keeping
// the data structure tiny (no styling, no IO) lets us unit-test layout
// independently from rendering.
//
// Usage:
//
//	root := output.NewNode("Pod  default/curl")
//	nic := root.Child("NetworkInterface  curl.eth0")
//	nic.Child("Subnet  app-subnet (10.80.0.0/24)")
//	output.WriteTree(w, root)
type Node struct {
	Label    string
	Children []*Node
}

// NewNode creates a root.
func NewNode(label string) *Node { return &Node{Label: label} }

// Child appends a labelled leaf and returns it for further nesting.
func (n *Node) Child(label string) *Node {
	c := &Node{Label: label}
	n.Children = append(n.Children, c)
	return c
}

// Childf is Child with fmt.Sprintf semantics.
func (n *Node) Childf(format string, a ...any) *Node {
	return n.Child(fmt.Sprintf(format, a...))
}

// Add appends an already-built subtree.
func (n *Node) Add(child *Node) *Node {
	n.Children = append(n.Children, child)
	return child
}

// WriteTree renders root and its descendants to w using ASCII glyphs.
// Glyphs are deliberately ASCII (not Unicode box-drawing) for terminals
// that mangle UTF-8; readers can switch later if it becomes necessary.
func WriteTree(w io.Writer, root *Node) error {
	if root == nil {
		return nil
	}
	if _, err := fmt.Fprintln(w, root.Label); err != nil {
		return err
	}
	return writeChildren(w, root.Children, "")
}

const (
	branchTee  = "|-- "
	branchLast = "`-- "
	stalk      = "|   "
	indent     = "    "
)

func writeChildren(w io.Writer, children []*Node, prefix string) error {
	for i, c := range children {
		last := i == len(children)-1
		connector := branchTee
		next := stalk
		if last {
			connector = branchLast
			next = indent
		}
		if _, err := fmt.Fprintf(w, "%s%s%s\n", prefix, connector, c.Label); err != nil {
			return err
		}
		if err := writeChildren(w, c.Children, prefix+next); err != nil {
			return err
		}
	}
	return nil
}
