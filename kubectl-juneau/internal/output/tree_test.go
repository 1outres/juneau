package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteTreeShape(t *testing.T) {
	root := NewNode("root")
	a := root.Child("a")
	a.Child("a1")
	a.Child("a2")
	root.Child("b")

	var buf bytes.Buffer
	if err := WriteTree(&buf, root); err != nil {
		t.Fatalf("WriteTree: %v", err)
	}
	got := buf.String()

	// We want a stable layout. The exact glyphs ("|--" / "`--") are
	// part of the user-visible output, so check both presence and
	// indentation.
	want := strings.Join([]string{
		"root",
		"|-- a",
		"|   |-- a1",
		"|   `-- a2",
		"`-- b",
		"",
	}, "\n")
	if got != want {
		t.Fatalf("tree shape mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestWriteTreeEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTree(&buf, NewNode("solo")); err != nil {
		t.Fatalf("WriteTree: %v", err)
	}
	if buf.String() != "solo\n" {
		t.Fatalf("expected lone label, got %q", buf.String())
	}
}
