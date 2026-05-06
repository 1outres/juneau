package bpfmap

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderDumpTableShape(t *testing.T) {
	r := DumpResult{
		Schema: Schema{
			Name: "subnet_map",
			Kind: "Hash",
			KeySchema: []FieldSchema{
				{Name: "subnet_id", Type: "u32"},
			},
			ValueSchema: []FieldSchema{
				{Name: "vpc_id", Type: "u32"},
				{Name: "gw_addr", Type: "ipv4"},
			},
		},
		Entries: []Entry{
			{
				Key:   []Field{{Name: "subnet_id", Value: "1"}},
				Value: []Field{{Name: "vpc_id", Value: "0"}, {Name: "gw_addr", Value: "10.16.0.1"}},
			},
			{
				Key:   []Field{{Name: "subnet_id", Value: "2"}},
				Value: []Field{{Name: "vpc_id", Value: "1"}, {Name: "gw_addr", Value: "10.80.0.1"}},
			},
		},
	}
	var buf bytes.Buffer
	if err := RenderDumpTable(&buf, r); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"SUBNET_ID", "VPC_ID", "GW_ADDR", "10.16.0.1", "10.80.0.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestRenderDumpTableMultiNode(t *testing.T) {
	r := DumpResult{
		MultiNode: true,
		Schema: Schema{
			KeySchema:   []FieldSchema{{Name: "vpc_id", Type: "u32"}},
			ValueSchema: []FieldSchema{{Name: "addr", Type: "ipv4"}},
		},
		Entries: []Entry{
			{Node: "worker-1", Key: []Field{{Name: "vpc_id", Value: "1"}}, Value: []Field{{Name: "addr", Value: "10.0.0.1"}}},
			{Node: "worker-2", Key: []Field{{Name: "vpc_id", Value: "1"}}, Value: []Field{{Name: "addr", Value: "10.0.0.2"}}},
		},
	}
	var buf bytes.Buffer
	if err := RenderDumpTable(&buf, r); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "NODE") || !strings.Contains(got, "worker-1") {
		t.Errorf("multi-node output missing node column\n%s", got)
	}
}

func TestRenderListTreeUniform(t *testing.T) {
	r := ListResult{
		Nodes: []string{"worker-1", "worker-2"},
		PerNode: map[string][]Schema{
			"worker-1": {{Name: "subnet_map", Kind: "Hash", MaxEntries: 100,
				KeySchema:   []FieldSchema{{Name: "subnet_id", Type: "u32"}},
				ValueSchema: []FieldSchema{{Name: "vpc_id", Type: "u32"}},
			}},
			"worker-2": {{Name: "subnet_map", Kind: "Hash", MaxEntries: 100,
				KeySchema:   []FieldSchema{{Name: "subnet_id", Type: "u32"}},
				ValueSchema: []FieldSchema{{Name: "vpc_id", Type: "u32"}},
			}},
		},
	}
	var buf bytes.Buffer
	if err := RenderListTree(&buf, r); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "subnet_map") {
		t.Fatalf("missing map name in output:\n%s", got)
	}
	if !strings.Contains(got, "consistent across 2 nodes") {
		t.Errorf("uniform marker missing:\n%s", got)
	}
	if strings.Contains(got, "Node worker-1") {
		t.Errorf("per-node block should be collapsed when schemas are uniform")
	}
}

func TestRenderListTreeDivergent(t *testing.T) {
	r := ListResult{
		Nodes: []string{"worker-1", "worker-2"},
		PerNode: map[string][]Schema{
			"worker-1": {{Name: "subnet_map", Kind: "Hash"}},
			"worker-2": {{Name: "subnet_map", Kind: "Hash"}, {Name: "extra", Kind: "Hash"}},
		},
	}
	var buf bytes.Buffer
	if err := RenderListTree(&buf, r); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "Node worker-1") || !strings.Contains(got, "Node worker-2") {
		t.Errorf("divergent output missing per-node sections:\n%s", got)
	}
}
