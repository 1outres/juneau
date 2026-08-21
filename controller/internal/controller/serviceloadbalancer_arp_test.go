package controller

import (
	"fmt"
	"slices"
	"testing"
)

func TestElectARPNodeIsDeterministic(t *testing.T) {
	nodes := []string{"node-a", "node-b", "node-c", "node-d"}
	want := electARPNode("10.0.0.1", nodes, "")

	for i := 0; i < 32; i++ {
		if got := electARPNode("10.0.0.1", nodes, ""); got != want {
			t.Fatalf("electARPNode returned %q on run %d, want %q", got, i, want)
		}
	}
}

func TestElectARPNodeIgnoresNodeOrder(t *testing.T) {
	nodes := []string{"node-a", "node-b", "node-c", "node-d"}
	want := electARPNode("10.0.0.1", nodes, "")

	reversed := slices.Clone(nodes)
	slices.Reverse(reversed)
	if got := electARPNode("10.0.0.1", reversed, ""); got != want {
		t.Fatalf("electARPNode returned %q for reversed input, want %q", got, want)
	}

	rotated := []string{"node-c", "node-d", "node-a", "node-b"}
	if got := electARPNode("10.0.0.1", rotated, ""); got != want {
		t.Fatalf("electARPNode returned %q for rotated input, want %q", got, want)
	}
}

func TestElectARPNodeKeepsTheCurrentNode(t *testing.T) {
	nodes := []string{"node-a", "node-b", "node-c", "node-d"}

	for _, current := range nodes {
		if got := electARPNode("10.0.0.1", nodes, current); got != current {
			t.Errorf("electARPNode moved the address off %q to %q", current, got)
		}
	}
}

func TestElectARPNodeMovesOffANodeThatStoppedAdvertising(t *testing.T) {
	nodes := []string{"node-a", "node-b", "node-c"}

	got := electARPNode("10.0.0.1", nodes, "node-gone")
	if got == "node-gone" {
		t.Fatal("electARPNode kept a node that no longer advertises")
	}
	if !slices.Contains(nodes, got) {
		t.Fatalf("electARPNode returned %q, which is not an advertising node", got)
	}
	if want := electARPNode("10.0.0.1", nodes, ""); got != want {
		t.Fatalf("electARPNode returned %q for a departed node, want the same %q as for no current node", got, want)
	}
}

func TestElectARPNodeReturnsNothingWithoutAdvertisingNodes(t *testing.T) {
	for _, current := range []string{"", "node-a"} {
		if got := electARPNode("10.0.0.1", nil, current); got != "" {
			t.Errorf("electARPNode(current=%q) returned %q, want an empty node name", current, got)
		}
		if got := electARPNode("10.0.0.1", []string{}, current); got != "" {
			t.Errorf("electARPNode(current=%q) returned %q, want an empty node name", current, got)
		}
	}
}

func TestElectARPNodeSpreadsVIPsAcrossNodes(t *testing.T) {
	nodes := []string{"node-a", "node-b", "node-c"}
	elected := map[string]int{}

	for i := 0; i < 60; i++ {
		vip := fmt.Sprintf("192.0.2.%d", i)
		elected[electARPNode(vip, nodes, "")]++
	}

	if len(elected) != len(nodes) {
		t.Fatalf("electARPNode used %d of %d nodes: %v", len(elected), len(nodes), elected)
	}
	for _, node := range nodes {
		if elected[node] == 0 {
			t.Errorf("node %q never answered for any VIP: %v", node, elected)
		}
	}
}

func TestElectARPNodeReplacesADepartedNodeWithoutMovingTheRest(t *testing.T) {
	nodes := []string{"node-a", "node-b", "node-c", "node-d"}
	remaining := []string{"node-a", "node-b", "node-c"}

	moved := 0
	for i := 0; i < 60; i++ {
		vip := fmt.Sprintf("192.0.2.%d", i)
		before := electARPNode(vip, nodes, "")
		after := electARPNode(vip, remaining, before)
		if before != "node-d" && after != before {
			t.Errorf("VIP %s moved from %q to %q even though %q still advertises", vip, before, after, before)
		}
		if before == "node-d" {
			moved++
		}
	}

	if moved == 0 {
		t.Fatal("no VIP was elected onto node-d, so its removal was never exercised")
	}
}
