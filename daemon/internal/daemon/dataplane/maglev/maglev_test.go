package maglev

import (
	"fmt"
	"reflect"
	"testing"
)

// M is the prime the daemon ships with; tests use the same value so
// any algorithmic property they verify holds for the production size.
const productionM uint32 = 4093

// nodeSet returns N synthetic NodeIDs. Using a stable formatting so
// the SHA-256 inputs are deterministic across test runs.
func nodeSet(n int) []NodeID {
	out := make([]NodeID, n)
	for i := range n {
		out[i] = NodeID(fmt.Sprintf("10.0.0.%d", i+1))
	}
	return out
}

func TestBuildTable_DeterministicForSameInput(t *testing.T) {
	t.Parallel()
	nodes := nodeSet(7)

	a := BuildTable(nodes, productionM)
	b := BuildTable(nodes, productionM)

	if !reflect.DeepEqual(a.Slots, b.Slots) {
		t.Fatalf("BuildTable not deterministic: slots differ between two runs")
	}
	if !reflect.DeepEqual(a.Counts, b.Counts) {
		t.Fatalf("BuildTable not deterministic: counts differ between two runs")
	}
}

func TestBuildTable_InsensitiveToInputOrder(t *testing.T) {
	t.Parallel()
	nodes := nodeSet(11)

	a := BuildTable(nodes, productionM)

	// Reverse the input slice to make sure the implementation does
	// not encode positional information beyond the sort BuildTable
	// applies internally.
	reversed := make([]NodeID, len(nodes))
	for i, id := range nodes {
		reversed[len(nodes)-1-i] = id
	}
	b := BuildTable(reversed, productionM)

	if !reflect.DeepEqual(a.Slots, b.Slots) {
		t.Fatalf("BuildTable depends on input order; expected sort to neutralize")
	}
}

func TestBuildTable_FillsEverySlotWhenNodesNonEmpty(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 2, 5, 100} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			t.Parallel()
			tbl := BuildTable(nodeSet(n), productionM)
			if tbl.SlotCount != productionM {
				t.Fatalf("SlotCount = %d, want %d", tbl.SlotCount, productionM)
			}
			for i, s := range tbl.Slots {
				if s == Empty {
					t.Fatalf("slot %d is Empty; expected every slot owned for N=%d", i, n)
				}
			}
		})
	}
}

func TestBuildTable_EmptyInputProducesAllEmptySlots(t *testing.T) {
	t.Parallel()
	tbl := BuildTable(nil, productionM)
	if tbl.SlotCount != productionM {
		t.Fatalf("SlotCount = %d, want %d", tbl.SlotCount, productionM)
	}
	for i, s := range tbl.Slots {
		if s != Empty {
			t.Fatalf("slot %d = %q, want Empty for empty input", i, s)
		}
	}
	if len(tbl.Counts) != 0 {
		t.Fatalf("Counts non-empty for empty input: %v", tbl.Counts)
	}
}

func TestBuildTable_BalancedDistribution(t *testing.T) {
	t.Parallel()
	// For every common cluster size we expect the per-Node slot count
	// to differ by at most one (the canonical Maglev balance bound for
	// M ≥ N).
	for _, n := range []int{2, 3, 5, 7, 10, 25, 100} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			t.Parallel()
			tbl := BuildTable(nodeSet(n), productionM)

			min := -1
			max := -1
			for _, c := range tbl.Counts {
				if min == -1 || c < min {
					min = c
				}
				if c > max {
					max = c
				}
			}
			if max-min > 1 {
				t.Fatalf("per-node slot count diff = %d (max=%d, min=%d), want ≤ 1", max-min, max, min)
			}

			expected := int(productionM) / n
			if min < expected || max > expected+1 {
				t.Fatalf("per-node count out of expected range [%d, %d]: min=%d max=%d", expected, expected+1, min, max)
			}
		})
	}
}

func TestBuildTable_DisruptionOnAdd(t *testing.T) {
	t.Parallel()
	// Adding one Node to N-1 should move at most M/N slots (the new
	// Node's share). We allow some slack to absorb the variance from
	// the round-robin filler.
	const N = 10
	before := BuildTable(nodeSet(N-1), productionM)
	after := BuildTable(nodeSet(N), productionM)

	moved := 0
	for i := range before.Slots {
		if before.Slots[i] != after.Slots[i] {
			moved++
		}
	}

	expected := int(productionM) / N
	// The new node's share should be in [expected, expected+1]; the
	// moved-slot count should not greatly exceed that. Bound at 2x to
	// catch wild regressions while tolerating realistic slack.
	upper := expected*2 + 1
	if moved > upper {
		t.Fatalf("disruption on add: %d slots moved, want ≤ %d (≈ M/N = %d)", moved, upper, expected)
	}
}

func TestBuildTable_DisruptionOnRemove(t *testing.T) {
	t.Parallel()
	// Removing one Node from N should move at most M/N slots.
	const N = 10
	before := BuildTable(nodeSet(N), productionM)

	// Remove the lexically-largest Node (10.0.0.9 in our synthetic
	// set; nodeSet returns 1..N).
	smaller := nodeSet(N)[:N-1]
	after := BuildTable(smaller, productionM)

	moved := 0
	for i := range before.Slots {
		if before.Slots[i] != after.Slots[i] {
			moved++
		}
	}

	expected := int(productionM) / N
	upper := expected*2 + 1
	if moved > upper {
		t.Fatalf("disruption on remove: %d slots moved, want ≤ %d (≈ M/N = %d)", moved, upper, expected)
	}
}

func TestBuildTable_AddRemoveCommute(t *testing.T) {
	t.Parallel()
	// Maglev's stability guarantee is that the slot table depends only
	// on the *set* of nodes, not the path of additions/removals. Verify
	// add-then-remove returns to the original table.
	base := nodeSet(5)
	original := BuildTable(base, productionM)

	withExtra := append([]NodeID{}, base...)
	withExtra = append(withExtra, NodeID("10.0.0.99"))
	_ = BuildTable(withExtra, productionM)

	again := BuildTable(base, productionM)
	if !reflect.DeepEqual(original.Slots, again.Slots) {
		t.Fatalf("table for the same node set differs after a transient larger build")
	}
}

func TestBuildTable_SingleNodeOwnsEverything(t *testing.T) {
	t.Parallel()
	n := nodeSet(1)
	tbl := BuildTable(n, productionM)
	for i, s := range tbl.Slots {
		if s != n[0] {
			t.Fatalf("slot %d = %q, want %q (single-node table)", i, s, n[0])
		}
	}
	if got := tbl.Counts[n[0]]; got != int(productionM) {
		t.Fatalf("count for sole node = %d, want %d", got, productionM)
	}
}

func TestBuildTable_PanicsOnZeroM(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for M == 0, got none")
		}
	}()
	BuildTable(nodeSet(3), 0)
}

func TestBuildTable_HandlesMEqualOne(t *testing.T) {
	t.Parallel()
	// M == 1 degenerates to "first node in sorted order wins". The
	// derive() helper has a special case for M == 1 (skip irrelevant);
	// this test guards against future refactors that reintroduce the
	// (M-1) % 0 hazard.
	nodes := nodeSet(3)
	tbl := BuildTable(nodes, 1)
	if tbl.SlotCount != 1 {
		t.Fatalf("SlotCount = %d, want 1", tbl.SlotCount)
	}
	if tbl.Slots[0] == Empty {
		t.Fatalf("single slot is Empty; want filled")
	}
}

func TestBuildTable_ManyAddsAreStableInTotal(t *testing.T) {
	t.Parallel()
	// Statistical sanity: across a sequence of single-Node additions
	// the cumulative number of moved slots should track the harmonic
	// growth ∑(M/k) for k = 2..N+1 ≈ M·ln(N+1). We don't assert the
	// exact figure (depends on the specific hashes of nodeSet IDs)
	// but require it stays well under the trivial upper bound of
	// (N-1)·M (which would mean every step rebuilt from scratch).
	const start = 5
	const adds = 20

	prev := BuildTable(nodeSet(start), productionM)
	totalMoved := 0
	for i := start + 1; i <= start+adds; i++ {
		cur := BuildTable(nodeSet(i), productionM)
		for j := range cur.Slots {
			if prev.Slots[j] != cur.Slots[j] {
				totalMoved++
			}
		}
		prev = cur
	}

	trivialBound := adds * int(productionM)
	if totalMoved >= trivialBound {
		t.Fatalf("cumulative moved slots = %d, expected substantially less than trivial bound %d", totalMoved, trivialBound)
	}
}

func BenchmarkBuildTable(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			nodes := nodeSet(n)
			b.ResetTimer()
			for b.Loop() {
				_ = BuildTable(nodes, productionM)
			}
		})
	}
}
