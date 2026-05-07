// Package maglev implements the Maglev consistent-hashing slot table
// used by the LB owner-redirection layer. Each cluster Node holds an
// identical copy of the table (keyed by flow-hash slot, valued by the
// owner Node's underlay IP) and uses it to deterministically forward
// LB traffic to its owner regardless of which Node the upstream router
// ECMP'd the original packet to.
//
// Reference: Eisenbud et al., "Maglev: A Fast and Reliable Software
// Network Load Balancer", NSDI 2016, §3.4. The implementation here
// follows the paper directly: each input node contributes a
// permutation of slot indices derived from two hashes (offset, skip),
// and slots are filled round-robin over the node set until the table
// is full.
//
// Key properties this package guarantees and tests cover:
//
//   - Determinism: identical (sorted node set, M) → identical Table.
//   - Balance: max - min slot count per node ≤ 1 when M ≥ N.
//   - Minimal disruption: adding or removing one node out of N reshapes
//     ≈ M/N slots; the rest of the table is preserved. This is the
//     property that buys us "ECMP picks any Node, the same flow still
//     resolves to the same owner Node".
//   - Cheap to rebuild: O(M·N) hash ops with no inter-Node coordination,
//     so each Node can recompute the table independently from a Node-
//     membership snapshot and converge on the same answer.
//
// Pick a prime M (the daemon uses 4093, see
// daemon/bpf/maps.h::MAX_LB_OWNER_TABLE) so the (offset, skip) pairs
// generate full-period permutations.
package maglev

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
)

// NodeID identifies a Node in the consistent hash. The daemon supplies
// each Node's underlay IPv4 in dotted-quad form (e.g. "10.0.0.5"), but
// BuildTable treats the value opaquely — only the SHA-256 of the byte
// representation matters. Any stable, unique identifier works.
type NodeID string

// Empty is the sentinel value Table.Slots carries when no node owns a
// given slot. The only way Empty appears in a successfully-built table
// is when the caller passes an empty `nodes` slice; for any non-empty
// input every slot is filled. Callers in the data plane can therefore
// treat Empty as "no owner programmed for this slot" and fall back to
// local handling.
const Empty NodeID = ""

// Table is a built Maglev slot table. Slots[i] is the NodeID
// responsible for flows whose hash maps to slot i; SlotCount mirrors
// len(Slots) for convenience; Counts holds the per-Node slot count
// (useful for balance assertions and observability).
type Table struct {
	Slots     []NodeID
	SlotCount uint32
	Counts    map[NodeID]int
}

// BuildTable constructs a Maglev slot table of length M from the
// supplied nodes. The input slice is copied and sorted before
// processing so callers may pass nodes in any order without affecting
// the result.
//
// Returned values:
//   - len(nodes) == 0 → every slot is Empty; Counts is empty.
//   - len(nodes) >  0 → every slot is owned; Counts holds non-negative
//     counts for every node (some nodes can hold 0 slots if M < N).
//
// M must be a positive prime for the (offset, skip) walks to cover the
// whole index space; BuildTable does not validate primality (callers
// pick from a small fixed set of constants in practice).
//
// Panics: only on M == 0, since that would require dividing by zero
// when computing offsets. M == 1 degenerates correctly (every node's
// permutation has length 1; the first node wins the only slot).
func BuildTable(nodes []NodeID, M uint32) Table {
	if M == 0 {
		panic("maglev: slot count M must be > 0")
	}

	if len(nodes) == 0 {
		return Table{
			Slots:     emptySlots(M),
			SlotCount: M,
			Counts:    map[NodeID]int{},
		}
	}

	// Defensive copy + sort. Callers may pass an informer-derived
	// slice that is shared with other goroutines or sorted in a
	// different order on rebuild; we don't want to surprise them
	// with hidden mutations, and we need a deterministic input
	// ordering so two Nodes building from the same membership snapshot
	// produce identical tables.
	sorted := make([]NodeID, len(nodes))
	copy(sorted, nodes)
	slices.Sort(sorted)

	N := len(sorted)
	offsets := make([]uint32, N)
	skips := make([]uint32, N)
	for i, id := range sorted {
		o, s := derive(id, M)
		offsets[i] = o
		skips[i] = s
	}

	slots := emptySlots(M)
	next := make([]uint32, N)
	counts := make(map[NodeID]int, N)
	for _, id := range sorted {
		counts[id] = 0
	}

	filled := uint32(0)
	for filled < M {
		for i := range N {
			cand := (offsets[i] + next[i]*skips[i]) % M
			for slots[cand] != Empty {
				next[i]++
				cand = (offsets[i] + next[i]*skips[i]) % M
			}
			slots[cand] = sorted[i]
			next[i]++
			counts[sorted[i]]++
			filled++
			if filled == M {
				break
			}
		}
	}

	return Table{
		Slots:     slots,
		SlotCount: M,
		Counts:    counts,
	}
}

// derive computes the (offset, skip) pair Maglev uses to walk the slot
// space for a given NodeID. h1 (offset) covers [0, M); h2 (skip) is
// reduced mod (M-1) and shifted into [1, M-1] so it can never be 0
// (a zero skip would re-visit the offset forever).
//
// SHA-256 is overkill cryptographically — Maglev only needs a low-
// collision hash family — but it is cheap, deterministic across Go
// versions / platforms, and avoids pulling in an external dependency.
// The first 8 bytes of the digest split cleanly into two uint32s, one
// per hash.
func derive(id NodeID, M uint32) (offset, skip uint32) {
	digest := sha256.Sum256([]byte(id))
	h1 := binary.BigEndian.Uint32(digest[0:4])
	h2 := binary.BigEndian.Uint32(digest[4:8])
	offset = h1 % M
	if M == 1 {
		// Degenerate case: there is only one slot, skip is irrelevant
		// because next[i]*skip never advances past the (single) slot
		// before it is taken. Return 1 so callers do not have to
		// special-case M == 1.
		return offset, 1
	}
	skip = (h2 % (M - 1)) + 1
	return offset, skip
}

func emptySlots(M uint32) []NodeID {
	out := make([]NodeID, M)
	// Empty == "" which is the zero value for string; the make() above
	// already gives us an all-Empty slice. Keeping the helper for
	// readability at the call site.
	return out
}

// String renders a compact summary of the table — slot count plus per-
// Node distribution — handy for log lines and test failure messages.
func (t Table) String() string {
	return fmt.Sprintf("maglev.Table{slots=%d nodes=%d}", t.SlotCount, len(t.Counts))
}
