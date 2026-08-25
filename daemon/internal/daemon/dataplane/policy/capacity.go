package policy

import (
	"errors"
	"fmt"
)

// CapacityError reports that one direction of one policy resource
// expands into more data plane entries than its window in the BPF rule
// array can hold.
//
// The direction it names was installed FAIL-CLOSED: zero entries, plus
// the meta state that keeps the direction in rule-list mode, so the
// evaluator falls through to the terminal deny for that direction. The
// other direction is untouched.
//
// It carries the numbers instead of a formatted message because the
// condition is permanent. A spec that does not fit never starts
// fitting on its own, so a caller must report it and stop, not retry.
type CapacityError struct {
	// Layer is the policy layer the id belongs to: "networkacl" or
	// "securitygroup".
	Layer     string
	ID        uint32
	Direction Direction
	Entries   int
	Limit     int
}

func (e *CapacityError) Error() string {
	return fmt.Sprintf("policy/%s: id %d %s expands to %d entries but the window holds %d; the direction was installed fail-closed",
		e.Layer, e.ID, e.Direction, e.Entries, e.Limit)
}

// CapacityErrorsFrom returns every CapacityError inside err, in the
// order Apply produced them, and nil for any other error. Callers use
// it to tell a spec that cannot fit (permanent: log it and forget the
// key) from a failed write (transient: worth retrying).
func CapacityErrorsFrom(err error) []*CapacityError {
	var found []*CapacityError
	collectCapacityErrors(err, &found)
	return found
}

func collectCapacityErrors(err error, found *[]*CapacityError) {
	switch e := err.(type) {
	case nil:
		return
	case *CapacityError:
		*found = append(*found, e)
	case interface{ Unwrap() []error }:
		for _, joined := range e.Unwrap() {
			collectCapacityErrors(joined, found)
		}
	case interface{ Unwrap() error }:
		collectCapacityErrors(e.Unwrap(), found)
	}
}

// fitRuleSet decides what a Store is allowed to write for rs.
//
// A direction that fits its window comes back unchanged. A direction
// that does not comes back EMPTY and marked as declaring rules, which
// is what fail-closed means here: the evaluator sees a direction in
// rule-list mode with nothing to match and falls through to the
// terminal deny, for that direction alone. Installing the prefix that
// fits instead would enforce a rule list nobody wrote.
//
// The returned RuleSet is what the data plane ends up holding, so it
// is also what the invalidator must record: falling back to
// fail-closed takes rules away, and the flows admitted under them have
// to be dropped.
func fitRuleSet(layer string, rs RuleSet, perDirection int) (RuleSet, error) {
	var errs []error
	if len(rs.Ingress) > perDirection {
		errs = append(errs, &CapacityError{
			Layer:     layer,
			ID:        rs.GroupID,
			Direction: DirIngress,
			Entries:   len(rs.Ingress),
			Limit:     perDirection,
		})
		rs.Ingress = nil
		rs.HasIngressRules = true
	}
	if len(rs.Egress) > perDirection {
		errs = append(errs, &CapacityError{
			Layer:     layer,
			ID:        rs.GroupID,
			Direction: DirEgress,
			Entries:   len(rs.Egress),
			Limit:     perDirection,
		})
		rs.Egress = nil
		rs.HasEgressRules = true
	}
	return rs, errors.Join(errs...)
}
