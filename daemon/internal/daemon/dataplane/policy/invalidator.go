package policy

import (
	"fmt"
	"reflect"
	"sync"
)

// invalidator decides when a rule change has to drop the flows the
// data plane already admitted.
//
// It remembers the content installed for each id because informer
// resyncs replay the same RuleSet on a timer. Bumping for those would
// make every controlled flow on the Node run the policy layers again
// for no reason.
type invalidator struct {
	layer  string
	bumper Bumper

	mu        sync.Mutex
	installed map[uint32]RuleSet
}

func newInvalidator(layer string, bumper Bumper) *invalidator {
	return &invalidator{
		layer:     layer,
		bumper:    bumper,
		installed: make(map[uint32]RuleSet),
	}
}

// applied invalidates admitted flows when rs differs from the content
// installed for id so far. Callers must have published rs to the data
// plane first, so a re-evaluated flow is matched against the new
// rules and not the old ones.
func (i *invalidator) applied(id uint32, rs RuleSet) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	previous, had := i.installed[id]
	if had && reflect.DeepEqual(previous, rs) {
		return nil
	}
	if err := i.bump(id); err != nil {
		return err
	}
	i.installed[id] = rs
	return nil
}

// deleted invalidates admitted flows after the rules for id are gone.
// It bumps unconditionally: a delete always takes rules away from the
// data plane, and deletes are rare enough that skipping the content
// check buys nothing.
func (i *invalidator) deleted(id uint32) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.bump(id); err != nil {
		return err
	}
	delete(i.installed, id)
	return nil
}

func (i *invalidator) bump(id uint32) error {
	if err := i.bumper.Bump(); err != nil {
		return fmt.Errorf("policy/%s: invalidate admitted flows after %d changed: %w", i.layer, id, err)
	}
	return nil
}
