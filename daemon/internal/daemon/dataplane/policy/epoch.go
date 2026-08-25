package policy

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

// Bumper publishes a new policy generation. A store calls it once the
// data plane can see a rule change, which makes every flow admitted
// under the previous rules get evaluated again.
type Bumper interface {
	Bump() error
}

// epochCounter is the whole contract Epoch needs from the BPF cell
// that holds the generation. Keeping it this small lets Epoch be
// tested without a real map, which would need CAP_BPF.
type epochCounter interface {
	Load() (uint32, error)
	Store(v uint32) error
}

// Epoch owns the policy generation counter published in
// policy_epoch_map. The data plane puts the current value in every
// policy_ct_map key it writes, so bumping the counter invalidates all
// admissions at once: later lookups build keys nobody has written and
// every flow is evaluated again. The conntrack GC then removes what
// the bump orphaned.
//
// Epoch is safe for concurrent use.
type Epoch struct {
	counter epochCounter

	mu      sync.Mutex
	current uint32
}

// epochIndex is the only key policy_epoch_map has.
const epochIndex uint32 = 0

// NewEpoch reads the counter from policy_epoch_map and starts one
// generation after it.
//
// Manager.Start wipes the pin path before loading, so today the map
// is fresh and the read returns 0. Reading first still matters if the
// maps ever outlive the daemon: a conntrack key then carries at most
// the last value the previous daemon published, and one past it puts
// every admission made before this daemon came up out of reach. Rules
// may have changed while the daemon was down, so dropping them is the
// safe reading.
func NewEpoch(m *ebpf.Map) (*Epoch, error) {
	return newEpoch(bpfEpochCounter{m: m})
}

func newEpoch(c epochCounter) (*Epoch, error) {
	previous, err := c.Load()
	if err != nil {
		return nil, fmt.Errorf("policy: read epoch counter: %w", err)
	}
	e := &Epoch{counter: c, current: previous + 1}
	if err := c.Store(e.current); err != nil {
		return nil, fmt.Errorf("policy: publish epoch %d: %w", e.current, err)
	}
	return e, nil
}

// Bump moves the data plane to the next generation.
func (e *Epoch) Bump() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	next := e.current + 1
	if err := e.counter.Store(next); err != nil {
		return fmt.Errorf("policy: publish epoch %d: %w", next, err)
	}
	e.current = next
	return nil
}

// Current reports the generation the data plane is enforcing.
func (e *Epoch) Current() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.current
}

// bpfEpochCounter adapts policy_epoch_map to epochCounter.
type bpfEpochCounter struct {
	m *ebpf.Map
}

func (c bpfEpochCounter) Load() (uint32, error) {
	var value uint32
	if err := c.m.Lookup(epochIndex, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func (c bpfEpochCounter) Store(v uint32) error {
	return c.m.Update(epochIndex, v, ebpf.UpdateAny)
}
