package serviceloadbalancer

import (
	"sync"
)

// Programmer is the contract between the userspace reconciler and
// whatever finally writes the dataplane state. Phase 6 ships a
// pure-Go in-memory implementation (used by tests and by
// production until the BPF maps land in Phase 7); Phase 7 swaps in
// a BPF-backed implementation that updates lb_service_map /
// lb_backend_map.
//
// Implementations must be safe for concurrent use: the reconciler
// is driven by a single workqueue today, but observers (debug RPC,
// status publisher) may read snapshots while the reconciler writes.
type Programmer interface {
	// Apply replaces the recorded state for the SLB key with desired.
	// A nil desired means "delete every entry for this key."
	Apply(key string, desired *LBService) error

	// Snapshot returns a defensive copy of the currently-recorded
	// state for every known key. Used by tests and the future
	// kubectl-juneau topology command. Order is not guaranteed.
	Snapshot() map[string]LBService
}

// InMemoryProgrammer is the default Programmer used until the BPF
// maps land. It tracks the desired state per SLB key in memory and
// is the substrate the unit tests assert against.
//
// The struct is intentionally minimal — no map handles, no
// allocations beyond the snapshot map — so the production daemon
// can run with it during Phase 6 without paying for a BPF
// programmer that does not exist yet, while still exercising the
// reconciler end-to-end.
type InMemoryProgrammer struct {
	mu    sync.Mutex
	state map[string]LBService
}

// NewInMemoryProgrammer returns an empty Programmer suitable for
// production-with-no-dataplane and for tests.
func NewInMemoryProgrammer() *InMemoryProgrammer {
	return &InMemoryProgrammer{state: map[string]LBService{}}
}

// Apply implements Programmer.
func (p *InMemoryProgrammer) Apply(key string, desired *LBService) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if desired == nil {
		delete(p.state, key)
		return nil
	}
	p.state[key] = cloneLBService(*desired)
	return nil
}

// Snapshot implements Programmer.
func (p *InMemoryProgrammer) Snapshot() map[string]LBService {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]LBService, len(p.state))
	for k, v := range p.state {
		out[k] = cloneLBService(v)
	}
	return out
}

func cloneLBService(in LBService) LBService {
	out := LBService{
		Key:         in.Key,
		VIP:         append(in.VIP[:0:0], in.VIP...),
		Advertising: in.Advertising,
	}
	if len(in.Ports) > 0 {
		out.Ports = append([]LBServicePort(nil), in.Ports...)
	}
	if len(in.Backends) > 0 {
		out.Backends = make([]LBBackend, len(in.Backends))
		for i, b := range in.Backends {
			out.Backends[i] = b
			out.Backends[i].PodIP = append(b.PodIP[:0:0], b.PodIP...)
		}
	}
	return out
}
