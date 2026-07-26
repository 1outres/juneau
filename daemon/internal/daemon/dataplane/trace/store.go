package trace

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// Store programs the BPF trace_active counter, trace_config_map and
// trace_tuple_map from TraceSession reconciler events. It is the
// single point of write access to the trace BPF state — readers
// (ringbuf reader, debug gRPC) only consume.
//
// Concurrent Apply / Delete calls are serialised internally so the
// active counter stays consistent with the per-session entries.
type Store struct {
	active   *ebpf.Map
	config   *ebpf.Map
	tuples   *ebpf.Map
	mu       sync.Mutex
	sessions map[uint32]*sessionState
	now      func() time.Time
	bootNs   int64 // CLOCK_MONOTONIC nanoseconds at process start
}

// sessionState tracks the userspace bookkeeping required to clean up
// a session: which tuples were programmed, when it expires, and the
// matching CRD generation so a stale reconcile event does not undo a
// fresh apply.
type sessionState struct {
	traceID    uint32
	expiresAt  time.Time
	tuples     map[TupleKey]Direction
	generation int64
}

// NewStore wires the Store to the BPF maps that ebpf.Collection has
// already loaded.
func NewStore(active, config, tuples *ebpf.Map) *Store {
	return &Store{
		active:   active,
		config:   config,
		tuples:   tuples,
		sessions: make(map[uint32]*sessionState),
		now:      time.Now,
		bootNs:   monoNowNs() - int64(time.Since(processStart)),
	}
}

// Apply (re-)programs the BPF state for one session. Tuples not
// present in the new set are removed, expiry is refreshed, and the
// active counter is reconciled.
//
// Returns an error only when the underlying map operations fail; CRD
// validation must reject malformed inputs upstream.
func (s *Store) Apply(spec SessionSpec) error {
	if spec.TraceID == 0 {
		return errors.New("trace.Store: traceID must be non-zero")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.sessions[spec.TraceID]
	if prev != nil && spec.Generation < prev.generation {
		// Reconciler rate limiting can deliver an older event after a
		// newer one; trust generation as the linearisation point.
		return nil
	}

	// Program / refresh the per-session config slot.
	cfg := storeConfigVal(spec, s.bootNs)
	if err := s.config.Update(spec.TraceID, cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("trace.Store: write config %d: %w", spec.TraceID, err)
	}

	desired := tupleSet(spec.Tuples)
	if prev != nil {
		// Drop tuples that left the session. Other sessions may still
		// claim them — we use traceID equality on the stored value to
		// decide ownership.
		for k := range prev.tuples {
			if _, keep := desired[k]; keep {
				continue
			}
			if err := s.deleteTupleIfOwned(k, spec.TraceID); err != nil {
				return err
			}
		}
	}

	for k, dir := range desired {
		if err := s.putTuple(k, spec.TraceID, dir); err != nil {
			return err
		}
	}

	s.sessions[spec.TraceID] = &sessionState{
		traceID:    spec.TraceID,
		expiresAt:  spec.ExpiresAt,
		tuples:     desired,
		generation: spec.Generation,
	}
	return s.refreshActiveCount()
}

// Delete removes a session's BPF state. Idempotent; calling Delete on
// an unknown traceID is a no-op so reconciler tombstone events do not
// surface as errors.
func (s *Store) Delete(traceID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(traceID)
}

func (s *Store) deleteLocked(traceID uint32) error {
	if _, ok := s.sessions[traceID]; !ok {
		return nil
	}
	delete(s.sessions, traceID)

	// Scan trace_tuple_map for every entry this session owns rather than
	// only the tuples we tracked in userspace. The dataplane auto-learns
	// reverse (reply) tuples directly into the map without going through
	// the Store, so a tracked-set-only sweep would leak them until the
	// daemon restarts. Owning the value's trace_id makes the scan
	// authoritative.
	if err := s.deleteTuplesOwnedBy(traceID); err != nil {
		return err
	}
	if err := s.config.Delete(traceID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("trace.Store: delete config %d: %w", traceID, err)
	}
	return s.refreshActiveCount()
}

// deleteTuplesOwnedBy removes every trace_tuple_map entry whose value's
// trace_id matches. Keys are collected first, then deleted, because
// mutating a BPF hash map mid-iteration risks skipping entries.
func (s *Store) deleteTuplesOwnedBy(traceID uint32) error {
	var (
		keyBytes [TupleKeyBytes]byte
		val      TupleVal
		victims  [][]byte
	)
	it := s.tuples.Iterate()
	for it.Next(&keyBytes, &val) {
		if val.TraceID != traceID {
			continue
		}
		k := make([]byte, TupleKeyBytes)
		copy(k, keyBytes[:])
		victims = append(victims, k)
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("trace.Store: iterate tuples: %w", err)
	}
	for _, k := range victims {
		if err := s.tuples.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("trace.Store: delete tuple: %w", err)
		}
	}
	return nil
}

// LearnTuple installs a learned post-NAT continuation tuple with an
// explicit leg. Used by the debug gRPC server when kubectl mirrors a
// post-NAT forward tuple (Request) it decoded from one daemon over to
// the peers whose dataplane may also see the continuation. The
// dataplane itself auto-learns the matching reply tuple locally, so
// this path only carries forward continuations.
func (s *Store) LearnTuple(traceID uint32, key TupleKey, dir Direction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sessions[traceID]
	if !ok {
		return errors.New("trace.Store: unknown traceID for learned tuple")
	}
	if existing, exists := st.tuples[key]; exists && existing == dir {
		return nil
	}
	if err := s.putTuple(key, traceID, dir); err != nil {
		return err
	}
	st.tuples[key] = dir
	return nil
}

// LearnReverseFromEvent installs the opposite-leg (reply) mirror of a
// tuple this node observed, replacing the in-kernel reverse-learn that
// was removed to fit the BPF combined-stack budget. It is a no-op for
// events that seed no mirror, so the ringbuf reader can call it
// unconditionally on every decoded event.
func (s *Store) LearnReverseFromEvent(ev Event) error {
	key, dir, ok := reverseMirrorFromEvent(ev)
	if !ok {
		return nil
	}
	return s.learnReverseMirror(ev.TraceID, key, dir)
}

// learnReverseMirror writes a reply-mirror tuple with NOEXIST semantics
// so it never clobbers a kubectl-seeded Reply mirror or an existing
// Request tuple — the BPF reverse-learn used BPF_NOEXIST for exactly the
// same reason.
//
// The mirror is deliberately not recorded in sessionState.tuples. Like
// the dataplane's former direct map writes, it is reaped by Delete's
// whole-map ownership scan (deleteTuplesOwnedBy), and keeping it out of
// the Apply diff set stops a status-patch reconcile from sweeping it
// between a request and its reply.
func (s *Store) learnReverseMirror(traceID uint32, key TupleKey, dir Direction) error {
	if traceID == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[traceID]; !ok {
		// Session torn down between event emission and decode; nothing to
		// attach the mirror to.
		return nil
	}
	keyBytes, err := key.MarshalBinary()
	if err != nil {
		return fmt.Errorf("trace.Store: marshal reverse tuple: %w", err)
	}
	val := TupleVal{TraceID: traceID, Direction: uint8(dir)}
	if err := s.tuples.Update(keyBytes, val, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			// A kubectl-seeded mirror or another session already owns this
			// key; leave it authoritative.
			return nil
		}
		return fmt.Errorf("trace.Store: write reverse tuple: %w", err)
	}
	return nil
}

// GC sweeps expired sessions out of BPF state. Called on a timer so
// that a vanished kubectl (whose CRD finalizer never ran) eventually
// stops consuming dataplane resources.
func (s *Store) GC() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, st := range s.sessions {
		if !st.expiresAt.IsZero() && now.After(st.expiresAt) {
			if err := s.deleteLocked(id); err != nil {
				return err
			}
		}
	}
	return nil
}

// ActiveTraceIDs is exposed for tests and the debug gRPC server's
// snapshot endpoint.
func (s *Store) ActiveTraceIDs() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint32, 0, len(s.sessions))
	for id := range s.sessions {
		out = append(out, id)
	}
	return out
}

func (s *Store) putTuple(k TupleKey, traceID uint32, dir Direction) error {
	keyBytes, err := k.MarshalBinary()
	if err != nil {
		return fmt.Errorf("trace.Store: marshal tuple: %w", err)
	}
	val := TupleVal{TraceID: traceID, Direction: uint8(dir)}
	if err := s.tuples.Update(keyBytes, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("trace.Store: write tuple: %w", err)
	}
	return nil
}

func (s *Store) deleteTupleIfOwned(k TupleKey, traceID uint32) error {
	keyBytes, err := k.MarshalBinary()
	if err != nil {
		return fmt.Errorf("trace.Store: marshal tuple: %w", err)
	}
	var existing TupleVal
	if err := s.tuples.Lookup(keyBytes, &existing); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("trace.Store: lookup tuple: %w", err)
	}
	if existing.TraceID != traceID {
		// A concurrent session already owns this tuple; leave it.
		return nil
	}
	if err := s.tuples.Delete(keyBytes); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("trace.Store: delete tuple: %w", err)
	}
	return nil
}

func (s *Store) refreshActiveCount() error {
	count := uint32(len(s.sessions))
	if err := s.active.Update(uint32(0), count, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("trace.Store: write active count: %w", err)
	}
	return nil
}

// Tuple pairs a trace_tuple_map key with the leg it is tagged as.
// kubectl-computed forward tuples are Request; the reverse mirrors it
// precomputes are Reply.
type Tuple struct {
	Key       TupleKey
	Direction Direction
}

// SessionSpec is the daemon-side projection of TraceSession.spec —
// the parts the BPF data plane cares about. The reconciler builds it
// from the CRD; tests build it directly.
type SessionSpec struct {
	TraceID      uint32
	Generation   int64
	ExpiresAt    time.Time
	CaptureFlags CaptureFlag
	Level        CaptureLevel
	Mode         uint8 // 0=ObserveOnly, 1=ActiveProbe
	Tuples       []Tuple
}

func storeConfigVal(spec SessionSpec, bootNs int64) any {
	type configVal struct {
		ExpiresNs    uint64
		CaptureFlags uint32
		Level        uint8
		Mode         uint8
		Pad          [2]uint8
	}
	v := configVal{
		CaptureFlags: uint32(spec.CaptureFlags),
		Level:        uint8(spec.Level),
		Mode:         spec.Mode,
	}
	if !spec.ExpiresAt.IsZero() {
		// Express expiry on the kernel's CLOCK_MONOTONIC. We anchor
		// at process start (bootNs vs processStart's wallclock) so
		// the BPF helper can compare via bpf_ktime_get_ns directly.
		nowMono := monoNowNs()
		ahead := time.Until(spec.ExpiresAt)
		if ahead < 0 {
			// Expiry is already in the past; encode as 1 ns so BPF
			// treats every packet as expired. Reconciler will delete
			// us on the next GC tick.
			v.ExpiresNs = uint64(nowMono - 1)
		} else {
			v.ExpiresNs = uint64(nowMono + int64(ahead))
		}
	}
	return v
}

func tupleSet(in []Tuple) map[TupleKey]Direction {
	out := make(map[TupleKey]Direction, len(in))
	for _, t := range in {
		out[t.Key] = t.Direction
	}
	return out
}
