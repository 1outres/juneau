package trace

import (
	"sync"
	"sync/atomic"
)

// Bus fans out trace events to in-process subscribers. The debug
// gRPC server is the canonical subscriber; tests can plug in their
// own. The bus owns no goroutines — Publish runs synchronously on
// the caller's goroutine, with non-blocking sends to subscriber
// channels (overflow drops, see the Drops counter).
//
// Subscribers receive a filtered stream: each subscription declares
// the set of trace_ids it cares about, so a client watching trace
// A does not pay decode cost for unrelated events on this node.
type Bus struct {
	mu           sync.RWMutex
	subscribers  map[*subscription]struct{}
	publishedCnt atomic.Uint64
	dropCnt      atomic.Uint64
}

// NewBus constructs an empty Bus. Subscribers attach via Subscribe;
// the bus has no implicit fanout state until at least one subscriber
// connects, so the no-op cost when no kubectl is connected is one
// atomic load per Publish.
func NewBus() *Bus {
	return &Bus{subscribers: make(map[*subscription]struct{})}
}

// Subscription is the handle a subscriber holds onto to receive
// events and to detach.
type Subscription struct {
	bus *Bus
	sub *subscription
}

type subscription struct {
	traceIDs map[uint32]struct{} // empty == "every trace_id on this node"
	ch       chan Event
	closed   atomic.Bool
}

// Subscribe returns a Subscription whose channel receives every event
// whose TraceID is in `traceIDs`. Pass an empty slice to receive
// every event. `bufSize` is the per-subscription channel capacity —
// short enough to bound memory, long enough to absorb burst.
//
// Cleanup is mandatory: callers must Close the returned Subscription
// when done so the bus stops sending.
func (b *Bus) Subscribe(traceIDs []uint32, bufSize int) *Subscription {
	if bufSize <= 0 {
		bufSize = 256
	}
	sub := &subscription{
		traceIDs: idSet(traceIDs),
		ch:       make(chan Event, bufSize),
	}
	b.mu.Lock()
	b.subscribers[sub] = struct{}{}
	b.mu.Unlock()
	return &Subscription{bus: b, sub: sub}
}

// Channel returns the receive end of the subscription. Closed when
// Subscription.Close is called.
func (s *Subscription) Channel() <-chan Event { return s.sub.ch }

// Close detaches the subscription and closes its channel. Idempotent.
func (s *Subscription) Close() {
	if s.sub.closed.Swap(true) {
		return
	}
	s.bus.mu.Lock()
	delete(s.bus.subscribers, s.sub)
	s.bus.mu.Unlock()
	close(s.sub.ch)
}

// Publish dispatches an event to every matching subscriber. Sends
// are non-blocking; on a full channel the event is dropped and the
// drop counter incremented. Bounded buffering keeps a slow consumer
// from backpressuring the ringbuf reader.
func (b *Bus) Publish(ev Event) {
	b.publishedCnt.Add(1)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for sub := range b.subscribers {
		if len(sub.traceIDs) > 0 {
			if _, ok := sub.traceIDs[ev.TraceID]; !ok {
				continue
			}
		}
		select {
		case sub.ch <- ev:
		default:
			b.dropCnt.Add(1)
		}
	}
}

// Stats returns counters useful for observability and tests.
func (b *Bus) Stats() (published, drops uint64) {
	return b.publishedCnt.Load(), b.dropCnt.Load()
}

func idSet(ids []uint32) map[uint32]struct{} {
	if len(ids) == 0 {
		return nil
	}
	out := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}
