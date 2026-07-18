package trace

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// Reader drains the trace_events ringbuf and forwards decoded events
// to a Bus. One Reader per node is sufficient — the BPF ringbuf is
// MPSC across BPF programs but SPSC at the userspace boundary.
//
// The Reader integrates with cilium/ebpf's ringbuf.Reader, which
// blocks on a poll() syscall and unblocks when ctx is cancelled.
type Reader struct {
	rb    *ringbuf.Reader
	bus   *Bus
	store *Store
}

// NewReader builds a Reader bound to the kernel ringbuf. Caller
// retains ownership of the underlying *ebpf.Map; closing the Reader
// closes the ringbuf reader handle, not the map.
//
// store is used to install the opposite-leg (reply) mirror of tuples
// this node observes — the userspace successor to the BPF reverse-learn
// that was removed to fit the combined-stack budget. A nil store
// disables mirror learning (the live stream still flows); tests that
// only exercise decoding pass nil.
func NewReader(events *ebpf.Map, bus *Bus, store *Store) (*Reader, error) {
	rb, err := ringbuf.NewReader(events)
	if err != nil {
		return nil, fmt.Errorf("trace.Reader: open ringbuf: %w", err)
	}
	return &Reader{rb: rb, bus: bus, store: store}, nil
}

// Run blocks until ctx is cancelled, dispatching every record to the
// bus. Decode errors are logged and skipped — a malformed record
// must not stop the whole stream.
func (r *Reader) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = r.rb.Close()
	}()

	for {
		rec, err := r.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("trace.Reader: read: %w", err)
		}
		ev, err := DecodeEvent(rec.RawSample)
		if err != nil {
			zap.S().Warnw("trace: skipping malformed event", "err", err, "len", len(rec.RawSample))
			continue
		}
		// Install the reply mirror of this node's observed tuple before
		// publishing, so the return leg resolves the same trace_id. This
		// is the userspace successor to the removed BPF reverse-learn; a
		// mirror-write failure must not drop the event from the stream.
		if r.store != nil {
			if err := r.store.LearnReverseFromEvent(ev); err != nil {
				zap.S().Warnw("trace: reverse-mirror learn failed", "err", err, "traceID", ev.TraceID)
			}
		}
		r.bus.Publish(ev)
	}
}

// Close releases the underlying ringbuf reader. Safe to call
// multiple times.
func (r *Reader) Close() error { return r.rb.Close() }
