package trace

import (
	"testing"
)

func TestBusSubscribeFiltersByTraceID(t *testing.T) {
	bus := NewBus()
	a := bus.Subscribe([]uint32{1}, 4)
	b := bus.Subscribe([]uint32{2}, 4)
	c := bus.Subscribe(nil, 4)
	defer a.Close()
	defer b.Close()
	defer c.Close()

	bus.Publish(Event{TraceID: 1})
	bus.Publish(Event{TraceID: 2})
	bus.Publish(Event{TraceID: 3})

	if got := drainCount(a); got != 1 {
		t.Fatalf("subscriber a got %d (want 1)", got)
	}
	if got := drainCount(b); got != 1 {
		t.Fatalf("subscriber b got %d (want 1)", got)
	}
	if got := drainCount(c); got != 3 {
		t.Fatalf("subscriber c got %d (want 3)", got)
	}
}

func TestBusDropsOnFullChannel(t *testing.T) {
	bus := NewBus()
	sub := bus.Subscribe(nil, 1)
	defer sub.Close()

	bus.Publish(Event{TraceID: 1})
	bus.Publish(Event{TraceID: 2}) // should be dropped
	bus.Publish(Event{TraceID: 3}) // should be dropped

	_, drops := bus.Stats()
	if drops != 2 {
		t.Fatalf("drops = %d (want 2)", drops)
	}
}

func drainCount(s *Subscription) int {
	n := 0
	for {
		select {
		case _, ok := <-s.Channel():
			if !ok {
				return n
			}
			n++
		default:
			return n
		}
	}
}
