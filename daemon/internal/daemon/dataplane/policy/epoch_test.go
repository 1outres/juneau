package policy

import (
	"errors"
	"sync"
	"testing"
)

type fakeEpochCounter struct {
	mu       sync.Mutex
	value    uint32
	loads    int
	stores   int
	loadErr  error
	storeErr error
}

func (c *fakeEpochCounter) Load() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads++
	if c.loadErr != nil {
		return 0, c.loadErr
	}
	return c.value, nil
}

func (c *fakeEpochCounter) Store(v uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stores++
	if c.storeErr != nil {
		return c.storeErr
	}
	c.value = v
	return nil
}

func (c *fakeEpochCounter) read() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

func TestNewEpochStartsAfterThePersistedValue(t *testing.T) {
	c := &fakeEpochCounter{value: 41}

	e, err := newEpoch(c)
	if err != nil {
		t.Fatalf("newEpoch: %v", err)
	}

	if got := e.Current(); got != 42 {
		t.Errorf("Current() = %d, want 42", got)
	}
	if got := c.read(); got != 42 {
		t.Errorf("counter = %d, want 42 (must be published immediately)", got)
	}
}

func TestNewEpochPublishesFromZero(t *testing.T) {
	c := &fakeEpochCounter{}

	e, err := newEpoch(c)
	if err != nil {
		t.Fatalf("newEpoch: %v", err)
	}

	if got := e.Current(); got != 1 {
		t.Errorf("Current() = %d, want 1", got)
	}
	if c.stores != 1 {
		t.Errorf("stores = %d, want 1", c.stores)
	}
}

func TestNewEpochReportsLoadFailure(t *testing.T) {
	want := errors.New("boom")
	c := &fakeEpochCounter{loadErr: want}

	if _, err := newEpoch(c); !errors.Is(err, want) {
		t.Fatalf("newEpoch error = %v, want %v", err, want)
	}
}

func TestNewEpochReportsStoreFailure(t *testing.T) {
	want := errors.New("boom")
	c := &fakeEpochCounter{storeErr: want}

	if _, err := newEpoch(c); !errors.Is(err, want) {
		t.Fatalf("newEpoch error = %v, want %v", err, want)
	}
}

func TestEpochBumpAdvancesTheCounter(t *testing.T) {
	c := &fakeEpochCounter{value: 7}
	e, err := newEpoch(c)
	if err != nil {
		t.Fatalf("newEpoch: %v", err)
	}

	if err := e.Bump(); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	if err := e.Bump(); err != nil {
		t.Fatalf("Bump: %v", err)
	}

	if got := e.Current(); got != 10 {
		t.Errorf("Current() = %d, want 10", got)
	}
	if got := c.read(); got != 10 {
		t.Errorf("counter = %d, want 10", got)
	}
}

func TestEpochBumpKeepsTheCounterOnFailure(t *testing.T) {
	c := &fakeEpochCounter{value: 3}
	e, err := newEpoch(c)
	if err != nil {
		t.Fatalf("newEpoch: %v", err)
	}

	want := errors.New("boom")
	c.storeErr = want
	if err := e.Bump(); !errors.Is(err, want) {
		t.Fatalf("Bump error = %v, want %v", err, want)
	}

	if got := e.Current(); got != 4 {
		t.Errorf("Current() = %d, want 4 (a failed publish must not advance)", got)
	}
}

func TestEpochBumpIsSafeUnderConcurrency(t *testing.T) {
	const goroutines = 8
	const perGoroutine = 200

	c := &fakeEpochCounter{}
	e, err := newEpoch(c)
	if err != nil {
		t.Fatalf("newEpoch: %v", err)
	}
	start := e.Current()

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perGoroutine {
				if err := e.Bump(); err != nil {
					t.Errorf("Bump: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	want := start + goroutines*perGoroutine
	if got := e.Current(); got != want {
		t.Errorf("Current() = %d, want %d", got, want)
	}
	if got := c.read(); got != want {
		t.Errorf("counter = %d, want %d", got, want)
	}
}
