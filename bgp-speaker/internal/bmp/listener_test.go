package bmp_test

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/1outres/juneau/bgp-speaker/internal/bmp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

func TestListener_HandleConn_PeerUpReachesTracker(t *testing.T) {
	t.Parallel()

	tracker := bmp.NewTracker(bmp.WithNowFunc(func() time.Time {
		return time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	}))
	listener := bmp.NewListener(tracker)

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	payload := serializeBMP(t, buildPeerUp(t, "10.77.0.3", 64513, "10.77.0.2"))

	done := make(chan error, 1)
	go func() { done <- listener.HandleConn(server) }()

	if _, err := client.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close client: %v", err)
	}

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("HandleConn returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConn did not return after client close")
	}

	sessions := tracker.Snapshot()
	if len(sessions) != 0 {
		t.Errorf("Snapshot after disconnect: want 0 sessions (all dropped), got %d", len(sessions))
	}
	if tracker.Connected() {
		t.Errorf("Connected: want false after disconnect")
	}
}

func TestListener_HandleConn_SetsConnectedWhileReading(t *testing.T) {
	t.Parallel()

	tracker := bmp.NewTracker()
	listener := bmp.NewListener(tracker)

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	done := make(chan error, 1)
	go func() { done <- listener.HandleConn(server) }()

	waitUntil(t, 2*time.Second, func() bool { return tracker.Connected() })

	// While connection is open, Connected should be true.
	if !tracker.Connected() {
		t.Fatalf("Connected: want true while conn open")
	}

	_ = client.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConn did not return after client close")
	}

	if tracker.Connected() {
		t.Errorf("Connected: want false after close")
	}
}

func serializeBMP(t *testing.T, msg *gobmp.BMPMessage) []byte {
	t.Helper()
	b, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return b
}

func waitUntil(t *testing.T, d time.Duration, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("waitUntil: predicate never became true")
}
