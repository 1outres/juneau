package bmp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/1outres/juneau/bgp-speaker/internal/bmp"
	gobgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

func TestTracker_PeerUp_AddsSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	tracker := bmp.NewTracker(bmp.WithNowFunc(func() time.Time { return now }))

	msg := buildPeerUp(t, "10.77.0.3", 64513, "10.77.0.2")

	tracker.HandleMessage(msg)

	got := tracker.Snapshot()
	if len(got) != 1 {
		t.Fatalf("Snapshot: want 1 session, got %d: %+v", len(got), got)
	}
	s := got[0]
	if s.PeerAddress != "10.77.0.3" {
		t.Errorf("PeerAddress: want %q, got %q", "10.77.0.3", s.PeerAddress)
	}
	if s.PeerAS != 64513 {
		t.Errorf("PeerAS: want %d, got %d", 64513, s.PeerAS)
	}
	if s.State != bmp.SessionStateUp {
		t.Errorf("State: want %q, got %q", bmp.SessionStateUp, s.State)
	}
	if !s.UpSince.Equal(now) {
		t.Errorf("UpSince: want %s, got %s", now, s.UpSince)
	}
	if s.LastError != "" {
		t.Errorf("LastError: want empty, got %q", s.LastError)
	}
}

func TestTracker_PeerDown_TransitionsToDown(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	tracker := bmp.NewTracker(bmp.WithNowFunc(func() time.Time { return now }))

	tracker.HandleMessage(buildPeerUp(t, "10.77.0.3", 64513, "10.77.0.2"))
	tracker.HandleMessage(buildPeerDownRemoteNoNotif(t, "10.77.0.3", 64513))

	got := tracker.Snapshot()
	if len(got) != 1 {
		t.Fatalf("Snapshot: want 1 session, got %d: %+v", len(got), got)
	}
	s := got[0]
	if s.State != bmp.SessionStateDown {
		t.Errorf("State: want %q, got %q", bmp.SessionStateDown, s.State)
	}
	if s.LastError == "" {
		t.Errorf("LastError: want non-empty, got empty")
	}
}

func TestTracker_PeerDown_WithNotification_RecordsBGPCode(t *testing.T) {
	t.Parallel()

	tracker := bmp.NewTracker()
	tracker.HandleMessage(buildPeerUp(t, "10.77.0.3", 64513, "10.77.0.2"))
	tracker.HandleMessage(buildPeerDownWithNotif(t, "10.77.0.3", 64513,
		gobgp.BGP_ERROR_CEASE, gobgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN))

	got := tracker.Snapshot()
	if len(got) != 1 {
		t.Fatalf("Snapshot: want 1 session, got %d", len(got))
	}
	s := got[0]
	if s.State != bmp.SessionStateDown {
		t.Fatalf("State: want %q, got %q", bmp.SessionStateDown, s.State)
	}
	if !strings.Contains(s.LastError, "cease") && !strings.Contains(s.LastError, "Cease") {
		t.Errorf("LastError: want to mention BGP cease, got %q", s.LastError)
	}
}

func TestTracker_OnDisconnect_DropsSessionsAndClearsConnected(t *testing.T) {
	t.Parallel()

	tracker := bmp.NewTracker()
	tracker.OnConnect()
	tracker.HandleMessage(buildPeerUp(t, "10.77.0.3", 64513, "10.77.0.2"))
	tracker.HandleMessage(buildPeerUp(t, "10.77.0.4", 64514, "10.77.0.2"))

	if !tracker.Connected() {
		t.Fatalf("Connected: want true before disconnect")
	}
	if got := len(tracker.Snapshot()); got != 2 {
		t.Fatalf("Snapshot before disconnect: want 2, got %d", got)
	}

	tracker.OnDisconnect()

	if tracker.Connected() {
		t.Errorf("Connected: want false after disconnect")
	}
	if got := len(tracker.Snapshot()); got != 0 {
		t.Errorf("Snapshot after disconnect: want 0, got %d", got)
	}
}

func TestTracker_ConnectedInitiallyFalse(t *testing.T) {
	t.Parallel()

	if bmp.NewTracker().Connected() {
		t.Errorf("new Tracker: want Connected=false")
	}
}

func buildPeerUp(t *testing.T, peerAddr string, peerAS uint32, localAddr string) *gobmp.BMPMessage {
	t.Helper()
	ph := gobmp.NewBMPPeerHeader(
		gobmp.BMP_PEER_TYPE_GLOBAL,
		0,
		0,
		peerAddr,
		peerAS,
		peerAddr,
		0,
	)
	open := gobgp.NewBGPOpenMessage(uint16(peerAS), 90, peerAddr, nil)
	return gobmp.NewBMPPeerUpNotification(*ph, localAddr, 179, 45678, open, open)
}

func buildPeerDownRemoteNoNotif(t *testing.T, peerAddr string, peerAS uint32) *gobmp.BMPMessage {
	t.Helper()
	ph := gobmp.NewBMPPeerHeader(gobmp.BMP_PEER_TYPE_GLOBAL, 0, 0, peerAddr, peerAS, peerAddr, 0)
	return gobmp.NewBMPPeerDownNotification(*ph, gobmp.BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION, nil, nil)
}

func buildPeerDownWithNotif(t *testing.T, peerAddr string, peerAS uint32, code, subcode uint8) *gobmp.BMPMessage {
	t.Helper()
	ph := gobmp.NewBMPPeerHeader(gobmp.BMP_PEER_TYPE_GLOBAL, 0, 0, peerAddr, peerAS, peerAddr, 0)
	notif := gobgp.NewBGPNotificationMessage(code, subcode, nil)
	return gobmp.NewBMPPeerDownNotification(*ph, gobmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION, notif, nil)
}
