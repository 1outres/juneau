package nodestate_test

import (
	"testing"
	"time"

	"github.com/1outres/juneau/bgp-speaker/internal/bmp"
	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
	"github.com/1outres/juneau/bgp-speaker/internal/peerindex"
	"github.com/google/go-cmp/cmp"
	gobgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuilder_Build_SessionsTranslatedViaPeerIndex(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	tracker := bmp.NewTracker(bmp.WithNowFunc(func() time.Time { return now }))
	idx := peerindex.New()
	idx.Set(map[string]string{"10.77.0.3": "upstream-a"})

	tracker.OnConnect()
	tracker.HandleMessage(mustPeerUp(t, "10.77.0.3", 64513, "10.77.0.2"))
	tracker.HandleMessage(mustPeerUp(t, "10.77.0.9", 64999, "10.77.0.2"))

	b := nodestate.NewBuilder("node-a", tracker, idx)
	status := b.Build(nodestate.Inputs{})

	if got := len(status.BGPSessions); got != 2 {
		t.Fatalf("BGPSessions: want 2, got %d", got)
	}
	s0, s1 := status.BGPSessions[0], status.BGPSessions[1]

	if s0.PeerAddress != "10.77.0.3" {
		t.Errorf("session[0].PeerAddress: want 10.77.0.3, got %q", s0.PeerAddress)
	}
	if s0.PeerName != "upstream-a" {
		t.Errorf("session[0].PeerName: want 'upstream-a', got %q", s0.PeerName)
	}
	if s0.State != string(bmp.SessionStateUp) {
		t.Errorf("session[0].State: want Up, got %q", s0.State)
	}
	if s0.UpSince == nil || !s0.UpSince.Time.Equal(now) {
		t.Errorf("session[0].UpSince: want %v, got %v", now, s0.UpSince)
	}

	if s1.PeerAddress != "10.77.0.9" {
		t.Errorf("session[1].PeerAddress: want 10.77.0.9, got %q", s1.PeerAddress)
	}
	if s1.PeerName != "" {
		t.Errorf("session[1].PeerName: want empty (unresolved), got %q", s1.PeerName)
	}
}

func TestBuilder_Build_AdvertisementsFromInputs(t *testing.T) {
	t.Parallel()

	lastSync := time.Date(2026, 4, 24, 9, 59, 0, 0, time.UTC)
	b := nodestate.NewBuilder("node-a", bmp.NewTracker(), peerindex.New())
	status := b.Build(nodestate.Inputs{
		Advertisements: []nodestate.Advertisement{
			{AddressPool: "pool-b", Prefixes: []string{"10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24"}, LastSyncedAt: lastSync},
			{AddressPool: "pool-a", Prefixes: []string{"10.1.0.0/24"}, LastSyncedAt: lastSync},
		},
	})

	if got := len(status.Advertisements); got != 2 {
		t.Fatalf("Advertisements: want 2, got %d", got)
	}
	a0 := status.Advertisements[0]
	if a0.AddressPool != "pool-a" {
		t.Errorf("Advertisements[0].AddressPool: want pool-a (sorted), got %q", a0.AddressPool)
	}
	if diff := cmp.Diff([]string{"10.1.0.0/24"}, a0.Prefixes); diff != "" {
		t.Errorf("Advertisements[0].Prefixes mismatch (-want +got):\n%s", diff)
	}
	if a0.LastSyncedAt == nil || !a0.LastSyncedAt.Time.Equal(lastSync) {
		t.Errorf("Advertisements[0].LastSyncedAt: want %v, got %v", lastSync, a0.LastSyncedAt)
	}

	a1 := status.Advertisements[1]
	if diff := cmp.Diff([]string{"10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24"}, a1.Prefixes); diff != "" {
		t.Errorf("Advertisements[1].Prefixes mismatch (-want +got):\n%s", diff)
	}
}

func TestBuilder_Build_AdvertisementPrefixes_Sorted(t *testing.T) {
	t.Parallel()

	b := nodestate.NewBuilder("node-a", bmp.NewTracker(), peerindex.New())
	status := b.Build(nodestate.Inputs{
		Advertisements: []nodestate.Advertisement{
			{AddressPool: "pool-a", Prefixes: []string{"10.3.0.0/24", "10.1.0.0/24", "10.2.0.0/24"}},
		},
	})
	want := []string{"10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"}
	if diff := cmp.Diff(want, status.Advertisements[0].Prefixes); diff != "" {
		t.Errorf("Prefixes mismatch (-want +got):\n%s", diff)
	}
}

func TestBuilder_Build_AdvertisementLastSyncedAt_ZeroOmitted(t *testing.T) {
	t.Parallel()

	b := nodestate.NewBuilder("node-a", bmp.NewTracker(), peerindex.New())
	status := b.Build(nodestate.Inputs{
		Advertisements: []nodestate.Advertisement{
			{AddressPool: "pool-a", Prefixes: []string{"10.1.0.0/24"}},
		},
	})

	if len(status.Advertisements) != 1 {
		t.Fatalf("Advertisements: want 1, got %d", len(status.Advertisements))
	}
	if status.Advertisements[0].LastSyncedAt != nil {
		t.Errorf("LastSyncedAt: want nil when zero time, got %v", status.Advertisements[0].LastSyncedAt)
	}
}

func TestBuilder_Build_Conditions_Healthy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	tracker := bmp.NewTracker()
	tracker.OnConnect()

	b := nodestate.NewBuilder("node-a", tracker, peerindex.New(),
		nodestate.WithNowFunc(func() time.Time { return now }))

	status := b.Build(nodestate.Inputs{BirdRunning: true})

	assertCondition(t, status.Conditions, "Ready", "True", "Healthy")
	assertCondition(t, status.Conditions, "BirdRunning", "True", "Running")
	assertCondition(t, status.Conditions, "BMPConnected", "True", "Connected")

	if status.Heartbeat == nil || !status.Heartbeat.Time.Equal(now) {
		t.Errorf("Heartbeat: want %v, got %v", now, status.Heartbeat)
	}
}

func TestBuilder_Build_Conditions_BMPDisconnected(t *testing.T) {
	t.Parallel()

	tracker := bmp.NewTracker() // not connected
	b := nodestate.NewBuilder("node-a", tracker, peerindex.New())

	status := b.Build(nodestate.Inputs{BirdRunning: true})

	assertCondition(t, status.Conditions, "Ready", "False", "BMPNotConnected")
	assertCondition(t, status.Conditions, "BirdRunning", "True", "Running")
	assertCondition(t, status.Conditions, "BMPConnected", "False", "Disconnected")
}

func TestBuilder_Build_Conditions_BirdNotRunning(t *testing.T) {
	t.Parallel()

	tracker := bmp.NewTracker()
	tracker.OnConnect()
	b := nodestate.NewBuilder("node-a", tracker, peerindex.New())

	status := b.Build(nodestate.Inputs{BirdRunning: false})

	assertCondition(t, status.Conditions, "Ready", "False", "BirdNotRunning")
	assertCondition(t, status.Conditions, "BirdRunning", "False", "NotRunning")
	assertCondition(t, status.Conditions, "BMPConnected", "True", "Connected")
}

func assertCondition(t *testing.T, conds []metav1.Condition, typ, status, reason string) {
	t.Helper()
	for _, c := range conds {
		if c.Type == typ {
			if string(c.Status) != status {
				t.Errorf("condition %s status: want %s, got %s", typ, status, c.Status)
			}
			if c.Reason != reason {
				t.Errorf("condition %s reason: want %s, got %s", typ, reason, c.Reason)
			}
			return
		}
	}
	t.Errorf("condition %s not found in %+v", typ, conds)
}

func TestBuilder_Build_Errors_StableOrderAndFiltering(t *testing.T) {
	t.Parallel()

	seen := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	b := nodestate.NewBuilder("node-a", bmp.NewTracker(), peerindex.New())
	status := b.Build(nodestate.Inputs{
		Errors: []nodestate.ResourceError{
			{ResourceKind: "BGPPeer", ResourceName: "z", Message: "bad", LastSeen: seen},
			{ResourceKind: "AddressPool", ResourceName: "y", Message: "invalid addr", LastSeen: seen},
			{ResourceKind: "BGPPeer", ResourceName: "a", Message: "missing ASN", LastSeen: seen},
		},
	})

	want := []struct {
		kind, name, msg string
	}{
		{"AddressPool", "y", "invalid addr"},
		{"BGPPeer", "a", "missing ASN"},
		{"BGPPeer", "z", "bad"},
	}
	if got := len(status.Errors); got != len(want) {
		t.Fatalf("Errors: want %d, got %d: %+v", len(want), got, status.Errors)
	}
	for i, w := range want {
		e := status.Errors[i]
		if e.ResourceKind != w.kind || e.ResourceName != w.name || e.Message != w.msg {
			t.Errorf("Errors[%d]: want {%s,%s,%s}, got {%s,%s,%s}",
				i, w.kind, w.name, w.msg, e.ResourceKind, e.ResourceName, e.Message)
		}
		if e.LastSeen == nil || !e.LastSeen.Time.Equal(seen) {
			t.Errorf("Errors[%d].LastSeen: want %v, got %v", i, seen, e.LastSeen)
		}
	}
}

func mustPeerUp(t *testing.T, peer string, peerAS uint32, local string) *gobmp.BMPMessage {
	t.Helper()
	ph := gobmp.NewBMPPeerHeader(gobmp.BMP_PEER_TYPE_GLOBAL, 0, 0, peer, peerAS, peer, 0)
	open := gobgp.NewBGPOpenMessage(uint16(peerAS), 90, peer, nil)
	return gobmp.NewBMPPeerUpNotification(*ph, local, 179, 45678, open, open)
}
