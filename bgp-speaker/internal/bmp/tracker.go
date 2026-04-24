package bmp

import (
	"fmt"
	"sort"
	"sync"
	"time"

	gobgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

type Tracker struct {
	nowFn func() time.Time

	mu        sync.RWMutex
	sessions  map[string]SessionState
	connected bool
}

type Option func(*Tracker)

func WithNowFunc(fn func() time.Time) Option {
	return func(t *Tracker) { t.nowFn = fn }
}

func NewTracker(opts ...Option) *Tracker {
	t := &Tracker{
		nowFn:    time.Now,
		sessions: make(map[string]SessionState),
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

func (t *Tracker) HandleMessage(msg *gobmp.BMPMessage) {
	if msg == nil {
		return
	}
	switch body := msg.Body.(type) {
	case *gobmp.BMPPeerUpNotification:
		t.onPeerUp(msg.PeerHeader)
	case *gobmp.BMPPeerDownNotification:
		t.onPeerDown(msg.PeerHeader, body)
	}
}

func (t *Tracker) onPeerUp(ph gobmp.BMPPeerHeader) {
	t.mu.Lock()
	defer t.mu.Unlock()
	addr := ph.PeerAddress.String()
	t.sessions[addr] = SessionState{
		PeerAddress: addr,
		PeerAS:      ph.PeerAS,
		State:       SessionStateUp,
		UpSince:     t.nowFn(),
	}
}

func (t *Tracker) onPeerDown(ph gobmp.BMPPeerHeader, body *gobmp.BMPPeerDownNotification) {
	t.mu.Lock()
	defer t.mu.Unlock()
	addr := ph.PeerAddress.String()
	prev := t.sessions[addr]
	prev.PeerAddress = addr
	prev.PeerAS = ph.PeerAS
	prev.State = SessionStateDown
	prev.UpSince = time.Time{}
	prev.LastError = formatPeerDown(body)
	t.sessions[addr] = prev
}

func formatPeerDown(body *gobmp.BMPPeerDownNotification) string {
	reason := bmpReasonText(body.Reason)
	if body.BGPNotification == nil {
		return reason
	}
	if n, ok := body.BGPNotification.Body.(*gobgp.BGPNotification); ok {
		code := bgpErrorCodeText(n.ErrorCode)
		sub := bgpErrorSubcodeText(n.ErrorCode, n.ErrorSubcode)
		return fmt.Sprintf("%s: %s/%s", reason, code, sub)
	}
	return reason
}

func bmpReasonText(reason uint8) string {
	switch reason {
	case gobmp.BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION:
		return "local-system-notification"
	case gobmp.BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION:
		return "local-system-no-notification"
	case gobmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION:
		return "remote-system-notification"
	case gobmp.BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION:
		return "remote-system-no-notification"
	case gobmp.BMP_PEER_DOWN_REASON_PEER_DE_CONFIGURED:
		return "peer-deconfigured"
	default:
		return fmt.Sprintf("reason-%d", reason)
	}
}

func bgpErrorCodeText(code uint8) string {
	switch code {
	case gobgp.BGP_ERROR_MESSAGE_HEADER_ERROR:
		return "message-header-error"
	case gobgp.BGP_ERROR_OPEN_MESSAGE_ERROR:
		return "open-message-error"
	case gobgp.BGP_ERROR_UPDATE_MESSAGE_ERROR:
		return "update-message-error"
	case gobgp.BGP_ERROR_HOLD_TIMER_EXPIRED:
		return "hold-timer-expired"
	case gobgp.BGP_ERROR_FSM_ERROR:
		return "fsm-error"
	case gobgp.BGP_ERROR_CEASE:
		return "cease"
	case gobgp.BGP_ERROR_ROUTE_REFRESH_MESSAGE_ERROR:
		return "route-refresh-message-error"
	default:
		return fmt.Sprintf("code-%d", code)
	}
}

func bgpErrorSubcodeText(code, sub uint8) string {
	if code != gobgp.BGP_ERROR_CEASE {
		return fmt.Sprintf("subcode-%d", sub)
	}
	switch sub {
	case gobgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED:
		return "max-prefixes-reached"
	case gobgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN:
		return "administrative-shutdown"
	case gobgp.BGP_ERROR_SUB_PEER_DECONFIGURED:
		return "peer-deconfigured"
	case gobgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET:
		return "administrative-reset"
	case gobgp.BGP_ERROR_SUB_CONNECTION_REJECTED:
		return "connection-rejected"
	case gobgp.BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE:
		return "other-configuration-change"
	case gobgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION:
		return "connection-collision-resolution"
	case gobgp.BGP_ERROR_SUB_OUT_OF_RESOURCES:
		return "out-of-resources"
	case gobgp.BGP_ERROR_SUB_HARD_RESET:
		return "hard-reset"
	default:
		return fmt.Sprintf("cease-subcode-%d", sub)
	}
}

func (t *Tracker) OnConnect() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connected = true
}

func (t *Tracker) OnDisconnect() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connected = false
	t.sessions = make(map[string]SessionState)
}

func (t *Tracker) Connected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connected
}

func (t *Tracker) Snapshot() []SessionState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]SessionState, 0, len(t.sessions))
	for _, s := range t.sessions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PeerAddress < out[j].PeerAddress })
	return out
}
