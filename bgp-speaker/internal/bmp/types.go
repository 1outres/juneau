package bmp

import "time"

type SessionState struct {
	PeerAddress string
	PeerAS      uint32
	State       State
	UpSince     time.Time
	LastError   string
}

type State string

const (
	SessionStateUnknown State = "Unknown"
	SessionStateUp      State = "Up"
	SessionStateDown    State = "Down"
)
