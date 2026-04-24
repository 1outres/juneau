package peerindex

import (
	"maps"
	"sync"
)

// PeerIndex maps BGP peer IP addresses (as returned by BMP PeerHeader.PeerAddress.String())
// to the Kubernetes BGPPeer resource names that configured them. It is written
// by the reconciler after each bird.conf rebuild and read by the status builder.
type PeerIndex struct {
	mu   sync.RWMutex
	byIP map[string]string
}

func New() *PeerIndex {
	return &PeerIndex{byIP: map[string]string{}}
}

// Set replaces the mapping. A nil argument clears the index.
func (p *PeerIndex) Set(m map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m == nil {
		p.byIP = map[string]string{}
		return
	}
	p.byIP = maps.Clone(m)
}

// Name returns the BGPPeer resource name for peerAddr and true if present.
// Returns ("", false) on miss.
func (p *PeerIndex) Name(peerAddr string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	name, ok := p.byIP[peerAddr]
	return name, ok
}
