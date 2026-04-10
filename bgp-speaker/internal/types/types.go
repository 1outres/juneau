package types

import "net"

type DesiredConfig struct {
	Peers []*Peer
}

type Peer struct {
	LocalASN  uint32
	RemoteIP  string
	RemoteASN uint32

	Prefixes []*net.IPNet
}
