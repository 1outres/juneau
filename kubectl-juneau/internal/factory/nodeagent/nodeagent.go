// Package nodeagent connects kubectl-juneau to per-Node juneaud
// debug surfaces.
//
// Tier 1 commands never need this; the trace command (Tier 2) drives
// every interesting RPC. The package hides the transport choice
// (today: `kubectl exec`-tunnelled gRPC over the daemon's UDS) so
// commands depend on a stable Client interface even as the transport
// evolves.
package nodeagent

import (
	"context"
	"errors"

	"github.com/1outres/juneau/daemon/pkg/debugpb"
)

// ErrNotImplemented signals that the running kubectl-juneau build
// does not include node-agent connectivity for the requested
// transport. Commands handle this explicitly so a missing transport
// surfaces as a clean "feature not available in this build" message
// rather than a panic.
var ErrNotImplemented = errors.New("nodeagent: not implemented in this build")

// Client is the contract trace and other operational commands depend
// on. Implementations are responsible for hiding transport details
// (port-forward, exec-tunnel, future TLS-on-NodePort, etc.).
type Client interface {
	// Debug returns the debug RPC stub multiplexed over this client.
	Debug() debugpb.DebugClient
	// Close releases any resources (port-forward sessions, exec
	// streams, gRPC conns).
	Close() error
}

// Dialer constructs a Client targeting a specific Node. The factory
// implementation injects a Dialer; Tier 2 builds use exec-tunnel,
// while tests use a fake.
type Dialer interface {
	Dial(ctx context.Context, node string) (Client, error)
}
