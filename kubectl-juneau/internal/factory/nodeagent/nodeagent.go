// Package nodeagent reserves the surface that Tier 2 commands will use
// to read BPF map state from the per-Node juneaud process. Today the
// only contract exposed is a sentinel error returned by Factory; the
// types here exist so callers (e.g. describe --with-bpf) can compile
// against an interface that will gain methods in a follow-up change
// without rippling import edits across the plugin.
//
// Concrete clients (gRPC over `kubectl exec` is the leading candidate)
// belong here when implemented. Until then, every Factory.NodeAgent
// call returns ErrNotImplemented and the surrounding command surfaces
// a clean "feature not available in this build" message.
package nodeagent

import "errors"

// ErrNotImplemented signals that the running kubectl-juneau build does
// not include node-agent connectivity. Tier 1 commands never reach this
// path; later tiers must handle it explicitly.
var ErrNotImplemented = errors.New("nodeagent: not implemented in this build")

// Client is the contract Tier 2 commands will depend on. It is empty
// today because no methods are stable enough to commit to. Adding
// methods later is a backward-compatible change for callers that fall
// back on ErrNotImplemented.
type Client interface {
	// Close releases any resources (port-forward sessions, gRPC conns).
	Close() error
}
