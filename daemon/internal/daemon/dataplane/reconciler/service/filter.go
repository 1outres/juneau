package service

import (
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"

	"github.com/1outres/juneau/daemon/internal/daemon/svcpolicy"
)

// applyPolicy projects the resolved backend candidates through the
// per-Service BackendSelectionPolicy. The output is the per-port set
// the BPF reconciler should commit to backend_map.
//
// Two filters apply, in order:
//
//  1. internalTrafficPolicy=Local — when the policy is set, drop every
//     candidate whose endpoint.NodeName disagrees with the local node.
//     This must run first: kube-proxy's iTP=Local semantics treat a
//     Service with no local endpoints as "drop", even if remote
//     endpoints would otherwise be Ready.
//
//  2. Endpoint readiness — within the (possibly Local-restricted)
//     candidate set, admit Ready endpoints unconditionally; fall back
//     to Serving && !Terminating only when no Ready endpoint exists.
//     This preserves graceful termination: clients that already
//     opened connections still hit the same backends, but new
//     sessions skip terminating Pods unless the Service is otherwise
//     empty.
//
// The function is pure: same inputs → same outputs, no I/O. That keeps
// it directly unit-testable through resolved backend stubs.
func applyPolicy(input map[corev1.ServicePort][]resolvedBackend, policy svcpolicy.BackendSelectionPolicy, localNode string) map[corev1.ServicePort][]resolvedBackend {
	if input == nil {
		return nil
	}
	out := make(map[corev1.ServicePort][]resolvedBackend, len(input))
	for port, backends := range input {
		filtered := backends
		if policy.InternalLocal {
			filtered = retainLocal(filtered, localNode)
		}
		out[port] = admitByConditions(filtered)
	}
	return out
}

// admitByConditions favours Ready endpoints. Falls back to
// Serving && !Terminating only when no Ready endpoint exists for the
// (Service × port) pair. Mirrors kube-proxy's
// ProxyTerminatingEndpoints behaviour.
func admitByConditions(backends []resolvedBackend) []resolvedBackend {
	if len(backends) == 0 {
		return backends
	}
	ready := backends[:0:0]
	fallback := backends[:0:0]
	for _, b := range backends {
		if b.ready {
			ready = append(ready, b)
			continue
		}
		if b.serving && !b.terminating {
			fallback = append(fallback, b)
		}
	}
	if len(ready) > 0 {
		return ready
	}
	return fallback
}

// retainLocal restricts the candidate set to backends whose endpoint
// nodeName matches localNode. Returns nil when localNode is empty:
// iTP=Local without a known local Node identity is a misconfiguration
// (the boot-time --node-name flag is Required, so this branch should
// be unreachable in production), but we fail closed here as
// defence-in-depth so the policy is never silently bypassed. Mirrors
// kube-proxy: no local backend → drop, never fall back to remote.
func retainLocal(backends []resolvedBackend, localNode string) []resolvedBackend {
	if localNode == "" {
		zap.S().Warn("service: retainLocal called with empty localNode; iTP=Local cannot be enforced, dropping all backends. Check daemon --node-name flag.")
		return nil
	}
	out := backends[:0:0]
	for _, b := range backends {
		if b.nodeName == localNode {
			out = append(out, b)
		}
	}
	return out
}
