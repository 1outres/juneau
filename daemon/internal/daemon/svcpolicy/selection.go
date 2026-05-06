package svcpolicy

import (
	"time"

	corev1 "k8s.io/api/core/v1"
)

// DefaultClientIPAffinityTimeout matches the upstream Kubernetes
// default for ClientIP session affinity (3 hours). Used when
// Service.spec.sessionAffinityConfig.clientIP.timeoutSeconds is left
// unset by the user.
const DefaultClientIPAffinityTimeout = 3 * time.Hour

// AffinityMode enumerates how the data plane should pick a backend
// across packets that share a Service hit.
type AffinityMode uint8

const (
	// AffinityNone is stateless 5-tuple hashing — the historical
	// default for every Juneau Service.
	AffinityNone AffinityMode = iota
	// AffinityClientIP makes successive packets from the same caller
	// IP land on the same backend index for AffinityPolicy.Timeout.
	AffinityClientIP
)

// AffinityPolicy captures the per-Service "stickiness" knob.
//
// Mode==AffinityNone is the absence of a policy and Timeout is
// ignored. Mode==AffinityClientIP requires Timeout > 0; the
// reconciler is expected to ensure that.
type AffinityPolicy struct {
	Mode    AffinityMode
	Timeout time.Duration
}

// BackendSelectionPolicy is the value object that captures every
// per-Service "how should the data plane choose a backend" decision
// derived purely from the Service spec.
//
// One source of truth keeps the BPF reconciler, debug dumps, and any
// future userspace consumer (e.g. a virtual-service hairpin) aligned
// on the same interpretation. The struct intentionally only carries
// Service-spec-level intent: which Node-local view it produces (e.g.
// the actual local backend list under InternalLocal=true) is the
// reconciler's responsibility because that decision needs the
// daemon's nodeName.
type BackendSelectionPolicy struct {
	// InternalLocal is set when Service.spec.internalTrafficPolicy=
	// Local. The reconciler must restrict backend_map to backends
	// whose endpoint.nodeName matches the local Node, dropping
	// Service traffic when no such backend exists. Cluster-policy
	// (the default) installs every reachable backend.
	InternalLocal bool

	// Affinity describes the sessionAffinity stickiness, if any.
	Affinity AffinityPolicy
}

// IsClusterInternal reports whether the policy is the default
// "spread across every backend in the cluster" behaviour, useful
// when callers want a cheap "is anything special configured" check.
func (p BackendSelectionPolicy) IsClusterInternal() bool {
	return !p.InternalLocal
}

// SelectionPolicyOf is the single source of truth that translates a
// Kubernetes Service into Juneau's backend-selection intent.
//
// The function is intentionally pure (no Kubernetes API access) and
// returns zero-value defaults for nil / cluster-policy / no-affinity
// so callers can use it unconditionally without nil checks.
func SelectionPolicyOf(svc *corev1.Service) BackendSelectionPolicy {
	policy := BackendSelectionPolicy{}
	if svc == nil {
		return policy
	}
	if itp := svc.Spec.InternalTrafficPolicy; itp != nil && *itp == corev1.ServiceInternalTrafficPolicyLocal {
		policy.InternalLocal = true
	}
	policy.Affinity = affinityPolicyOf(svc)
	return policy
}

func affinityPolicyOf(svc *corev1.Service) AffinityPolicy {
	if svc.Spec.SessionAffinity != corev1.ServiceAffinityClientIP {
		return AffinityPolicy{}
	}
	timeout := DefaultClientIPAffinityTimeout
	if cfg := svc.Spec.SessionAffinityConfig; cfg != nil && cfg.ClientIP != nil && cfg.ClientIP.TimeoutSeconds != nil {
		if t := *cfg.ClientIP.TimeoutSeconds; t > 0 {
			timeout = time.Duration(t) * time.Second
		}
	}
	return AffinityPolicy{Mode: AffinityClientIP, Timeout: timeout}
}
