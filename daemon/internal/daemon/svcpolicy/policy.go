// Package svcpolicy centralises the cross-Vpc resolution policy used
// by every Juneau component that decides whether a Pod in one VPC may
// reach a Service in another.
//
// The same rules apply at two layers:
//
//   - BPF backend programming (daemon/internal/daemon/dataplane/reconciler/service.go)
//     decides whether to populate service_map / backend_map for a Service
//     so the data plane forwards Pod → ClusterIP traffic.
//
//   - Virtual DNS resolution (daemon/internal/daemon/virtservice/dns)
//     decides whether to answer A queries for `<svc>.<ns>.svc.cluster.local`.
//
// Without a shared helper the two paths inevitably drift, producing
// surprising states like "DNS resolves but connect refused" or vice
// versa. This package is intentionally tiny so both call sites can
// import it without taking on extra dependencies.
package svcpolicy

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const (
	// AnnotationVpc names the Vpc that owns the Service. Empty /
	// missing annotation means "default Vpc".
	AnnotationVpc = "juneau.loutres.me/vpc"

	// AnnotationShared opts a Service in to cross-Vpc reachability via
	// the shared-service path. The value must be the literal string
	// "true". The owner Vpc must have spec.service.provider configured.
	AnnotationShared = "juneau.loutres.me/shared-service"

	// AnnotationAllowedConsumerVpcs whitelists the caller Vpcs that
	// may reach the shared Service. The value is a comma-separated
	// list of Vpc names. When the annotation is absent every Vpc
	// with spec.service.consume=true is permitted; when present only
	// listed Vpcs are.
	AnnotationAllowedConsumerVpcs = "juneau.loutres.me/shared-service-allowed-consumer-vpcs"

	// DefaultVpc is the conventional Vpc name a Service belongs to
	// when its AnnotationVpc is unset.
	DefaultVpc = "default"
)

// OwningVpc returns the name of the Vpc that owns svc. AnnotationVpc
// when present, otherwise DefaultVpc. Never returns the empty string.
func OwningVpc(svc *corev1.Service) string {
	if svc == nil {
		return DefaultVpc
	}
	if v, ok := svc.Annotations[AnnotationVpc]; ok && v != "" {
		return v
	}
	return DefaultVpc
}

// IsShared reports whether svc has opted in to cross-Vpc reachability
// via the shared-service annotation. Whether a particular caller Vpc
// is actually allowed to reach the Service is governed by
// IsAllowedConsumer / ResolvableFrom in addition to this flag.
func IsShared(svc *corev1.Service) bool {
	if svc == nil {
		return false
	}
	return svc.Annotations[AnnotationShared] == "true"
}

// AllowedConsumerVpcs returns the explicit ACL list of caller Vpcs
// that may reach svc. An empty slice means "no ACL configured" — i.e.
// every consume-enabled Vpc is permitted; a non-empty slice is a
// whitelist. The result is normalised: comma-separated entries are
// trimmed and empty entries are dropped, but order is preserved.
func AllowedConsumerVpcs(svc *corev1.Service) []string {
	if svc == nil {
		return nil
	}
	raw, ok := svc.Annotations[AnnotationAllowedConsumerVpcs]
	if !ok {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// HasConsumerACL reports whether svc carries an explicit consumer
// whitelist. When false, every consume-enabled Vpc is permitted by
// default.
func HasConsumerACL(svc *corev1.Service) bool {
	return len(AllowedConsumerVpcs(svc)) > 0
}

// IsAllowedConsumer reports whether callerVpc is permitted by svc's
// consumer ACL. When the ACL is absent the function returns true
// (default-allow). When present, only listed Vpcs match.
func IsAllowedConsumer(svc *corev1.Service, callerVpc string) bool {
	allowed := AllowedConsumerVpcs(svc)
	if len(allowed) == 0 {
		return true
	}
	for _, v := range allowed {
		if v == callerVpc {
			return true
		}
	}
	return false
}

// CallerVpc bundles the caller Vpc's identity with the two opt-in
// bits ResolvableFrom needs. Decoupling from the v1alpha1 type keeps
// this package dependency-free so both the BPF reconciler and the
// virtual DNS resolver can import it without taking on extra
// transitive dependencies.
type CallerVpc struct {
	// Name is the caller Vpc's metadata.name.
	Name string
	// ServiceEnabled is true when the caller Vpc has Service routing
	// enabled at all (Vpc.Spec.ServiceEnabled() — equivalent to
	// "Provider configured OR Consume true"). False means the Vpc
	// has no Service support; not even own-Vpc Services resolve.
	ServiceEnabled bool
	// Consume is true when the caller Vpc opts in to calling shared
	// Services hosted in other Vpcs (Vpc.Spec.Service.Consume).
	Consume bool
}

// ResolvableFrom returns true when a caller may legitimately resolve
// / reach svc.
//
// Rules (in order):
//  1. If the caller Vpc has no Service routing at all (ServiceEnabled
//     is false), no Service is resolvable. This mirrors the BPF data
//     plane, which won't forward Pod → ClusterIP traffic from such a
//     Vpc.
//  2. If svc is owned by the caller Vpc, it is resolvable. Same-Vpc
//     resolution does not require consume.
//  3. Cross-Vpc resolution requires svc to be shared, the caller Vpc
//     to have Consume=true, and the caller to pass svc's per-Service
//     consumer ACL (AllowedConsumerVpcs).
//  4. Otherwise no.
func ResolvableFrom(svc *corev1.Service, caller CallerVpc) bool {
	if svc == nil {
		return false
	}
	if !caller.ServiceEnabled {
		return false
	}
	if OwningVpc(svc) == caller.Name {
		return true
	}
	if !caller.Consume {
		return false
	}
	if !IsShared(svc) {
		return false
	}
	return IsAllowedConsumer(svc, caller.Name)
}
