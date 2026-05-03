// Package svcpolicy centralises the cross-Vpc resolution policy used
// by every Juneau component that decides whether a Pod in one VPC may
// reach a Service in another.
//
// The same rules apply at two layers:
//
//   * BPF backend programming (daemon/internal/daemon/dataplane/reconciler/service.go)
//     decides whether to populate service_map / backend_map for a Service
//     so the data plane forwards Pod → ClusterIP traffic.
//
//   * Virtual DNS resolution (daemon/internal/daemon/virtservice/dns)
//     decides whether to answer A queries for `<svc>.<ns>.svc.cluster.local`.
//
// Without a shared helper the two paths inevitably drift, producing
// surprising states like "DNS resolves but connect refused" or vice
// versa. This package is intentionally tiny so both call sites can
// import it without taking on extra dependencies.
package svcpolicy

import (
	corev1 "k8s.io/api/core/v1"
)

const (
	// AnnotationVpc names the Vpc that owns the Service. Empty /
	// missing annotation means "default Vpc".
	AnnotationVpc = "juneau.loutres.me/vpc"

	// AnnotationShared opts a default-Vpc Service in to cross-Vpc
	// reachability via the shared-service path. The value must be
	// the literal string "true".
	AnnotationShared = "juneau.loutres.me/shared-service"

	// DefaultVpc is the conventional Vpc name a Service belongs to
	// when its AnnotationVpc is unset.
	DefaultVpc = "default"

	// KubernetesNamespace and KubernetesName identify the canonical
	// "kubernetes" Service in the default namespace. It is treated
	// as implicitly shared so any Pod can reach the apiserver
	// regardless of explicit annotation.
	KubernetesNamespace = "default"
	KubernetesName      = "kubernetes"
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

// IsShared reports whether svc is reachable from any Vpc with
// EnableService=true. The canonical kubernetes Service is implicitly
// shared so apiserver access does not require explicit opt-in.
func IsShared(svc *corev1.Service) bool {
	if svc == nil {
		return false
	}
	if svc.Namespace == KubernetesNamespace && svc.Name == KubernetesName {
		return true
	}
	return svc.Annotations[AnnotationShared] == "true"
}

// ResolvableFrom returns true when a caller in callerVpc may legitimately
// resolve / reach svc, given whether that Vpc has EnableService set.
//
// Rules (in order):
//   1. If the caller Vpc does not have EnableService, no Service is
//      resolvable. This mirrors the BPF data plane, which won't
//      forward Pod → ClusterIP traffic from such a Vpc.
//   2. If the Service is owned by the same Vpc as the caller, it is
//      resolvable.
//   3. If the Service is shared (annotation or kubernetes Service),
//      it is resolvable from any EnableService Vpc.
//   4. Otherwise no.
func ResolvableFrom(svc *corev1.Service, callerVpc string, callerEnableService bool) bool {
	if svc == nil {
		return false
	}
	if !callerEnableService {
		return false
	}
	if OwningVpc(svc) == callerVpc {
		return true
	}
	return IsShared(svc)
}
