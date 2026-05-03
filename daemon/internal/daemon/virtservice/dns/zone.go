package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/1outres/juneau/daemon/internal/daemon/svcpolicy"
)

// ClusterZone resolves names ending in the configured cluster suffix
// (default "cluster.local.") against the daemon's Service informer
// cache. Authoritative for everything under that suffix; defers other
// names to the wrapping Resolver chain by returning ErrNotInZone.
//
// Naming scheme supported (the kubernetes-conventional one):
//
//   <svc>.<ns>.svc.<cluster-domain>          → A record(s) for the
//                                              ClusterIP, subject to
//                                              VPC policy.
//
// Other forms (PTR, SRV, etc.) currently return NXDOMAIN; we add them
// as use cases come in.
type ClusterZone struct {
	client      client.Client
	suffix      string // dot-suffixed; e.g. "cluster.local."
	defaultTTL  uint32
}

// ErrNotInZone signals that the queried name is outside the zone's
// authoritative scope so the caller can try a different resolver.
var ErrNotInZone = errors.New("dns: not in cluster zone")

// NewClusterZone constructs a zone bound to the given client (must be
// backed by a cache that watches corev1.Service). suffix should be
// dot-suffixed; passing "" is a programming error.
func NewClusterZone(cl client.Client, suffix string, defaultTTL uint32) *ClusterZone {
	if suffix == "" {
		suffix = DefaultClusterDomain
	}
	if !strings.HasSuffix(suffix, ".") {
		suffix += "."
	}
	if defaultTTL == 0 {
		defaultTTL = 30
	}
	return &ClusterZone{client: cl, suffix: strings.ToLower(suffix), defaultTTL: defaultTTL}
}

// Resolve answers a Query. Errors only on infrastructure failures (cache
// errors); policy denials map to NXDOMAIN so callers can't probe the
// existence of Services they aren't allowed to reach.
func (z *ClusterZone) Resolve(ctx context.Context, q Query) (Response, error) {
	name := strings.ToLower(q.Name)
	if !strings.HasSuffix(name, z.suffix) {
		return Response{}, ErrNotInZone
	}

	// Strip the trailing ".cluster.local." and split into labels.
	stripped := strings.TrimSuffix(name, z.suffix)
	stripped = strings.TrimSuffix(stripped, ".")
	labels := strings.Split(stripped, ".")

	// Only the <svc>.<ns>.svc form is supported right now.
	if len(labels) != 3 || labels[2] != "svc" {
		return Response{RCode: RCodeNXDomain, Authoritative: true}, nil
	}
	svcName := labels[0]
	nsName := labels[1]

	if q.Class != ClassINET {
		return Response{RCode: RCodeNotImplemented, Authoritative: true}, nil
	}
	switch q.Type {
	case TypeA, TypeAAAA:
		// fine
	default:
		return Response{RCode: RCodeNXDomain, Authoritative: true}, nil
	}

	var svc corev1.Service
	err := z.client.Get(ctx, client.ObjectKey{Namespace: nsName, Name: svcName}, &svc)
	if apierrors.IsNotFound(err) {
		return Response{RCode: RCodeNXDomain, Authoritative: true}, nil
	}
	if err != nil {
		return Response{}, fmt.Errorf("get service %s/%s: %w", nsName, svcName, err)
	}

	if !svcpolicy.ResolvableFrom(&svc, q.CallerVPC, q.CallerEnableService) {
		// Treat as NXDOMAIN to avoid leaking the existence of
		// Services the caller VPC can't reach.
		return Response{RCode: RCodeNXDomain, Authoritative: true}, nil
	}

	// Headless / external services have no ClusterIP; treat as
	// NODATA (NoError, no answers) so the client falls back to its
	// next search domain.
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return Response{RCode: RCodeNoError, Authoritative: true}, nil
	}

	if q.Type == TypeAAAA {
		// Juneau is IPv4-only today; advertise NODATA for AAAA so
		// happy-eyeballs falls through to A.
		return Response{RCode: RCodeNoError, Authoritative: true}, nil
	}

	res := Response{RCode: RCodeNoError, Authoritative: true}
	for _, ipStr := range serviceClusterIPs(&svc) {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil || !addr.Is4() {
			continue
		}
		res.Answers = append(res.Answers, Answer{
			Name:  q.Name,
			Type:  TypeA,
			Class: ClassINET,
			TTL:   z.defaultTTL,
			A:     addr,
		})
	}
	if len(res.Answers) == 0 {
		// All IPs were non-IPv4 — we don't speak v6 yet.
		return Response{RCode: RCodeNoError, Authoritative: true}, nil
	}
	return res, nil
}

// serviceClusterIPs returns the Service's ClusterIPs in declared
// order. Falls back to the legacy single ClusterIP field when ClusterIPs
// is empty, matching apiserver behaviour for older clients.
func serviceClusterIPs(svc *corev1.Service) []string {
	if svc == nil {
		return nil
	}
	if len(svc.Spec.ClusterIPs) > 0 {
		return svc.Spec.ClusterIPs
	}
	if svc.Spec.ClusterIP != "" {
		return []string{svc.Spec.ClusterIP}
	}
	return nil
}
