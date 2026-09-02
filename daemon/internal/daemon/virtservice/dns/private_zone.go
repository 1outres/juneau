package dns

import (
	"context"
	"net/netip"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const AllocationLeaseDNSNameField = "spec.dns.names"

// PrivateZone resolves exact Vpc-scoped names carried by IP allocation
// leases. The names are supplied by allocation consumers; Juneau assigns no
// product meaning to them.
type PrivateZone struct {
	client     client.Client
	defaultTTL uint32
}

func NewPrivateZone(cl client.Client, defaultTTL uint32) *PrivateZone {
	if defaultTTL == 0 {
		defaultTTL = 30
	}
	return &PrivateZone{client: cl, defaultTTL: defaultTTL}
}

func (z *PrivateZone) Resolve(ctx context.Context, q Query) (Response, error) {
	if q.Class != ClassINET {
		return Response{RCode: RCodeNotImplemented, Authoritative: true}, nil
	}
	queryName := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	var leases juneauv1alpha1.AllocationLeaseList
	if err := z.client.List(ctx, &leases, client.MatchingFields{AllocationLeaseDNSNameField: queryName}); err != nil {
		return Response{RCode: RCodeServerFailure}, err
	}

	knownName := false
	availableName := false
	seen := map[netip.Addr]struct{}{}
	answers := make([]Answer, 0)
	for i := range leases.Items {
		lease := &leases.Items[i]
		if lease.Spec.DNS == nil || !containsDNSName(lease.Spec.DNS.Names, queryName) {
			continue
		}
		knownName = true
		if lease.Spec.DNS.Vpc != q.CallerVPC ||
			(lease.Status.Phase != juneauv1alpha1.AllocationLeasePhaseActive && lease.Status.Phase != juneauv1alpha1.AllocationLeasePhaseRetained) {
			continue
		}
		availableName = true
		address, err := netip.ParseAddr(lease.Spec.Value.IP)
		if err != nil || !address.IsValid() {
			continue
		}
		if (q.Type == TypeA && !address.Is4()) || (q.Type == TypeAAAA && !address.Is6()) {
			continue
		}
		if q.Type != TypeA && q.Type != TypeAAAA {
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		answers = append(answers, Answer{Name: q.Name, Type: q.Type, Class: ClassINET, TTL: z.defaultTTL, A: address})
	}
	if len(answers) > 0 {
		return Response{RCode: RCodeNoError, Answers: answers, Authoritative: true}, nil
	}
	if availableName {
		return Response{RCode: RCodeNoError, Authoritative: true}, nil
	}
	if knownName {
		return Response{RCode: RCodeNXDomain, Authoritative: true}, nil
	}
	return Response{}, ErrNotInZone
}

func containsDNSName(names []string, query string) bool {
	for _, name := range names {
		if strings.TrimSuffix(strings.ToLower(name), ".") == query {
			return true
		}
	}
	return false
}
