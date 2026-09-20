package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	minimumCustomRecordTTL = int32(1)
	maximumCustomRecordTTL = int32(86400)
	maximumCustomAddresses = 100

	customZoneIndexField   = "dns.zoneVpcDomain"
	customRecordIndexField = "dns.recordZoneName"
)

// CustomZone resolves private DNSZone and DNSRecord resources for the caller's Vpc.
type CustomZone struct {
	client  client.Client
	shuffle func(int, func(int, int))
}

// RegisterCustomZoneIndexes registers the exact lookup keys used by CustomZone.
func RegisterCustomZoneIndexes(ctx context.Context, indexer client.FieldIndexer) error {
	if err := indexer.IndexField(ctx, &juneauv1alpha1.DNSZone{}, customZoneIndexField, func(object client.Object) []string {
		zone := object.(*juneauv1alpha1.DNSZone)
		return []string{customDNSIndexKey(zone.Spec.Vpc, zone.Spec.Domain)}
	}); err != nil {
		return fmt.Errorf("index DNSZone by Vpc and domain: %w", err)
	}
	if err := indexer.IndexField(ctx, &juneauv1alpha1.DNSRecord{}, customRecordIndexField, func(object client.Object) []string {
		record := object.(*juneauv1alpha1.DNSRecord)
		return []string{customDNSIndexKey(record.Spec.Zone, record.Spec.Name)}
	}); err != nil {
		return fmt.Errorf("index DNSRecord by zone and name: %w", err)
	}
	return nil
}

// NewCustomZone creates a Vpc-private authoritative resolver.
func NewCustomZone(cl client.Client, shuffle func(int, func(int, int))) *CustomZone {
	if cl == nil {
		panic("dns: custom zone client is nil")
	}
	if shuffle == nil {
		panic("dns: custom zone shuffler is nil")
	}
	return &CustomZone{client: cl, shuffle: shuffle}
}

// Resolve serves the longest matching zone owned by the caller's Vpc.
func (z *CustomZone) Resolve(ctx context.Context, query Query) (Response, error) {
	zone, conflict, err := z.lookupZone(ctx, query.CallerVPC, query.Name)
	if err != nil {
		return Response{RCode: RCodeServerFailure}, err
	}
	if conflict {
		return customServerFailure(), nil
	}
	if zone == nil {
		return Response{}, ErrNotInZone
	}
	if !servableResource(zone.Generation, zone.Status.ObservedGeneration, zone.Status.Conditions, juneauv1alpha1.DNSZoneConditionReady, zone.DeletionTimestamp) {
		return customServerFailure(), nil
	}

	relativeName := relativeRecordName(query.Name, zone.Spec.Domain)
	var records juneauv1alpha1.DNSRecordList
	if err := z.client.List(ctx, &records, client.MatchingFields{
		customRecordIndexField: customDNSIndexKey(zone.Name, relativeName),
	}); err != nil {
		return Response{RCode: RCodeServerFailure}, fmt.Errorf("list DNSRecords by zone and name: %w", err)
	}
	if len(records.Items) > 1 {
		return customServerFailure(), nil
	}
	if len(records.Items) == 0 {
		return Response{RCode: RCodeNXDomain, Authoritative: true}, nil
	}

	record := &records.Items[0]
	if !servableResource(record.Generation, record.Status.ObservedGeneration, record.Status.Conditions, juneauv1alpha1.DNSRecordConditionReady, record.DeletionTimestamp) {
		return customServerFailure(), nil
	}

	addresses, ttl, valid := projectedRecordData(record)
	if !valid {
		return customServerFailure(), nil
	}
	if query.Class != ClassINET {
		return Response{RCode: RCodeNotImplemented, Authoritative: true}, nil
	}
	if query.Type != TypeA || len(addresses) == 0 {
		return Response{RCode: RCodeNoError, Authoritative: true}, nil
	}

	answers := make([]Answer, len(addresses))
	for i, address := range addresses {
		answers[i] = Answer{
			Name:  query.Name,
			Type:  TypeA,
			Class: ClassINET,
			TTL:   ttl,
			A:     address,
		}
	}
	z.shuffle(len(answers), func(i, j int) {
		answers[i], answers[j] = answers[j], answers[i]
	})
	return Response{RCode: RCodeNoError, Answers: answers, Authoritative: true}, nil
}

func (z *CustomZone) lookupZone(ctx context.Context, callerVPC, queryName string) (*juneauv1alpha1.DNSZone, bool, error) {
	for _, domain := range customDomainCandidates(queryName) {
		var zones juneauv1alpha1.DNSZoneList
		if err := z.client.List(ctx, &zones, client.MatchingFields{
			customZoneIndexField: customDNSIndexKey(callerVPC, domain),
		}); err != nil {
			return nil, false, fmt.Errorf("list DNSZones by Vpc and domain: %w", err)
		}
		if len(zones.Items) > 1 {
			return nil, true, nil
		}
		if len(zones.Items) == 1 {
			return &zones.Items[0], false, nil
		}
	}
	return nil, false, nil
}

func customDomainCandidates(queryName string) []string {
	name := strings.TrimSuffix(queryName, ".")
	if name == "" {
		return nil
	}
	labels := strings.Split(name, ".")
	candidates := make([]string, 0, len(labels))
	for i := range labels {
		candidates = append(candidates, strings.Join(labels[i:], "."))
	}
	return candidates
}

func customDNSIndexKey(first, second string) string {
	return strconv.Itoa(len(first)) + ":" + first + second
}

func relativeRecordName(queryName, domain string) string {
	fqdn := domain + "."
	if queryName == fqdn {
		return "@"
	}
	return strings.TrimSuffix(strings.TrimSuffix(queryName, fqdn), ".")
}

func servableResource(generation, observedGeneration int64, conditions []metav1.Condition, readyType string, deletionTimestamp *metav1.Time) bool {
	if deletionTimestamp != nil && !deletionTimestamp.IsZero() {
		return false
	}
	if observedGeneration != generation {
		return false
	}
	readyConditions := 0
	for i := range conditions {
		condition := &conditions[i]
		if condition.Type != readyType {
			continue
		}
		readyConditions++
		if condition.Status != metav1.ConditionTrue || condition.ObservedGeneration != generation {
			return false
		}
	}
	return readyConditions == 1
}

func projectedRecordData(record *juneauv1alpha1.DNSRecord) ([]netip.Addr, uint32, bool) {
	if record.Spec.Type != juneauv1alpha1.DNSRecordTypeA || record.Spec.TTL == nil {
		return nil, 0, false
	}
	ttl := *record.Spec.TTL
	if ttl < minimumCustomRecordTTL || ttl > maximumCustomRecordTTL || len(record.Status.Addresses) > maximumCustomAddresses {
		return nil, 0, false
	}

	addresses := make([]netip.Addr, len(record.Status.Addresses))
	seen := make(map[netip.Addr]struct{}, len(record.Status.Addresses))
	for i, value := range record.Status.Addresses {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return nil, 0, false
		}
		if _, exists := seen[address]; exists {
			return nil, 0, false
		}
		seen[address] = struct{}{}
		addresses[i] = address
	}
	return addresses, uint32(ttl), true
}

func customServerFailure() Response {
	return Response{RCode: RCodeServerFailure, Authoritative: true}
}
