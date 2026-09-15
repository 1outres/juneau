package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newCustomDNSClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := juneauv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add Juneau scheme: %v", err)
	}
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithIndex(&juneauv1alpha1.DNSZone{}, "dns.zoneVpcDomain", func(object client.Object) []string {
			zone := object.(*juneauv1alpha1.DNSZone)
			return []string{testDNSIndexKey(zone.Spec.Vpc, zone.Spec.Domain)}
		}).
		WithIndex(&juneauv1alpha1.DNSRecord{}, "dns.recordZoneName", func(object client.Object) []string {
			record := object.(*juneauv1alpha1.DNSRecord)
			return []string{testDNSIndexKey(record.Spec.Zone, record.Spec.Name)}
		}).
		Build()
}

func testDNSIndexKey(first, second string) string {
	return strconv.Itoa(len(first)) + ":" + first + second
}

func readyDNSZone(name, vpc, domain string) *juneauv1alpha1.DNSZone {
	const generation = int64(3)
	return &juneauv1alpha1.DNSZone{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: generation},
		Spec: juneauv1alpha1.DNSZoneSpec{
			Vpc:    vpc,
			Domain: domain,
		},
		Status: juneauv1alpha1.DNSZoneStatus{
			ObservedGeneration: generation,
			Conditions: []metav1.Condition{{
				Type:               juneauv1alpha1.DNSZoneConditionReady,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: generation,
			}},
		},
	}
}

func readyDNSRecord(name, zone, relativeName string, ttl int32, addresses ...string) *juneauv1alpha1.DNSRecord {
	const generation = int64(5)
	return &juneauv1alpha1.DNSRecord{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: generation},
		Spec: juneauv1alpha1.DNSRecordSpec{
			Zone: zone,
			Name: relativeName,
			Type: juneauv1alpha1.DNSRecordTypeA,
			TTL:  &ttl,
		},
		Status: juneauv1alpha1.DNSRecordStatus{
			ObservedGeneration: generation,
			Addresses:          addresses,
			Conditions: []metav1.Condition{{
				Type:               juneauv1alpha1.DNSRecordConditionReady,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: generation,
			}},
		},
	}
}

func noShuffle(_ int, _ func(int, int)) {}

func resolveCustom(t *testing.T, resolver Resolver, query Query) (Response, error) {
	t.Helper()
	response, err := resolver.Resolve(context.Background(), query)
	return response, err
}

func TestCustomZoneResolvesApexAndRelativeNames(t *testing.T) {
	zone := readyDNSZone("corp-zone", "tenant-a", "corp.example")
	apex := readyDNSRecord("apex", zone.Name, "@", 90, "10.0.0.1")
	relative := readyDNSRecord("api", zone.Name, "api.prod", 45, "10.0.0.2")
	resolver := NewCustomZone(newCustomDNSClient(t, zone, apex, relative), noShuffle)

	tests := []struct {
		name    string
		query   string
		address netip.Addr
		ttl     uint32
	}{
		{name: "apex", query: "corp.example.", address: netip.MustParseAddr("10.0.0.1"), ttl: 90},
		{name: "relative", query: "api.prod.corp.example.", address: netip.MustParseAddr("10.0.0.2"), ttl: 45},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := resolveCustom(t, resolver, Query{
				Name:                 test.query,
				Type:                 TypeA,
				Class:                ClassINET,
				CallerVPC:            "tenant-a",
				CallerServiceEnabled: false,
				CallerConsume:        false,
			})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if response.RCode != RCodeNoError || !response.Authoritative {
				t.Fatalf("response = %+v, want authoritative NOERROR", response)
			}
			if len(response.Answers) != 1 {
				t.Fatalf("answers = %+v, want one", response.Answers)
			}
			answer := response.Answers[0]
			if answer.Name != test.query || answer.A != test.address || answer.TTL != test.ttl || answer.Type != TypeA || answer.Class != ClassINET {
				t.Errorf("answer = %+v, want name=%q address=%s ttl=%d IN/A", answer, test.query, test.address, test.ttl)
			}
		})
	}
}

func TestCustomZoneUsesExactVPCAndDNSLabelBoundaries(t *testing.T) {
	foreignZone := readyDNSZone("foreign", "tenant-b", "shared.example")
	foreignRecord := readyDNSRecord("foreign-api", foreignZone.Name, "api", 30, "10.2.0.1")
	ownZone := readyDNSZone("own", "tenant-a", "shared.example")
	ownRecord := readyDNSRecord("own-api", ownZone.Name, "api", 30, "10.1.0.1")
	boundaryZone := readyDNSZone("boundary", "tenant-a", "example.com")
	resolver := NewCustomZone(newCustomDNSClient(t, foreignZone, foreignRecord, ownZone, ownRecord, boundaryZone), noShuffle)

	response, err := resolveCustom(t, resolver, Query{Name: "api.shared.example.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
	if err != nil {
		t.Fatalf("Resolve same domain across Vpcs: %v", err)
	}
	if len(response.Answers) != 1 || response.Answers[0].A != netip.MustParseAddr("10.1.0.1") {
		t.Fatalf("answers = %+v, want own-Vpc record", response.Answers)
	}

	_, err = resolveCustom(t, resolver, Query{Name: "notexample.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
	if !errors.Is(err, ErrNotInZone) {
		t.Fatalf("boundary query error = %v, want ErrNotInZone", err)
	}

	_, err = resolveCustom(t, resolver, Query{Name: "api.shared.example.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-c"})
	if !errors.Is(err, ErrNotInZone) {
		t.Fatalf("foreign-only query error = %v, want ErrNotInZone", err)
	}
}

func TestCustomZoneSelectsLongestMatchingZoneWithoutMerging(t *testing.T) {
	parent := readyDNSZone("parent", "tenant-a", "example.com")
	parentRecord := readyDNSRecord("parent-api", parent.Name, "api.child", 30, "10.0.0.1")
	child := readyDNSZone("child", "tenant-a", "child.example.com")
	childRecord := readyDNSRecord("child-api", child.Name, "api", 30, "10.0.0.2")
	resolver := NewCustomZone(newCustomDNSClient(t, parent, parentRecord, child, childRecord), noShuffle)

	response, err := resolveCustom(t, resolver, Query{Name: "api.child.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(response.Answers) != 1 || response.Answers[0].A != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("answers = %+v, want child-zone record only", response.Answers)
	}
}

func TestCustomZoneDoesNotFallBackFromStaleChildZone(t *testing.T) {
	parent := readyDNSZone("parent", "tenant-a", "example.com")
	parentRecord := readyDNSRecord("parent-api", parent.Name, "api.child", 30, "10.0.0.1")
	child := readyDNSZone("child", "tenant-a", "child.example.com")
	child.Status.ObservedGeneration--
	resolver := NewCustomZone(newCustomDNSClient(t, parent, parentRecord, child), noShuffle)

	response, err := resolveCustom(t, resolver, Query{Name: "api.child.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if response.RCode != RCodeServerFailure || !response.Authoritative || len(response.Answers) != 0 {
		t.Fatalf("response = %+v, want authoritative SERVFAIL", response)
	}
}

func TestCustomZoneIsAuthoritativeForUnknownAndUnsupportedOwners(t *testing.T) {
	zone := readyDNSZone("zone", "tenant-a", "example.com")
	record := readyDNSRecord("api", zone.Name, "api", 30, "10.0.0.1")
	resolver := NewCustomZone(newCustomDNSClient(t, zone, record), noShuffle)

	unknown, err := resolveCustom(t, resolver, Query{Name: "missing.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
	if err != nil {
		t.Fatalf("resolve unknown owner: %v", err)
	}
	if unknown.RCode != RCodeNXDomain || !unknown.Authoritative || len(unknown.Answers) != 0 {
		t.Fatalf("unknown response = %+v, want authoritative NXDOMAIN", unknown)
	}

	for _, queryType := range []QueryType{TypeAAAA, TypePTR, TypeCNAME} {
		response, err := resolveCustom(t, resolver, Query{Name: "api.example.com.", Type: queryType, Class: ClassINET, CallerVPC: "tenant-a"})
		if err != nil {
			t.Fatalf("resolve type %d: %v", queryType, err)
		}
		if response.RCode != RCodeNoError || !response.Authoritative || len(response.Answers) != 0 {
			t.Errorf("type %d response = %+v, want authoritative NODATA", queryType, response)
		}
	}
}

func TestCustomZoneReadyEmptyRecordReturnsNoData(t *testing.T) {
	zone := readyDNSZone("zone", "tenant-a", "example.com")
	record := readyDNSRecord("empty", zone.Name, "empty", 60)
	resolver := NewCustomZone(newCustomDNSClient(t, zone, record), noShuffle)

	response, err := resolveCustom(t, resolver, Query{Name: "empty.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if response.RCode != RCodeNoError || !response.Authoritative || len(response.Answers) != 0 {
		t.Fatalf("response = %+v, want authoritative NODATA", response)
	}
}

func TestCustomZoneRejectsUnservableZones(t *testing.T) {
	now := metav1.Now()
	tests := []struct {
		name   string
		mutate func(*juneauv1alpha1.DNSZone)
	}{
		{name: "stale status", mutate: func(zone *juneauv1alpha1.DNSZone) { zone.Status.ObservedGeneration-- }},
		{name: "stale condition", mutate: func(zone *juneauv1alpha1.DNSZone) { zone.Status.Conditions[0].ObservedGeneration-- }},
		{name: "not ready", mutate: func(zone *juneauv1alpha1.DNSZone) { zone.Status.Conditions[0].Status = metav1.ConditionFalse }},
		{name: "missing condition", mutate: func(zone *juneauv1alpha1.DNSZone) { zone.Status.Conditions = nil }},
		{name: "deleting", mutate: func(zone *juneauv1alpha1.DNSZone) {
			zone.DeletionTimestamp = &now
			zone.Finalizers = []string{"test.example/finalizer"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			zone := readyDNSZone("zone", "tenant-a", "example.com")
			test.mutate(zone)
			resolver := NewCustomZone(newCustomDNSClient(t, zone), noShuffle)
			response, err := resolveCustom(t, resolver, Query{Name: "api.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if response.RCode != RCodeServerFailure || !response.Authoritative {
				t.Fatalf("response = %+v, want authoritative SERVFAIL", response)
			}
		})
	}
}

func TestCustomZoneRejectsUnservableRecords(t *testing.T) {
	now := metav1.Now()
	tests := []struct {
		name   string
		mutate func(*juneauv1alpha1.DNSRecord)
	}{
		{name: "stale status", mutate: func(record *juneauv1alpha1.DNSRecord) { record.Status.ObservedGeneration-- }},
		{name: "stale condition", mutate: func(record *juneauv1alpha1.DNSRecord) { record.Status.Conditions[0].ObservedGeneration-- }},
		{name: "not ready", mutate: func(record *juneauv1alpha1.DNSRecord) { record.Status.Conditions[0].Status = metav1.ConditionFalse }},
		{name: "missing condition", mutate: func(record *juneauv1alpha1.DNSRecord) { record.Status.Conditions = nil }},
		{name: "deleting", mutate: func(record *juneauv1alpha1.DNSRecord) {
			record.DeletionTimestamp = &now
			record.Finalizers = []string{"test.example/finalizer"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			zone := readyDNSZone("zone", "tenant-a", "example.com")
			record := readyDNSRecord("api", zone.Name, "api", 30, "10.0.0.1")
			test.mutate(record)
			resolver := NewCustomZone(newCustomDNSClient(t, zone, record), noShuffle)
			response, err := resolveCustom(t, resolver, Query{Name: "api.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if response.RCode != RCodeServerFailure || !response.Authoritative {
				t.Fatalf("response = %+v, want authoritative SERVFAIL", response)
			}
		})
	}
}

func TestCustomZoneDetectsDuplicateZonesBeforeReadiness(t *testing.T) {
	first := readyDNSZone("first", "tenant-a", "example.com")
	second := readyDNSZone("second", "tenant-a", "example.com")
	second.Status.Conditions[0].Status = metav1.ConditionFalse
	resolver := NewCustomZone(newCustomDNSClient(t, first, second), noShuffle)

	response, err := resolveCustom(t, resolver, Query{Name: "api.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if response.RCode != RCodeServerFailure || !response.Authoritative {
		t.Fatalf("response = %+v, want authoritative SERVFAIL", response)
	}
}

func TestCustomZoneDetectsDuplicateRecordsBeforeReadiness(t *testing.T) {
	zone := readyDNSZone("zone", "tenant-a", "example.com")
	first := readyDNSRecord("first", zone.Name, "api", 30, "10.0.0.1")
	second := readyDNSRecord("second", zone.Name, "api", 30, "10.0.0.2")
	second.Status.Conditions[0].Status = metav1.ConditionFalse
	resolver := NewCustomZone(newCustomDNSClient(t, zone, first, second), noShuffle)

	response, err := resolveCustom(t, resolver, Query{Name: "api.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if response.RCode != RCodeServerFailure || !response.Authoritative {
		t.Fatalf("response = %+v, want authoritative SERVFAIL", response)
	}
}

func TestCustomZoneRejectsInvalidProjectedRecordData(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*juneauv1alpha1.DNSRecord)
	}{
		{name: "missing ttl", mutate: func(record *juneauv1alpha1.DNSRecord) { record.Spec.TTL = nil }},
		{name: "ttl too low", mutate: func(record *juneauv1alpha1.DNSRecord) { ttl := int32(0); record.Spec.TTL = &ttl }},
		{name: "ttl too high", mutate: func(record *juneauv1alpha1.DNSRecord) { ttl := int32(86401); record.Spec.TTL = &ttl }},
		{name: "too many addresses", mutate: func(record *juneauv1alpha1.DNSRecord) {
			record.Status.Addresses = make([]string, 101)
			for i := range record.Status.Addresses {
				record.Status.Addresses[i] = netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)}).String()
			}
		}},
		{name: "duplicate address", mutate: func(record *juneauv1alpha1.DNSRecord) { record.Status.Addresses = []string{"10.0.0.1", "10.0.0.1"} }},
		{name: "invalid address", mutate: func(record *juneauv1alpha1.DNSRecord) { record.Status.Addresses = []string{"10.0.0.1", "invalid"} }},
		{name: "ipv6 address", mutate: func(record *juneauv1alpha1.DNSRecord) { record.Status.Addresses = []string{"2001:db8::1"} }},
		{name: "unsupported stored type", mutate: func(record *juneauv1alpha1.DNSRecord) { record.Spec.Type = juneauv1alpha1.DNSRecordType("AAAA") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			zone := readyDNSZone("zone", "tenant-a", "example.com")
			record := readyDNSRecord("api", zone.Name, "api", 30, "10.0.0.1", "10.0.0.2")
			test.mutate(record)
			resolver := NewCustomZone(newCustomDNSClient(t, zone, record), noShuffle)
			response, err := resolveCustom(t, resolver, Query{Name: "api.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if response.RCode != RCodeServerFailure || !response.Authoritative || len(response.Answers) != 0 {
				t.Fatalf("response = %+v, want authoritative SERVFAIL without partial answers", response)
			}
		})
	}
}

func TestCustomZoneValidatesProjectedDataBeforeReturningNoData(t *testing.T) {
	zone := readyDNSZone("zone", "tenant-a", "example.com")
	record := readyDNSRecord("api", zone.Name, "api", 30, "invalid")
	resolver := NewCustomZone(newCustomDNSClient(t, zone, record), noShuffle)

	response, err := resolveCustom(t, resolver, Query{Name: "api.example.com.", Type: TypeAAAA, Class: ClassINET, CallerVPC: "tenant-a"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if response.RCode != RCodeServerFailure || !response.Authoritative {
		t.Fatalf("response = %+v, want authoritative SERVFAIL", response)
	}
}

func TestCustomZoneShufflesCompleteAnswerSet(t *testing.T) {
	zone := readyDNSZone("zone", "tenant-a", "example.com")
	record := readyDNSRecord("api", zone.Name, "api", 77, "10.0.0.1", "10.0.0.2", "10.0.0.3")
	calls := 0
	shuffle := func(n int, swap func(int, int)) {
		if calls%n != 0 {
			shift := calls % n
			for i := 0; i < shift; i++ {
				for j := n - 1; j > 0; j-- {
					swap(j, j-1)
				}
			}
		}
		calls++
	}
	resolver := NewCustomZone(newCustomDNSClient(t, zone, record), shuffle)
	query := Query{Name: "api.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"}

	first, err := resolveCustom(t, resolver, query)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	second, err := resolveCustom(t, resolver, query)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	firstAddresses := answerAddresses(first.Answers)
	secondAddresses := answerAddresses(second.Answers)
	want := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")}
	if !sameAddressSet(firstAddresses, want) || !sameAddressSet(secondAddresses, want) {
		t.Fatalf("address sets = %v and %v, want %v", firstAddresses, secondAddresses, want)
	}
	if slices.Equal(firstAddresses, secondAddresses) {
		t.Fatalf("answer order did not vary: %v", firstAddresses)
	}
	for _, answer := range append(first.Answers, second.Answers...) {
		if answer.TTL != 77 {
			t.Errorf("TTL = %d, want 77", answer.TTL)
		}
	}
}

func answerAddresses(answers []Answer) []netip.Addr {
	addresses := make([]netip.Addr, len(answers))
	for i := range answers {
		addresses[i] = answers[i].A
	}
	return addresses
}

func sameAddressSet(got, want []netip.Addr) bool {
	if len(got) != len(want) {
		return false
	}
	for _, address := range want {
		if !slices.Contains(got, address) {
			return false
		}
	}
	return true
}

type indexedListGuardClient struct {
	client.Client
}

func (c indexedListGuardClient) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	var field string
	switch list.(type) {
	case *juneauv1alpha1.DNSZoneList:
		field = "dns.zoneVpcDomain"
	case *juneauv1alpha1.DNSRecordList:
		field = "dns.recordZoneName"
	default:
		return c.Client.List(ctx, list, options...)
	}

	listOptions := &client.ListOptions{}
	for _, option := range options {
		option.ApplyToList(listOptions)
	}
	if listOptions.FieldSelector == nil {
		return fmt.Errorf("unfiltered %T List", list)
	}
	if _, found := listOptions.FieldSelector.RequiresExactMatch(field); !found {
		return fmt.Errorf("%T List does not use exact index %q", list, field)
	}
	return c.Client.List(ctx, list, options...)
}

func TestCustomZoneUsesOnlyIndexedLists(t *testing.T) {
	zone := readyDNSZone("zone", "tenant-a", "example.com")
	record := readyDNSRecord("api", zone.Name, "api", 30, "10.0.0.1")
	resolver := NewCustomZone(indexedListGuardClient{Client: newCustomDNSClient(t, zone, record)}, noShuffle)

	response, err := resolveCustom(t, resolver, Query{Name: "api.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(response.Answers) != 1 || response.Answers[0].A != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("answers = %+v, want indexed record", response.Answers)
	}
}

type failingListClient struct {
	client.Client
	failRecords bool
}

func (c failingListClient) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if _, ok := list.(*juneauv1alpha1.DNSZoneList); ok && !c.failRecords {
		return errors.New("zone cache failed")
	}
	if _, ok := list.(*juneauv1alpha1.DNSRecordList); ok && c.failRecords {
		return errors.New("record cache failed")
	}
	return c.Client.List(ctx, list, options...)
}

func TestCustomZonePropagatesCacheErrors(t *testing.T) {
	zone := readyDNSZone("zone", "tenant-a", "example.com")
	query := Query{Name: "api.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"}

	t.Run("zone list", func(t *testing.T) {
		base := newCustomDNSClient(t)
		resolver := NewCustomZone(failingListClient{Client: base}, noShuffle)
		_, err := resolveCustom(t, resolver, query)
		if err == nil {
			t.Fatal("Resolve succeeded, want zone cache error")
		}
	})

	t.Run("record list", func(t *testing.T) {
		base := newCustomDNSClient(t, zone)
		resolver := NewCustomZone(failingListClient{Client: base, failRecords: true}, noShuffle)
		_, err := resolveCustom(t, resolver, query)
		if err == nil {
			t.Fatal("Resolve succeeded, want record cache error")
		}
	})
}

type countingResolver struct {
	response Response
	err      error
	calls    int
}

func (r *countingResolver) Resolve(_ context.Context, _ Query) (Response, error) {
	r.calls++
	return r.response, r.err
}

func TestCustomZoneChainPrecedence(t *testing.T) {
	t.Run("cluster zone stays reserved", func(t *testing.T) {
		zone := readyDNSZone("local-zone", "tenant-a", "local")
		record := readyDNSRecord("cluster-parent-record", zone.Name, "missing.default.svc.cluster", 30, "10.0.0.1")
		custom := NewCustomZone(newCustomDNSClient(t, zone, record), noShuffle)
		upstream := &countingResolver{response: Response{RCode: RCodeNoError}}
		chain := NewChain(NewClusterZone(newFakeClient(t), DefaultClusterDomain, 30), custom, upstream)
		response, err := chain.Resolve(context.Background(), Query{Name: "missing.default.svc.cluster.local.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a", CallerServiceEnabled: true})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if response.RCode != RCodeNXDomain || len(response.Answers) != 0 || upstream.calls != 0 {
			t.Fatalf("response=%+v upstream calls=%d", response, upstream.calls)
		}
	})

	t.Run("similar cluster suffix reaches custom zone", func(t *testing.T) {
		zone := readyDNSZone("similar-zone", "tenant-a", "notcluster.local")
		record := readyDNSRecord("api", zone.Name, "api", 30, "10.0.0.9")
		custom := NewCustomZone(newCustomDNSClient(t, zone, record), noShuffle)
		upstream := &countingResolver{response: Response{RCode: RCodeNoError}}
		chain := NewChain(NewClusterZone(newFakeClient(t), DefaultClusterDomain, 30), custom, upstream)
		response, err := chain.Resolve(context.Background(), Query{Name: "api.notcluster.local.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(response.Answers) != 1 || response.Answers[0].A != netip.MustParseAddr("10.0.0.9") || upstream.calls != 0 {
			t.Fatalf("response=%+v upstream calls=%d", response, upstream.calls)
		}
	})

	t.Run("authoritative custom miss stops upstream", func(t *testing.T) {
		zone := readyDNSZone("zone", "tenant-a", "example.com")
		custom := NewCustomZone(newCustomDNSClient(t, zone), noShuffle)
		upstream := &countingResolver{response: Response{RCode: RCodeNoError}}
		chain := NewChain(NewClusterZone(newFakeClient(t), DefaultClusterDomain, 30), custom, upstream)
		response, err := chain.Resolve(context.Background(), Query{Name: "missing.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if response.RCode != RCodeNXDomain || upstream.calls != 0 {
			t.Fatalf("response=%+v upstream calls=%d", response, upstream.calls)
		}
	})

	t.Run("foreign zone falls through upstream", func(t *testing.T) {
		zone := readyDNSZone("zone", "tenant-b", "example.com")
		custom := NewCustomZone(newCustomDNSClient(t, zone), noShuffle)
		upstream := &countingResolver{response: Response{RCode: RCodeNoError}}
		chain := NewChain(NewClusterZone(newFakeClient(t), DefaultClusterDomain, 30), custom, upstream)
		response, err := chain.Resolve(context.Background(), Query{Name: "www.example.com.", Type: TypeA, Class: ClassINET, CallerVPC: "tenant-a"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if response.RCode != RCodeNoError || upstream.calls != 1 {
			t.Fatalf("response=%+v upstream calls=%d", response, upstream.calls)
		}
	})
}
