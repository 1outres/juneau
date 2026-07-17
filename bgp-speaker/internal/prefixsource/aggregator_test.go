package prefixsource

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
)

// constSource lets a test return a fixed Result without going
// through the kube client. Two implementations may share a kind but
// must use different names so the aggregator's BySource map remains
// unambiguous.
type constSource struct {
	name   string
	result Result
	err    error
}

func (s constSource) Name() string { return s.name }
func (s constSource) Build(_ context.Context, _ Input) (Result, error) {
	return s.result, s.err
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ipnet, err := ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return ipnet
}

func TestAggregate_DeduplicatesAcrossSources(t *testing.T) {
	t.Parallel()

	a := constSource{name: "src-a", result: Result{
		Advertisements: []SourceAdvertisement{
			{
				SourceKind: "BGPAdvertisement",
				SourceName: "adv-a",
				Prefixes:   []*net.IPNet{mustCIDR(t, "10.0.0.0/24"), mustCIDR(t, "10.1.0.0/24")},
			},
		},
	}}
	b := constSource{name: "src-b", result: Result{
		Advertisements: []SourceAdvertisement{
			{
				SourceKind: "ServiceLoadBalancer",
				SourceName: "web",
				Prefixes:   []*net.IPNet{mustCIDR(t, "10.1.0.0/24"), mustCIDR(t, "203.0.113.10/32")},
			},
		},
	}}

	out, err := Aggregate(context.Background(), []Source{a, b}, Input{})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	gotPrefixes := []string{}
	for _, p := range out.MergedPrefixes {
		gotPrefixes = append(gotPrefixes, p.String())
	}
	want := []string{"10.0.0.0/24", "10.1.0.0/24", "203.0.113.10/32"}
	if !reflect.DeepEqual(gotPrefixes, want) {
		t.Errorf("MergedPrefixes: want %v, got %v", want, gotPrefixes)
	}

	overlapping := out.PrefixSources["10.1.0.0/24"]
	if len(overlapping) != 2 {
		t.Errorf("PrefixSources[10.1.0.0/24]: want 2 sources, got %v", overlapping)
	}
}

func TestAggregate_PropagatesErrorsButPreservesOtherSources(t *testing.T) {
	t.Parallel()

	a := constSource{name: "src-a", result: Result{
		Advertisements: []SourceAdvertisement{
			{SourceKind: "BGPAdvertisement", SourceName: "ok", Prefixes: []*net.IPNet{mustCIDR(t, "10.10.0.0/24")}},
		},
		Errors: []nodestate.ResourceError{
			{ResourceKind: "AddressPool", ResourceName: "missing", Message: "not found"},
		},
	}}
	b := constSource{name: "src-b", result: Result{
		Advertisements: []SourceAdvertisement{
			{SourceKind: "ServiceLoadBalancer", SourceName: "web", Prefixes: []*net.IPNet{mustCIDR(t, "203.0.113.5/32")}},
		},
	}}

	out, err := Aggregate(context.Background(), []Source{a, b}, Input{})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(out.MergedPrefixes) != 2 {
		t.Errorf("MergedPrefixes: want 2 entries, got %v", out.MergedPrefixes)
	}
	if len(out.Errors) != 1 {
		t.Errorf("Errors: want 1, got %v", out.Errors)
	}
}

func TestAggregate_CanonicalisesNonNetworkAddresses(t *testing.T) {
	t.Parallel()

	// 203.0.113.5/24 → 203.0.113.0/24 once canonicalised.
	src := constSource{name: "src", result: Result{
		Advertisements: []SourceAdvertisement{
			{
				SourceKind: "BGPAdvertisement",
				SourceName: "noisy",
				Prefixes:   []*net.IPNet{mustCIDR(t, "203.0.113.5/24")},
			},
		},
	}}
	out, err := Aggregate(context.Background(), []Source{src}, Input{})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if got := out.MergedPrefixes[0].String(); got != "203.0.113.0/24" {
		t.Errorf("canonical: want 203.0.113.0/24, got %s", got)
	}
}
