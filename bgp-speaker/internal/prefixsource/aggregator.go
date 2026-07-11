package prefixsource

import (
	"context"
	"net"
	"sort"

	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
)

// Aggregate fans out across the configured sources, merges their
// advertisements into a deterministic prefix set, and surfaces a
// per-CIDR Ref list for downstream observability.
//
// A single source's transient error (returned via error, not
// Result.Errors) is fatal for the whole aggregate; the contract is
// that sources should prefer Result.Errors for "this resource is
// invalid, but the others are fine" cases. The boundary is the same
// one Kubernetes controllers use: returned errors trigger requeue,
// recorded errors update status.
func Aggregate(ctx context.Context, sources []Source, in Input) (Aggregated, error) {
	out := Aggregated{
		BySource: map[string][]SourceAdvertisement{},
	}
	mergedPrefixes := newPrefixSet()
	for _, s := range sources {
		r, err := s.Build(ctx, in)
		if err != nil {
			return Aggregated{}, err
		}
		out.BySource[s.Name()] = append(out.BySource[s.Name()], r.Advertisements...)
		out.Advertisements = append(out.Advertisements, r.Advertisements...)
		out.Errors = append(out.Errors, r.Errors...)
		for _, ad := range r.Advertisements {
			ref := Ref{
				Kind:      ad.SourceKind,
				Namespace: ad.SourceNamespace,
				Name:      ad.SourceName,
			}
			for _, p := range ad.Prefixes {
				if p == nil {
					continue
				}
				mergedPrefixes.add(p, ref)
			}
		}
	}

	out.MergedPrefixes = mergedPrefixes.sortedPrefixes()
	out.PrefixSources = mergedPrefixes.sourcesByCIDR()
	out.Records = mergedPrefixes.records()
	return out, nil
}

// Aggregated is the result of one Aggregate call. The naming keeps
// the per-source `Result` type free of any "aggregate" qualifier so
// each implementer's signature stays short.
type Aggregated struct {
	// MergedPrefixes is the deduplicated, lexicographically-sorted
	// list of CIDRs to feed into the bird config builder.
	MergedPrefixes []*net.IPNet

	// Advertisements is the flattened list of every source's
	// advertisement, preserved in source order. Used by status
	// publishers that want a "what each source said" view.
	Advertisements []SourceAdvertisement

	// BySource indexes Advertisements by Source.Name(). Sources are
	// keyed by name (not by kind) so multiple sources of the same
	// kind remain distinguishable.
	BySource map[string][]SourceAdvertisement

	// PrefixSources maps a CIDR string to the Refs that contributed
	// it, useful for debug commands and for emitting a per-prefix
	// audit log.
	PrefixSources map[string][]Ref

	// Records is the flat list of (prefix, sources) pairs in
	// MergedPrefixes order. Provided for callers that don't want to
	// reconstruct the pairing themselves.
	Records []PrefixRecord

	// Errors is the union of every source's recorded errors.
	Errors []nodestate.ResourceError
}

// PrefixRecord pairs a merged prefix with the Refs that contributed
// it. Returned by the aggregator in MergedPrefixes order.
type PrefixRecord struct {
	Prefix  *net.IPNet
	Sources []Ref
}

// prefixSet maintains a CIDR-keyed map under the canonical
// network-address form (e.g. 203.0.113.0/24) so that callers can
// pass any sub-form ("203.0.113.5/24") and still have it dedupe
// correctly. Dedup also runs at the source level, but doing it
// here once means future sources don't have to rediscover the
// invariant.
type prefixSet struct {
	byCIDR map[string]*PrefixRecord
}

func newPrefixSet() *prefixSet {
	return &prefixSet{byCIDR: map[string]*PrefixRecord{}}
}

func (s *prefixSet) add(p *net.IPNet, ref Ref) {
	if p == nil {
		return
	}
	canonical := canonicalCIDR(p)
	key := canonical.String()
	rec, ok := s.byCIDR[key]
	if !ok {
		rec = &PrefixRecord{Prefix: canonical}
		s.byCIDR[key] = rec
	}
	for _, existing := range rec.Sources {
		if existing == ref {
			return
		}
	}
	rec.Sources = append(rec.Sources, ref)
}

func (s *prefixSet) sortedPrefixes() []*net.IPNet {
	keys := make([]string, 0, len(s.byCIDR))
	for k := range s.byCIDR {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*net.IPNet, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.byCIDR[k].Prefix)
	}
	return out
}

func (s *prefixSet) sourcesByCIDR() map[string][]Ref {
	out := make(map[string][]Ref, len(s.byCIDR))
	for k, rec := range s.byCIDR {
		out[k] = append([]Ref(nil), rec.Sources...)
	}
	return out
}

func (s *prefixSet) records() []PrefixRecord {
	keys := make([]string, 0, len(s.byCIDR))
	for k := range s.byCIDR {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]PrefixRecord, 0, len(keys))
	for _, k := range keys {
		rec := s.byCIDR[k]
		out = append(out, PrefixRecord{
			Prefix:  rec.Prefix,
			Sources: append([]Ref(nil), rec.Sources...),
		})
	}
	return out
}

// canonicalCIDR returns the network-address form of an IPNet so that
// consumers passing different IPs within the same network still end
// up with one map entry. The result is a fresh allocation; mutating
// it does not affect the input.
func canonicalCIDR(p *net.IPNet) *net.IPNet {
	out := &net.IPNet{
		IP:   p.IP.Mask(p.Mask),
		Mask: append(net.IPMask(nil), p.Mask...),
	}
	return out
}
