// Package prefixsource is the bgp-speaker abstraction over "where do
// the prefixes we should advertise come from?". A Source listens to a
// specific Kubernetes resource family (BGPAdvertisement +
// AddressPool, ServiceLoadBalancer, …) and produces a uniform set of
// SourceAdvertisement entries that the aggregator merges and feeds to
// the bird config builder and BGPNodeState publisher.
//
// Splitting prefix discovery from peer discovery is a deliberate
// separation: peers are configured per-cluster, while prefix sources
// proliferate over time (per-feature LB, anycast, custom CRDs).
// Concentrating peer logic in the speaker and prefix logic behind a
// stable interface keeps each one independently testable.
package prefixsource

import (
	"context"
	"net"

	"github.com/1outres/juneau/bgp-speaker/internal/nodestate"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Input carries the per-call context every Source needs. The struct
// is forward-compatible: adding a new field does not break existing
// implementations.
type Input struct {
	// NodeName is the Kubernetes node this speaker runs on. Sources
	// use it for per-node filters such as "only emit when this node
	// holds a ready local backend."
	NodeName string

	// Client is a controller-runtime client scoped to the speaker's
	// kube cache, used for List / Get against Juneau and core types.
	Client client.Client
}

// Result is what every Source returns. It carries advertisements
// (one logical (kind, name, addressPool) unit per entry) and
// validation errors that should surface on BGPNodeState without
// preventing other sources from publishing.
type Result struct {
	Advertisements []SourceAdvertisement
	Errors         []nodestate.ResourceError
}

// SourceAdvertisement is the unit a Source emits. The fields encode
// "this prefix list comes from this resource."
//
// The layout intentionally mirrors what BGPNodeState surfaces, so the
// aggregator can pass-through to status without re-shaping.
type SourceAdvertisement struct {
	// SourceKind is the upstream resource kind (BGPAdvertisement,
	// ServiceLoadBalancer, …). Always set so multiple sources sharing
	// a name in different kinds remain distinguishable.
	SourceKind string

	// SourceNamespace is empty for cluster-scoped resources.
	SourceNamespace string

	// SourceName is the resource name. Empty is treated as "anonymous"
	// — sources should set it whenever a single resource owns the
	// advertisement.
	SourceName string

	// AddressPool, when set, is the AddressPool the prefix list is
	// derived from. Non-pool sources (ServiceLoadBalancer) leave this
	// empty.
	AddressPool string

	// Prefixes is the list of CIDRs to advertise on behalf of this
	// resource. Pre-canonicalised (CIDR base, e.g. 10.0.0.0/24) and
	// deduplicated within the slice.
	Prefixes []*net.IPNet
}

// Ref points back at a single resource. Used by the aggregator to
// list every source that contributed a particular CIDR, so a future
// kubectl-juneau "where does this prefix come from" query has the
// answer in-tree.
type Ref struct {
	Kind      string
	Namespace string
	Name      string
}

// Source is the polymorphism boundary the aggregator walks. New
// resource types only need a Source implementation to participate;
// the aggregator and speaker do not need to know about them.
type Source interface {
	// Name is a stable identifier used in logs and tests. Two
	// implementations must not share the same name.
	Name() string

	// Build is the per-reconcile entry point. The function is
	// expected to be idempotent and side-effect-free; mutations to
	// upstream resources belong to the controller, not the speaker.
	Build(ctx context.Context, in Input) (Result, error)
}
