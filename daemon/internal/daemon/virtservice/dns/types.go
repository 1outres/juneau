// Package dns implements the per-Subnet virtual DNS resolver that the
// juneau daemon binds at <Subnet>.status.dns:53.
//
// The package is split into:
//
//   * service.go   – lifecycle: Subnet informer → registry binding,
//                    constructs the resolver chain.
//   * handler.go   – PacketHandler implementation: parse → resolve →
//                    write response. Owns the wire format.
//   * zone.go      – cluster.local zone view: VPC-aware Service lookup
//                    backed by the daemon's Kubernetes cache.
//   * forwarder.go – upstream UDP forwarder for non-cluster names.
//
// The split keeps wire-level logic (handler) independent of resolution
// logic (zone + forwarder), so a future control-plane feature (e.g.
// stub zones, custom records) can plug in as another Resolver without
// touching the packet path.
package dns

import (
	"context"
	"net/netip"
	"time"
)

// QueryClass mirrors the dnsmessage.Class values we care about. Only
// ClassINET is supported; other classes get a NOTIMP response.
type QueryClass uint16

const (
	ClassINET QueryClass = 1
)

// QueryType mirrors the dnsmessage.Type values we answer. We
// translate to dnsmessage.Type at the wire layer; this enum exists so
// the resolver layer doesn't need to import dnsmessage.
type QueryType uint16

const (
	TypeA     QueryType = 1
	TypeAAAA  QueryType = 28
	TypeCNAME QueryType = 5
	TypePTR   QueryType = 12
)

// Query carries everything a Resolver needs to decide what to return
// for a single inbound DNS question.
type Query struct {
	// Name is the lower-cased FQDN with the trailing dot. e.g.
	// "kubernetes.default.svc.cluster.local."
	Name string
	Type QueryType
	Class QueryClass

	// CallerVPC is the Vpc resource name of the Pod that asked the
	// question. Resolved once at handler entry so resolvers don't
	// each have to do their own VPC lookup.
	CallerVPC string

	// CallerEnableService caches Vpc.spec.enableService for
	// CallerVPC. Resolvers use it to short-circuit the
	// svcpolicy.ResolvableFrom check.
	CallerEnableService bool

	// CallerIP is the Pod's source IP. Carried through for logging
	// and potential future EDNS Client Subnet support.
	CallerIP netip.Addr
}

// Answer is a single resource record the resolver wants to surface to
// the caller. Wire encoding lives in handler.go; resolvers stay
// independent of dnsmessage / wire formats.
type Answer struct {
	Name  string
	Type  QueryType
	Class QueryClass
	TTL   uint32
	A     netip.Addr // for TypeA
	// CNAME / PTR / etc. fields can be added here as we widen
	// resolver support; absent fields are simply ignored by the
	// wire encoder.
	CNAME string
	PTR   string
}

// Response is a resolver verdict. Empty Answers + RCodeNoError means
// "valid empty response" (e.g. NODATA); the wire layer translates
// non-zero RCode into the corresponding dnsmessage.RCode.
type Response struct {
	RCode     RCode
	Answers   []Answer
	// Authoritative reflects the AA bit on the wire. True for
	// cluster.local records served from the local Service cache;
	// false for forwarded responses.
	Authoritative bool
}

// RCode is the DNS response code. Mirrors dnsmessage.RCode but uses
// our own type so resolvers don't import the wire package.
type RCode uint16

const (
	RCodeNoError        RCode = 0
	RCodeFormErr        RCode = 1
	RCodeServerFailure  RCode = 2
	RCodeNXDomain       RCode = 3
	RCodeNotImplemented RCode = 4
	RCodeRefused        RCode = 5
)

// Resolver is the abstraction the handler dispatches a parsed query
// against. The default implementation chains a cluster.local zone in
// front of an upstream forwarder; tests can supply a fake.
type Resolver interface {
	// Resolve returns the response for q. ctx is bound to the
	// per-query handler timeout.
	Resolve(ctx context.Context, q Query) (Response, error)
}

// DefaultUpstreamTimeout is the per-query upstream forwarder budget.
// Set conservatively so a slow upstream doesn't pile up handler
// goroutines beyond the dispatcher's read rate.
const DefaultUpstreamTimeout = 2 * time.Second

// DefaultClusterDomain is the conventional cluster suffix
// kube-dns / CoreDNS use; matches what kubelet writes into Pods'
// /etc/resolv.conf search list. We answer cluster.local from the
// internal zone view; everything else is forwarded.
const DefaultClusterDomain = "cluster.local."
