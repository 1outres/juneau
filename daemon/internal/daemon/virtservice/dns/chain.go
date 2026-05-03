package dns

import (
	"context"
	"errors"
)

// Chain is a Resolver that tries each child resolver in order and
// returns the first non-ErrNotInZone result. Used to layer the
// authoritative cluster zone in front of the upstream forwarder.
type Chain struct {
	resolvers []Resolver
}

// NewChain wraps the given resolvers; nil entries are dropped.
func NewChain(resolvers ...Resolver) *Chain {
	out := make([]Resolver, 0, len(resolvers))
	for _, r := range resolvers {
		if r != nil {
			out = append(out, r)
		}
	}
	return &Chain{resolvers: out}
}

// Resolve walks the chain. ErrNotInZone is interpreted as "skip this
// resolver"; any other error stops the chain so the handler can map
// it to ServerFailure.
func (c *Chain) Resolve(ctx context.Context, q Query) (Response, error) {
	if len(c.resolvers) == 0 {
		return Response{RCode: RCodeServerFailure}, errors.New("dns: empty resolver chain")
	}
	for _, r := range c.resolvers {
		resp, err := r.Resolve(ctx, q)
		if errors.Is(err, ErrNotInZone) {
			continue
		}
		if err != nil {
			return resp, err
		}
		return resp, nil
	}
	// Every resolver declined → REFUSED so the client knows we're
	// not the authoritative answerer.
	return Response{RCode: RCodeRefused}, nil
}
