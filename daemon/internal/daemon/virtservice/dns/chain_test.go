package dns

import (
	"context"
	"errors"
	"testing"
)

type stubResolver struct {
	resp Response
	err  error
}

func (s stubResolver) Resolve(_ context.Context, _ Query) (Response, error) {
	return s.resp, s.err
}

func TestChainSkipsNotInZone(t *testing.T) {
	first := stubResolver{err: ErrNotInZone}
	second := stubResolver{resp: Response{Authoritative: true, RCode: RCodeNoError}}
	c := NewChain(first, second)

	res, err := c.Resolve(context.Background(), Query{Name: "x."})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !res.Authoritative {
		t.Fatalf("expected second resolver's authoritative response, got %+v", res)
	}
}

func TestChainStopsOnError(t *testing.T) {
	want := errors.New("boom")
	first := stubResolver{err: want}
	second := stubResolver{resp: Response{Authoritative: true}}
	c := NewChain(first, second)

	_, err := c.Resolve(context.Background(), Query{Name: "x."})
	if !errors.Is(err, want) {
		t.Fatalf("expected first resolver's error, got %v", err)
	}
}

func TestChainEmptyAllSkip(t *testing.T) {
	c := NewChain(stubResolver{err: ErrNotInZone}, stubResolver{err: ErrNotInZone})
	res, err := c.Resolve(context.Background(), Query{Name: "x."})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.RCode != RCodeRefused {
		t.Errorf("expected REFUSED when no resolver answers, got rcode=%d", res.RCode)
	}
}

func TestChainEmptyChainErrors(t *testing.T) {
	c := NewChain()
	_, err := c.Resolve(context.Background(), Query{Name: "x."})
	if err == nil {
		t.Fatal("expected error from empty chain")
	}
}
