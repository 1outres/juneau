package peerindex_test

import (
	"testing"

	"github.com/1outres/juneau/bgp-speaker/internal/peerindex"
)

func TestPeerIndex_Empty_NameMiss(t *testing.T) {
	t.Parallel()
	idx := peerindex.New()
	if name, ok := idx.Name("10.0.0.1"); ok || name != "" {
		t.Errorf("Name on empty: want ('', false), got (%q, %v)", name, ok)
	}
}

func TestPeerIndex_SetAndName(t *testing.T) {
	t.Parallel()
	idx := peerindex.New()
	idx.Set(map[string]string{
		"10.0.0.1": "upstream-a",
		"10.0.0.2": "upstream-b",
	})

	if name, ok := idx.Name("10.0.0.1"); !ok || name != "upstream-a" {
		t.Errorf("Name 10.0.0.1: want ('upstream-a', true), got (%q, %v)", name, ok)
	}
	if name, ok := idx.Name("10.0.0.9"); ok || name != "" {
		t.Errorf("Name 10.0.0.9: want ('', false), got (%q, %v)", name, ok)
	}
}

func TestPeerIndex_Set_Replaces(t *testing.T) {
	t.Parallel()
	idx := peerindex.New()
	idx.Set(map[string]string{"10.0.0.1": "old"})
	idx.Set(map[string]string{"10.0.0.2": "new"})

	if _, ok := idx.Name("10.0.0.1"); ok {
		t.Errorf("Name 10.0.0.1 after replace: want miss, got hit")
	}
	if name, ok := idx.Name("10.0.0.2"); !ok || name != "new" {
		t.Errorf("Name 10.0.0.2: want ('new', true), got (%q, %v)", name, ok)
	}
}

func TestPeerIndex_Set_NilMapClears(t *testing.T) {
	t.Parallel()
	idx := peerindex.New()
	idx.Set(map[string]string{"10.0.0.1": "a"})
	idx.Set(nil)
	if _, ok := idx.Name("10.0.0.1"); ok {
		t.Errorf("Name after Set(nil): want miss, got hit")
	}
}
