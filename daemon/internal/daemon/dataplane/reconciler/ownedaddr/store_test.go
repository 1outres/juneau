package ownedaddr

import (
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

type fakeMap struct {
	entries   map[bpf.PodEgressExternalAddressPoolsKey]uint8
	updates   int
	deletes   int
	updateErr error
}

func newFakeMap() *fakeMap {
	return &fakeMap{entries: make(map[bpf.PodEgressExternalAddressPoolsKey]uint8)}
}

func (m *fakeMap) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.updates++
	m.entries[*(key.(*bpf.PodEgressExternalAddressPoolsKey))] = *(value.(*uint8))
	return nil
}

func (m *fakeMap) Delete(key any) error {
	k := *(key.(*bpf.PodEgressExternalAddressPoolsKey))
	if _, ok := m.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, k)
	m.deletes++
	return nil
}

func (m *fakeMap) prefixes() []string {
	out := make([]string, 0, len(m.entries))
	for k := range m.entries {
		out = append(out, Key{Prefixlen: k.Prefixlen, Addr: k.Addr}.String())
	}
	sort.Strings(out)
	return out
}

func mustParse(t *testing.T, raw string) Key {
	t.Helper()
	key, err := ParsePrefix(raw)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", raw, err)
	}
	return key
}

func assertPrefixes(t *testing.T, m *fakeMap, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := m.prefixes()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("map prefixes = %v, want %v", got, want)
	}
}

func TestStoreKeepsPrefixClaimedByAnotherOwner(t *testing.T) {
	m := newFakeMap()
	scope := NewStore(m).Scope("napt")
	shared := mustParse(t, "192.0.2.10/32")

	if err := scope.Set("attachment-a", []Key{shared}); err != nil {
		t.Fatalf("Set attachment-a: %v", err)
	}
	if err := scope.Set("attachment-b", []Key{shared}); err != nil {
		t.Fatalf("Set attachment-b: %v", err)
	}
	if err := scope.Release("attachment-a"); err != nil {
		t.Fatalf("Release attachment-a: %v", err)
	}

	assertPrefixes(t, m, "192.0.2.10/32")
	if m.deletes != 0 {
		t.Errorf("deletes = %d, want 0 while another owner still claims the prefix", m.deletes)
	}
}

func TestStoreDeletesPrefixWhenLastOwnerReleases(t *testing.T) {
	m := newFakeMap()
	scope := NewStore(m).Scope("napt")
	shared := mustParse(t, "192.0.2.10/32")

	for _, owner := range []string{"attachment-a", "attachment-b"} {
		if err := scope.Set(owner, []Key{shared}); err != nil {
			t.Fatalf("Set %s: %v", owner, err)
		}
	}
	for _, owner := range []string{"attachment-a", "attachment-b"} {
		if err := scope.Release(owner); err != nil {
			t.Fatalf("Release %s: %v", owner, err)
		}
	}

	assertPrefixes(t, m)
	if m.deletes != 1 {
		t.Errorf("deletes = %d, want 1", m.deletes)
	}
}

func TestStoreRemovesOnlyPrefixesTheOwnerDropped(t *testing.T) {
	m := newFakeMap()
	scope := NewStore(m).Scope("bgp-pool")
	kept := mustParse(t, "10.0.0.0/24")
	dropped := mustParse(t, "10.1.0.0/24")
	added := mustParse(t, "10.2.0.0/24")

	if err := scope.Set("pools", []Key{kept, dropped}); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	updatesAfterFirst := m.updates

	if err := scope.Set("pools", []Key{kept, added}); err != nil {
		t.Fatalf("second Set: %v", err)
	}

	assertPrefixes(t, m, "10.0.0.0/24", "10.2.0.0/24")
	if m.deletes != 1 {
		t.Errorf("deletes = %d, want 1", m.deletes)
	}
	if got := m.updates - updatesAfterFirst; got != 1 {
		t.Errorf("updates during second Set = %d, want 1", got)
	}
}

func TestStoreDoesNotRewriteAlreadyInstalledPrefixes(t *testing.T) {
	m := newFakeMap()
	scope := NewStore(m).Scope("bgp-pool")
	keys := []Key{mustParse(t, "10.0.0.0/24"), mustParse(t, "10.1.0.0/24")}

	for range 3 {
		if err := scope.Set("pools", keys); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}

	if m.updates != len(keys) {
		t.Errorf("updates = %d, want %d", m.updates, len(keys))
	}
	if m.deletes != 0 {
		t.Errorf("deletes = %d, want 0", m.deletes)
	}
}

func TestStoreDedupesRepeatedPrefixesFromOneOwner(t *testing.T) {
	m := newFakeMap()
	scope := NewStore(m).Scope("bgp-pool")
	key := mustParse(t, "10.0.0.0/24")

	if err := scope.Set("pools", []Key{key, key}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	assertPrefixes(t, m, "10.0.0.0/24")
	if m.updates != 1 {
		t.Errorf("updates = %d, want 1", m.updates)
	}
}

func TestScopeReleaseAllDropsOnlyItsOwnClaims(t *testing.T) {
	m := newFakeMap()
	store := NewStore(m)
	napt := store.Scope("napt")
	externalARP := store.Scope("external-arp")
	shared := mustParse(t, "192.0.2.10/32")
	naptOnly := mustParse(t, "192.0.2.11/32")
	arpOnly := mustParse(t, "192.0.2.12/32")

	if err := napt.Set("attachment-a", []Key{shared, naptOnly}); err != nil {
		t.Fatalf("Set napt: %v", err)
	}
	if err := externalARP.Set("adv-a", []Key{shared, arpOnly}); err != nil {
		t.Fatalf("Set external-arp: %v", err)
	}

	if err := napt.ReleaseAll(); err != nil {
		t.Fatalf("ReleaseAll: %v", err)
	}

	assertPrefixes(t, m, "192.0.2.10/32", "192.0.2.12/32")
}

func TestScopesWithTheSameOwnerNameDoNotCollide(t *testing.T) {
	m := newFakeMap()
	store := NewStore(m)
	first := store.Scope("napt")
	second := store.Scope("external-arp")

	if err := first.Set("same-name", []Key{mustParse(t, "192.0.2.10/32")}); err != nil {
		t.Fatalf("Set first: %v", err)
	}
	if err := second.Set("same-name", []Key{mustParse(t, "192.0.2.11/32")}); err != nil {
		t.Fatalf("Set second: %v", err)
	}

	assertPrefixes(t, m, "192.0.2.10/32", "192.0.2.11/32")
}

func TestStoreRetriesUpdateAfterMapFailure(t *testing.T) {
	m := newFakeMap()
	m.updateErr = errors.New("boom")
	scope := NewStore(m).Scope("bgp-pool")
	keys := []Key{mustParse(t, "10.0.0.0/24")}

	if err := scope.Set("pools", keys); err == nil {
		t.Fatal("want error from failing map update, got none")
	}

	m.updateErr = nil
	if err := scope.Set("pools", keys); err != nil {
		t.Fatalf("Set after recovery: %v", err)
	}
	assertPrefixes(t, m, "10.0.0.0/24")
}
