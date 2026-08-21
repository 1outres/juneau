package ownedaddr

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
)

// Map is the subset of *ebpf.Map that Store drives.
type Map interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

// Store keeps external_address_pools equal to the union of the prefixes
// its owners claim, and applies only the difference on every change.
//
// The union matters because independent reconcilers claim the same
// prefix: the address of an ExternalNetworkAttachment is claimed by the
// NAPT reconciler and, in ARP mode, by the ARP advertisement reconciler
// as well. If each reconciler wrote the map on its own, whichever one
// dropped its claim first would delete an entry the other still needs.
type Store struct {
	m Map

	mu        sync.Mutex
	claims    map[owner]map[Key]struct{}
	installed map[Key]struct{}
}

type owner struct {
	scope string
	name  string
}

func NewStore(m Map) *Store {
	return &Store{
		m:         m,
		claims:    make(map[owner]map[Key]struct{}),
		installed: make(map[Key]struct{}),
	}
}

// Scope namespaces one reconciler's owners so that two reconcilers can
// use the same owner name without overwriting each other, and so a
// reconciler can drop all of its own claims on shutdown.
func (s *Store) Scope(name string) *Scope {
	return &Scope{store: s, name: name}
}

func (s *Store) set(o owner, keys []Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(keys) == 0 {
		delete(s.claims, o)
	} else {
		claimed := make(map[Key]struct{}, len(keys))
		for _, key := range keys {
			claimed[key] = struct{}{}
		}
		s.claims[o] = claimed
	}
	return s.apply()
}

func (s *Store) releaseScope(scope string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for o := range s.claims {
		if o.scope == scope {
			delete(s.claims, o)
		}
	}
	return s.apply()
}

// apply reconciles the map against the union of every claim. The caller
// must hold s.mu. installed tracks what the kernel actually holds, so a
// failed Update or Delete is retried on the next call instead of being
// remembered as done.
func (s *Store) apply() error {
	desired := make(map[Key]struct{}, len(s.installed))
	for _, claimed := range s.claims {
		for key := range claimed {
			desired[key] = struct{}{}
		}
	}

	var errs []error
	for _, key := range sortedKeys(s.installed) {
		if _, keep := desired[key]; keep {
			continue
		}
		bpfKey := key.bpfKey()
		if err := s.m.Delete(&bpfKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete external_address_pools entry %s: %w", key, err))
			continue
		}
		delete(s.installed, key)
	}

	present := uint8(1)
	for _, key := range sortedKeys(desired) {
		if _, done := s.installed[key]; done {
			continue
		}
		bpfKey := key.bpfKey()
		if err := s.m.Update(&bpfKey, &present, ebpf.UpdateAny); err != nil {
			errs = append(errs, fmt.Errorf("update external_address_pools entry %s: %w", key, err))
			continue
		}
		s.installed[key] = struct{}{}
	}

	return errors.Join(errs...)
}

func sortedKeys(set map[Key]struct{}) []Key {
	keys := make([]Key, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Prefixlen != keys[j].Prefixlen {
			return keys[i].Prefixlen < keys[j].Prefixlen
		}
		return keys[i].Addr < keys[j].Addr
	})
	return keys
}

// Scope is one reconciler's view of a Store.
type Scope struct {
	store *Store
	name  string
}

// Set replaces the prefixes owner claims. An empty set releases every
// prefix owner held, exactly like Release.
func (sc *Scope) Set(name string, keys []Key) error {
	return sc.store.set(owner{scope: sc.name, name: name}, keys)
}

// Release drops every prefix owner claims.
func (sc *Scope) Release(name string) error {
	return sc.Set(name, nil)
}

// ReleaseAll drops every claim made through this Scope. Claims made by
// other Scopes are untouched, so a prefix they still claim stays in the
// map.
func (sc *Scope) ReleaseAll() error {
	return sc.store.releaseScope(sc.name)
}
