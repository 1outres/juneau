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

// Delivery says which node the network delivers a claimed prefix to. It is
// the value external_address_pools holds, so the numbers must match
// EXTERNAL_ADDRESS_DELIVERED_* in daemon/bpf/maps.h.
type Delivery uint8

const (
	// DeliveredHere is a prefix the network delivers to this node.
	DeliveredHere Delivery = 1
	// DeliveredElsewhere is a prefix juneau handles, but that another node
	// advertises by itself, so the network delivers it there. node_ingress
	// still handles a packet for it that lands here; pod_egress does not
	// hand one to node_ingress.
	DeliveredElsewhere Delivery = 2
)

func (d Delivery) String() string {
	switch d {
	case DeliveredHere:
		return "here"
	case DeliveredElsewhere:
		return "elsewhere"
	default:
		return fmt.Sprintf("Delivery(%d)", uint8(d))
	}
}

// Claim is one prefix an owner claims, and where it is delivered.
type Claim struct {
	Key      Key
	Delivery Delivery
}

// Store keeps external_address_pools equal to the union of the prefixes
// its owners claim, and applies only the difference on every change.
//
// The union matters because independent reconcilers claim the same
// prefix: the address of an ExternalNetworkAttachment is claimed by the
// NAPT reconciler and, in ARP mode, by the ARP advertisement reconciler
// as well. If each reconciler wrote the map on its own, whichever one
// dropped its claim first would delete an entry the other still needs.
//
// When claims of the same prefix disagree on where it is delivered,
// DeliveredHere wins: a node that advertises a prefix itself is delivered
// that prefix, whatever other nodes advertise.
type Store struct {
	m Map

	mu        sync.Mutex
	claims    map[owner]map[Key]Delivery
	installed map[Key]Delivery
}

type owner struct {
	scope string
	name  string
}

func NewStore(m Map) *Store {
	return &Store{
		m:         m,
		claims:    make(map[owner]map[Key]Delivery),
		installed: make(map[Key]Delivery),
	}
}

// Scope namespaces one reconciler's owners so that two reconcilers can
// use the same owner name without overwriting each other, and so a
// reconciler can drop all of its own claims on shutdown.
func (s *Store) Scope(name string) *Scope {
	return &Scope{store: s, name: name}
}

func (s *Store) set(o owner, claims []Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(claims) == 0 {
		delete(s.claims, o)
	} else {
		claimed := make(map[Key]Delivery, len(claims))
		for _, claim := range claims {
			claimed[claim.Key] = preferredDelivery(claimed[claim.Key], claim.Delivery)
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

// preferredDelivery merges two claims of one prefix. current is 0 when
// there is no claim yet.
func preferredDelivery(current, next Delivery) Delivery {
	if current == DeliveredHere || next == DeliveredHere {
		return DeliveredHere
	}
	return next
}

// apply reconciles the map against the union of every claim. The caller
// must hold s.mu. installed tracks what the kernel actually holds, so a
// failed Update or Delete is retried on the next call instead of being
// remembered as done.
func (s *Store) apply() error {
	desired := make(map[Key]Delivery, len(s.installed))
	for _, claimed := range s.claims {
		for key, delivery := range claimed {
			desired[key] = preferredDelivery(desired[key], delivery)
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

	for _, key := range sortedKeys(desired) {
		delivery := desired[key]
		if installed, done := s.installed[key]; done && installed == delivery {
			continue
		}
		bpfKey := key.bpfKey()
		value := uint8(delivery)
		if err := s.m.Update(&bpfKey, &value, ebpf.UpdateAny); err != nil {
			errs = append(errs, fmt.Errorf("update external_address_pools entry %s: %w", key, err))
			continue
		}
		s.installed[key] = delivery
	}

	return errors.Join(errs...)
}

func sortedKeys(set map[Key]Delivery) []Key {
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

// Set replaces the prefixes owner claims with keys, each delivered to this
// node. An empty set releases every prefix owner held, exactly like
// Release.
func (sc *Scope) Set(name string, keys []Key) error {
	claims := make([]Claim, 0, len(keys))
	for _, key := range keys {
		claims = append(claims, Claim{Key: key, Delivery: DeliveredHere})
	}
	return sc.SetClaims(name, claims)
}

// SetClaims replaces the prefixes owner claims, each with where it is
// delivered. An empty set releases every prefix owner held.
func (sc *Scope) SetClaims(name string, claims []Claim) error {
	return sc.store.set(owner{scope: sc.name, name: name}, claims)
}

// Release drops every prefix owner claims.
func (sc *Scope) Release(name string) error {
	return sc.SetClaims(name, nil)
}

// ReleaseAll drops every claim made through this Scope. Claims made by
// other Scopes are untouched, so a prefix they still claim stays in the
// map.
func (sc *Scope) ReleaseAll() error {
	return sc.store.releaseScope(sc.name)
}
