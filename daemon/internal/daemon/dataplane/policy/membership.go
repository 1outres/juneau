package policy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// MembershipKey is the canonical (vpc_id, ipv4) tuple. ipv4 is in
// network byte order so we can write it directly into the BPF map.
type MembershipKey struct {
	VpcID uint32
	IPv4  uint32 // network byte order
}

// MembershipValue is one entry's resolved SG list. Length is bounded by
// MAX_SGS_PER_NIC; callers must trim before constructing.
type MembershipValue struct {
	GroupIDs []uint32
}

// membershipTable is the write side of sg_membership_map. *ebpf.Map
// implements it; tests bring their own because creating a BPF map
// needs CAP_BPF.
type membershipTable interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

// membershipEntry is what one owner last wrote into the table.
type membershipEntry struct {
	key      MembershipKey
	groupIDs []uint32
}

func (e membershipEntry) equal(other membershipEntry) bool {
	return e.key == other.key && slices.Equal(e.groupIDs, other.groupIDs)
}

// MembershipStore writes (vpc_id, ipv4) → SG list into sg_membership_map.
// It maintains its own snapshot so a NetworkInterface change can both
// apply the new entry and clean up the previous (vpc_id, ipv4) tuple
// when the Pod's IP changes.
type MembershipStore struct {
	table  membershipTable
	bumper Bumper

	mu        sync.Mutex
	snapshots map[string]membershipEntry // owner key (e.g. NetworkInterface name) -> last-written entry
}

// NewMembershipStore wraps sg_membership_map.
//
// bumper is what tells the data plane to stop trusting the flows it
// admitted while an interface had a different SG list: which rules
// apply to a Pod follows from its membership.
func NewMembershipStore(m *ebpf.Map, bumper Bumper) *MembershipStore {
	return newMembershipStore(m, bumper)
}

func newMembershipStore(table membershipTable, bumper Bumper) *MembershipStore {
	return &MembershipStore{
		table:     table,
		bumper:    bumper,
		snapshots: make(map[string]membershipEntry),
	}
}

// MaxSGsPerNIC mirrors MAX_SGS_PER_NIC in maps.h.
const MaxSGsPerNIC = 2

// Apply writes the membership entry for owner. If owner previously
// pointed at a different MembershipKey (e.g. its Pod was re-created
// with a different IP) the old key is deleted to avoid stale entries.
//
// Empty val.GroupIDs results in deletion (the BPF eval treats "no
// entry" and "entry with count=0" identically, so we keep the table
// dense by deleting in the empty case).
func (s *MembershipStore) Apply(owner string, key MembershipKey, val MembershipValue) error {
	if key.VpcID == 0 || key.IPv4 == 0 {
		return fmt.Errorf("policy: invalid membership key (vpc=%d ipv4=%#x)", key.VpcID, key.IPv4)
	}
	groupIDs := val.GroupIDs
	if len(groupIDs) > MaxSGsPerNIC {
		groupIDs = groupIDs[:MaxSGsPerNIC]
	}

	if len(groupIDs) == 0 {
		return s.Delete(owner)
	}

	bpfKey := bpf.PodEgressSgMembershipKey{
		VpcId: key.VpcID,
		Ipv4:  key.IPv4,
	}
	bpfVal := bpf.PodEgressSgMembershipVal{
		Count: uint8(len(groupIDs)),
	}
	copy(bpfVal.Sgs[:], groupIDs)

	if err := s.table.Update(bpfKey, bpfVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write membership for %s: %w", owner, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.snapshots[owner]
	if hadPrevious && previous.key != key {
		if err := s.deleteKey(previous.key); err != nil {
			zap.S().Warnf("policy: clean up stale membership for %s: %v", owner, err)
		}
	}

	entry := membershipEntry{key: key, groupIDs: slices.Clone(groupIDs)}
	if hadPrevious && previous.equal(entry) {
		return nil
	}
	if err := s.bumper.Bump(); err != nil {
		return fmt.Errorf("policy: invalidate admitted flows after membership for %s changed: %w", owner, err)
	}
	s.snapshots[owner] = entry
	return nil
}

// Delete removes the membership entry that owner currently maps to.
// Idempotent.
func (s *MembershipStore) Delete(owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.snapshots[owner]
	if !hadPrevious {
		return nil
	}
	if err := s.deleteKey(previous.key); err != nil {
		return err
	}
	if err := s.bumper.Bump(); err != nil {
		return fmt.Errorf("policy: invalidate admitted flows after membership for %s was removed: %w", owner, err)
	}
	delete(s.snapshots, owner)
	return nil
}

func (s *MembershipStore) deleteKey(k MembershipKey) error {
	bpfKey := bpf.PodEgressSgMembershipKey{
		VpcId: k.VpcID,
		Ipv4:  k.IPv4,
	}
	if err := s.table.Delete(bpfKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// IPv4ToBE converts a net.IP (IPv4 only) to a uint32 whose bytes-on-disk
// match network byte order when serialised by the cilium/ebpf bpf2go
// uint32 marshaller. The naming mirrors convert.IPv4ToBPFNetworkOrder
// elsewhere in the daemon — both rely on the LE host invariant of the
// kernel, so we encode via LittleEndian. Returns ok=false for invalid
// or non-IPv4 inputs so callers can surface a clean error.
func IPv4ToBE(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.LittleEndian.Uint32(v4), true
}
