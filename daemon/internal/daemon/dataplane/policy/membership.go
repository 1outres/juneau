package policy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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

// MembershipStore writes (vpc_id, ipv4) → SG list into sg_membership_map.
// It maintains its own snapshot so a NetworkInterface change can both
// apply the new entry and clean up the previous (vpc_id, ipv4) tuple
// when the Pod's IP changes.
type MembershipStore struct {
	m *ebpf.Map

	mu        sync.Mutex
	snapshots map[string]MembershipKey // owner key (e.g. NetworkInterface name) -> last-written key
}

func NewMembershipStore(m *ebpf.Map) *MembershipStore {
	return &MembershipStore{m: m, snapshots: make(map[string]MembershipKey)}
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
	if len(val.GroupIDs) > MaxSGsPerNIC {
		val.GroupIDs = val.GroupIDs[:MaxSGsPerNIC]
	}

	if len(val.GroupIDs) == 0 {
		return s.Delete(owner)
	}

	bpfKey := bpf.PodEgressSgMembershipKey{
		VpcId: key.VpcID,
		Ipv4:  key.IPv4,
	}
	bpfVal := bpf.PodEgressSgMembershipVal{
		Count: uint8(len(val.GroupIDs)),
	}
	copy(bpfVal.Sgs[:], val.GroupIDs)

	if err := s.m.Update(bpfKey, bpfVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write membership for %s: %w", owner, err)
	}

	s.mu.Lock()
	prev, hadPrev := s.snapshots[owner]
	s.snapshots[owner] = key
	s.mu.Unlock()

	if hadPrev && prev != key {
		if err := s.deleteKey(prev); err != nil {
			zap.S().Warnf("policy: clean up stale membership for %s: %v", owner, err)
		}
	}

	return nil
}

// Delete removes the membership entry that owner currently maps to.
// Idempotent.
func (s *MembershipStore) Delete(owner string) error {
	s.mu.Lock()
	prev, hadPrev := s.snapshots[owner]
	delete(s.snapshots, owner)
	s.mu.Unlock()
	if !hadPrev {
		return nil
	}
	return s.deleteKey(prev)
}

func (s *MembershipStore) deleteKey(k MembershipKey) error {
	bpfKey := bpf.PodEgressSgMembershipKey{
		VpcId: k.VpcID,
		Ipv4:  k.IPv4,
	}
	if err := s.m.Delete(bpfKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
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
