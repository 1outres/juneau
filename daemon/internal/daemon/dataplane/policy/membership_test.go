package policy

import (
	"errors"
	"testing"
)

const (
	testOwner      = "default/nic-a"
	testVpcID      = uint32(3)
	testIPv4       = uint32(0x0100000a)
	testOtherIPv4  = uint32(0x0200000a)
	testMemberedSG = uint32(11)
)

func newTestMembershipStore() (*MembershipStore, *fakeMembershipTable, *fakeBumper) {
	table := newFakeMembershipTable()
	bumper := &fakeBumper{}
	return newMembershipStore(table, bumper), table, bumper
}

func testMembershipKey(ipv4 uint32) MembershipKey {
	return MembershipKey{VpcID: testVpcID, IPv4: ipv4}
}

func TestMembershipApplyBumpsOnceForIdenticalEntries(t *testing.T) {
	store, table, bumper := newTestMembershipStore()
	key := testMembershipKey(testIPv4)
	val := MembershipValue{GroupIDs: []uint32{testMemberedSG}}

	for range 3 {
		if err := store.Apply(testOwner, key, val); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}

	if got := bumper.count(); got != 1 {
		t.Errorf("bumps = %d, want 1", got)
	}
	if table.updates != 3 {
		t.Errorf("updates = %d, want 3", table.updates)
	}
}

func TestMembershipApplyBumpsWhenTheGroupListChanges(t *testing.T) {
	store, _, bumper := newTestMembershipStore()
	key := testMembershipKey(testIPv4)

	if err := store.Apply(testOwner, key, MembershipValue{GroupIDs: []uint32{testMemberedSG}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := store.Apply(testOwner, key, MembershipValue{GroupIDs: []uint32{testMemberedSG, 12}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := store.Apply(testOwner, key, MembershipValue{GroupIDs: []uint32{12, testMemberedSG}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := bumper.count(); got != 3 {
		t.Errorf("bumps = %d, want 3", got)
	}
}

func TestMembershipApplyBumpsWhenTheAddressChanges(t *testing.T) {
	store, table, bumper := newTestMembershipStore()
	val := MembershipValue{GroupIDs: []uint32{testMemberedSG}}

	if err := store.Apply(testOwner, testMembershipKey(testIPv4), val); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := store.Apply(testOwner, testMembershipKey(testOtherIPv4), val); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := bumper.count(); got != 2 {
		t.Errorf("bumps = %d, want 2", got)
	}
	if table.has(testVpcID, testIPv4) {
		t.Error("the previous address must be removed from the table")
	}
	if !table.has(testVpcID, testOtherIPv4) {
		t.Error("the new address must be present in the table")
	}
}

func TestMembershipApplyIgnoresGroupsBeyondTheLimit(t *testing.T) {
	store, _, bumper := newTestMembershipStore()
	key := testMembershipKey(testIPv4)

	full := make([]uint32, 0, MaxSGsPerNIC+1)
	for i := range MaxSGsPerNIC + 1 {
		full = append(full, uint32(20+i))
	}
	trimmed := append(full[:MaxSGsPerNIC:MaxSGsPerNIC], 99)

	if err := store.Apply(testOwner, key, MembershipValue{GroupIDs: full}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := store.Apply(testOwner, key, MembershipValue{GroupIDs: trimmed}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := bumper.count(); got != 1 {
		t.Errorf("bumps = %d, want 1 (the installed prefix did not change)", got)
	}
}

func TestMembershipApplyWithoutGroupsDeletes(t *testing.T) {
	store, table, bumper := newTestMembershipStore()
	key := testMembershipKey(testIPv4)

	if err := store.Apply(testOwner, key, MembershipValue{GroupIDs: []uint32{testMemberedSG}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := store.Apply(testOwner, key, MembershipValue{}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if table.has(testVpcID, testIPv4) {
		t.Error("an empty group list must remove the entry")
	}
	if got := bumper.count(); got != 2 {
		t.Errorf("bumps = %d, want 2", got)
	}
}

func TestMembershipApplyRejectsAnIncompleteKey(t *testing.T) {
	store, table, bumper := newTestMembershipStore()

	if err := store.Apply(testOwner, MembershipKey{VpcID: testVpcID}, MembershipValue{GroupIDs: []uint32{testMemberedSG}}); err == nil {
		t.Fatal("Apply with ipv4=0 must fail")
	}
	if table.updates != 0 || bumper.count() != 0 {
		t.Errorf("updates = %d, bumps = %d, want 0 and 0", table.updates, bumper.count())
	}
}

func TestMembershipApplyRetriesTheBumpAfterFailure(t *testing.T) {
	store, _, bumper := newTestMembershipStore()
	key := testMembershipKey(testIPv4)
	val := MembershipValue{GroupIDs: []uint32{testMemberedSG}}

	want := errors.New("boom")
	bumper.err = want
	if err := store.Apply(testOwner, key, val); !errors.Is(err, want) {
		t.Fatalf("Apply error = %v, want %v", err, want)
	}

	bumper.err = nil
	if err := store.Apply(testOwner, key, val); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := bumper.count(); got != 1 {
		t.Errorf("bumps = %d, want 1", got)
	}
}

func TestMembershipApplyDoesNotBumpWhenTheWriteFails(t *testing.T) {
	store, table, bumper := newTestMembershipStore()
	want := errors.New("boom")
	table.updateErr = want

	err := store.Apply(testOwner, testMembershipKey(testIPv4), MembershipValue{GroupIDs: []uint32{testMemberedSG}})
	if !errors.Is(err, want) {
		t.Fatalf("Apply error = %v, want %v", err, want)
	}
	if got := bumper.count(); got != 0 {
		t.Errorf("bumps = %d, want 0", got)
	}
}

func TestMembershipDeleteBumpsOnlyWhenAnEntryExisted(t *testing.T) {
	store, _, bumper := newTestMembershipStore()

	if err := store.Delete(testOwner); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := bumper.count(); got != 0 {
		t.Errorf("bumps = %d, want 0 for an unknown owner", got)
	}

	if err := store.Apply(testOwner, testMembershipKey(testIPv4), MembershipValue{GroupIDs: []uint32{testMemberedSG}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := store.Delete(testOwner); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := bumper.count(); got != 2 {
		t.Errorf("bumps = %d, want 2", got)
	}

	if err := store.Delete(testOwner); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := bumper.count(); got != 2 {
		t.Errorf("bumps = %d, want 2 (the owner is already gone)", got)
	}
}
