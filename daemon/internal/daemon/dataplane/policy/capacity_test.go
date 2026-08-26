package policy

import (
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// The per-direction limits and the compiled array sizes are two halves
// of one contract: a store writes egress at slot limit+i and the BPF
// evaluator reads it there. Asserting it against the object file is
// the only version of "keep these in lockstep" that cannot be
// forgotten. Reading the spec does not need root; only loading the
// program does.
func TestRuleWindowsMatchTheCompiledMapSizes(t *testing.T) {
	spec, err := bpf.LoadPodEgress()
	if err != nil {
		t.Fatalf("load pod_egress spec: %v", err)
	}

	for _, tc := range []struct {
		mapName      string
		perDirection int
	}{
		{mapName: "acl_rules_inner_proto", perDirection: juneauv1alpha1.NetworkACLMaxEntriesPerDirection},
		{mapName: "sg_rules_inner_proto", perDirection: juneauv1alpha1.SecurityGroupMaxEntriesPerDirection},
	} {
		t.Run(tc.mapName, func(t *testing.T) {
			m, ok := spec.Maps[tc.mapName]
			if !ok {
				t.Fatalf("map %q is not in the pod_egress spec", tc.mapName)
			}
			if want := uint32(2 * tc.perDirection); m.MaxEntries != want {
				t.Errorf("%s max_entries = %d, want %d (two windows of %d)", tc.mapName, m.MaxEntries, want, tc.perDirection)
			}
		})
	}
}

func TestStoreLimitsMatchTheAPIContract(t *testing.T) {
	if MaxACLEntriesPerDirection != juneauv1alpha1.NetworkACLMaxEntriesPerDirection {
		t.Errorf("MaxACLEntriesPerDirection = %d, want %d", MaxACLEntriesPerDirection, juneauv1alpha1.NetworkACLMaxEntriesPerDirection)
	}
	if MaxSGEntriesPerDirection != juneauv1alpha1.SecurityGroupMaxEntriesPerDirection {
		t.Errorf("MaxSGEntriesPerDirection = %d, want %d", MaxSGEntriesPerDirection, juneauv1alpha1.SecurityGroupMaxEntriesPerDirection)
	}
}

// Capacity is spent on expanded entries, not on the rules the user
// wrote, so a single rule with a long port list can fill a window on
// its own.
func TestACLStoreApplyFailsClosedWhenOneRuleExpandsPastTheWindow(t *testing.T) {
	const aclID uint32 = 42
	overflow := MaxACLEntriesPerDirection + 1

	ports := make([]juneauv1alpha1.NetworkACLPort, 0, overflow)
	for i := range overflow {
		ports = append(ports, juneauv1alpha1.NetworkACLPort{Port: ptrInt32(int32(8000 + i))})
	}
	ingress := []juneauv1alpha1.NetworkACLRule{{
		Priority: 100,
		Action:   juneauv1alpha1.NetworkACLActionAllow,
		Protocol: juneauv1alpha1.NetworkACLProtocolTCP,
		CIDR:     "10.0.0.0/8",
		Ports:    ports,
	}}
	egress := []juneauv1alpha1.NetworkACLRule{{
		Priority: 50,
		Action:   juneauv1alpha1.NetworkACLActionAllow,
		Protocol: juneauv1alpha1.NetworkACLProtocolAll,
		CIDR:     "0.0.0.0/0",
	}}
	acl := &juneauv1alpha1.NetworkACL{
		Status: juneauv1alpha1.NetworkACLStatus{ACLID: aclID},
		Spec: juneauv1alpha1.NetworkACLSpec{
			Vpc:     "test",
			Ingress: &ingress,
			Egress:  &egress,
		},
	}

	rs, err := ExpandNetworkACL(acl)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(rs.Ingress) != overflow {
		t.Fatalf("expanded ingress entries = %d, want %d (one entry per port)", len(rs.Ingress), overflow)
	}

	table := &fakeRuleTable{}
	meta := newFakeMetaTable()
	store := newACLStore(table, meta, &fakeBumper{})

	wantCapacityErrors(t, store.Apply(rs), CapacityError{
		Layer:     aclLayer,
		ID:        aclID,
		Direction: DirIngress,
		Entries:   overflow,
		Limit:     MaxACLEntriesPerDirection,
	})

	if got := len(table.inner.slots); got != 1 {
		t.Errorf("installed slots = %d, want 1 (only the egress rule fits)", got)
	}
	if _, ok := table.inner.slots[uint32(MaxACLEntriesPerDirection)]; !ok {
		t.Errorf("egress rule missing from slot %d", MaxACLEntriesPerDirection)
	}

	value, ok := meta.values[aclID]
	if !ok {
		t.Fatalf("no meta published for acl %d", aclID)
	}
	m := value.(bpf.PodEgressAclMetaVal)
	if m.IngressCount != 0 || m.HasIngressRules != 1 {
		t.Errorf("ingress meta = count %d flag %d, want count 0 flag 1", m.IngressCount, m.HasIngressRules)
	}
	if m.EgressCount != 1 || m.HasEgressRules != 1 {
		t.Errorf("egress meta = count %d flag %d, want count 1 flag 1", m.EgressCount, m.HasEgressRules)
	}
}
