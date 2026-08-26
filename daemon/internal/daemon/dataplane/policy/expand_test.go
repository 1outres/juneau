package policy

import (
	"encoding/binary"
	"net"
	"testing"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

func ptrInt32(v int32) *int32 { return &v }

func TestExpandSecurityGroup_PortsAndPeers(t *testing.T) {
	sg := &juneauv1alpha1.SecurityGroup{
		Status: juneauv1alpha1.SecurityGroupStatus{GroupID: 100, RulesetVersion: 3},
		Spec: juneauv1alpha1.SecurityGroupSpec{
			Vpc: "test",
			Ingress: []juneauv1alpha1.SecurityGroupIngressRule{{
				From: []juneauv1alpha1.SecurityGroupPeer{
					{CIDR: "10.0.0.0/8"},
					{SecurityGroupRef: &juneauv1alpha1.SecurityGroupPeerRef{Name: "client-sg"}},
				},
				Protocol: juneauv1alpha1.SecurityGroupProtocolTCP,
				Ports: []juneauv1alpha1.SecurityGroupPort{
					{Port: ptrInt32(80)},
					{PortRange: &juneauv1alpha1.SecurityGroupPortRange{From: 8000, To: 8009}},
				},
			}},
		},
	}

	resolver := MapPeerResolver{"client-sg": 200}
	rs, err := ExpandSecurityGroup(sg, resolver)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}

	// 2 peers × 2 ports = 4 ingress entries
	if len(rs.Ingress) != 4 {
		t.Errorf("ingress entries = %d, want 4", len(rs.Ingress))
	}
	if len(rs.Egress) != 0 {
		t.Errorf("egress entries = %d, want 0", len(rs.Egress))
	}
	if rs.HasEgressRules {
		t.Errorf("hasEgressRules should be false when spec.egress is nil")
	}

	// Sanity check: first rule is CIDR + port 80
	r0 := rs.Ingress[0]
	if r0.Direction != DirIngress || r0.Proto != ProtoTCP {
		t.Errorf("r0 direction/proto wrong: %+v", r0)
	}
	if r0.PeerKind != PeerKindCIDR || r0.PeerPrefixlen != 8 {
		t.Errorf("r0 peer kind/prefix wrong: %+v", r0)
	}
	expectedAddr := binary.LittleEndian.Uint32(net.IPv4(10, 0, 0, 0).To4())
	if r0.PeerV4 != expectedAddr {
		t.Errorf("r0 peer addr = %#x want %#x", r0.PeerV4, expectedAddr)
	}
	if r0.PortLo != 80 || r0.PortHi != 80 {
		t.Errorf("r0 port = %d-%d want 80-80", r0.PortLo, r0.PortHi)
	}

	// Find a rule with PeerKindSG; PeerV4 should be the GroupID.
	var sawSGPeer bool
	for _, r := range rs.Ingress {
		if r.PeerKind == PeerKindSG {
			sawSGPeer = true
			if r.PeerV4 != 200 {
				t.Errorf("SG peer rule PeerV4 = %d want 200", r.PeerV4)
			}
		}
	}
	if !sawSGPeer {
		t.Error("expected at least one SG-peer rule")
	}
}

func TestExpandSecurityGroup_DropsUnresolvedSGPeer(t *testing.T) {
	sg := &juneauv1alpha1.SecurityGroup{
		Status: juneauv1alpha1.SecurityGroupStatus{GroupID: 100},
		Spec: juneauv1alpha1.SecurityGroupSpec{
			Vpc: "test",
			Ingress: []juneauv1alpha1.SecurityGroupIngressRule{{
				From: []juneauv1alpha1.SecurityGroupPeer{
					{SecurityGroupRef: &juneauv1alpha1.SecurityGroupPeerRef{Name: "missing-sg"}},
					{CIDR: "192.168.0.0/16"},
				},
				Protocol: juneauv1alpha1.SecurityGroupProtocolTCP,
				Ports:    []juneauv1alpha1.SecurityGroupPort{{Port: ptrInt32(443)}},
			}},
		},
	}
	rs, err := ExpandSecurityGroup(sg, MapPeerResolver{})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(rs.Ingress) != 1 {
		t.Errorf("ingress entries = %d, want 1 (unresolved SG peer dropped)", len(rs.Ingress))
	}
}

func TestExpandSecurityGroup_EgressEmptyMeansAllowAll(t *testing.T) {
	emptyEgress := []juneauv1alpha1.SecurityGroupEgressRule{}
	sg := &juneauv1alpha1.SecurityGroup{
		Status: juneauv1alpha1.SecurityGroupStatus{GroupID: 1},
		Spec: juneauv1alpha1.SecurityGroupSpec{
			Vpc:    "test",
			Egress: &emptyEgress, // explicit non-nil empty: deny-all egress
		},
	}
	rs, err := ExpandSecurityGroup(sg, MapPeerResolver{})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if !rs.HasEgressRules {
		t.Error("HasEgressRules should be true when spec.egress is non-nil")
	}
	if len(rs.Egress) != 0 {
		t.Errorf("egress entries = %d, want 0", len(rs.Egress))
	}

	sg2 := &juneauv1alpha1.SecurityGroup{
		Status: juneauv1alpha1.SecurityGroupStatus{GroupID: 1},
		Spec:   juneauv1alpha1.SecurityGroupSpec{Vpc: "test"},
	}
	rs2, err := ExpandSecurityGroup(sg2, MapPeerResolver{})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if rs2.HasEgressRules {
		t.Error("HasEgressRules should be false when spec.egress is nil (default-allow)")
	}
}

func TestExpandSecurityGroup_NoGroupID(t *testing.T) {
	sg := &juneauv1alpha1.SecurityGroup{}
	if _, err := ExpandSecurityGroup(sg, MapPeerResolver{}); err == nil {
		t.Error("expected error when GroupID == 0")
	}
}

func TestExpandNetworkACL_PrioritySortAndPortExpansion(t *testing.T) {
	ingress := []juneauv1alpha1.NetworkACLRule{
		{
			Priority: 200,
			Action:   juneauv1alpha1.NetworkACLActionDeny,
			Protocol: juneauv1alpha1.NetworkACLProtocolAll,
			CIDR:     "192.0.2.0/24",
		},
		{
			Priority: 100,
			Action:   juneauv1alpha1.NetworkACLActionAllow,
			Protocol: juneauv1alpha1.NetworkACLProtocolTCP,
			CIDR:     "10.0.0.0/8",
			Ports: []juneauv1alpha1.NetworkACLPort{
				{Port: ptrInt32(80)},
				{PortRange: &juneauv1alpha1.NetworkACLPortRange{From: 8000, To: 8009}},
			},
		},
	}
	egress := []juneauv1alpha1.NetworkACLRule{
		{
			Priority: 50,
			Action:   juneauv1alpha1.NetworkACLActionAllow,
			Protocol: juneauv1alpha1.NetworkACLProtocolAll,
			CIDR:     "0.0.0.0/0",
		},
		{
			Priority: 10,
			Action:   juneauv1alpha1.NetworkACLActionDeny,
			Protocol: juneauv1alpha1.NetworkACLProtocolAll,
			CIDR:     "198.51.100.0/24",
		},
	}

	acl := &juneauv1alpha1.NetworkACL{
		Status: juneauv1alpha1.NetworkACLStatus{ACLID: 42, RulesetVersion: 7},
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
	if rs.GroupID != 42 || rs.RulesetVersion != 7 {
		t.Errorf("identifiers wrong: %+v", rs)
	}
	if !rs.HasIngressRules || !rs.HasEgressRules {
		t.Errorf("Has*Rules should be true when both directions are non-nil")
	}
	// Ingress: 1 (priority=200, port-any) + 2 (priority=100, two ports) = 3
	if len(rs.Ingress) != 3 {
		t.Errorf("ingress entries = %d, want 3", len(rs.Ingress))
	}
	if len(rs.Egress) != 2 {
		t.Errorf("egress entries = %d, want 2", len(rs.Egress))
	}

	// Each direction is sorted by priority asc on its own, so the
	// evaluator can scan that direction's window front-to-back.
	wantIngress := []uint16{100, 100, 200}
	for i, want := range wantIngress {
		if rs.Ingress[i].Direction != DirIngress || rs.Ingress[i].Priority != want {
			t.Errorf("ingress[%d] = %+v, want ingress priority %d", i, rs.Ingress[i], want)
		}
	}
	wantEgress := []uint16{10, 50}
	for i, want := range wantEgress {
		if rs.Egress[i].Direction != DirEgress || rs.Egress[i].Priority != want {
			t.Errorf("egress[%d] = %+v, want egress priority %d", i, rs.Egress[i], want)
		}
	}

	// Verdict mapping: deny rule (priority 200) carries VerdictDeny.
	if rs.Ingress[2].Verdict != VerdictDeny {
		t.Errorf("ingress[2] verdict = %d, want VerdictDeny", rs.Ingress[2].Verdict)
	}

	// CIDR encoding sanity: 10.0.0.0/8 is little-endian-encoded so the
	// in-memory bytes line up with the BPF __be32 view.
	expectedAddr := binary.LittleEndian.Uint32(net.IPv4(10, 0, 0, 0).To4())
	if rs.Ingress[0].PeerV4 != expectedAddr || rs.Ingress[0].PeerPrefixlen != 8 {
		t.Errorf("ingress[0] CIDR encoding wrong: %+v (expected %#x)", rs.Ingress[0], expectedAddr)
	}
}

func TestExpandNetworkACL_NilDirectionDefaults(t *testing.T) {
	acl := &juneauv1alpha1.NetworkACL{
		Status: juneauv1alpha1.NetworkACLStatus{ACLID: 7},
		Spec:   juneauv1alpha1.NetworkACLSpec{Vpc: "test"}, // both nil
	}
	rs, err := ExpandNetworkACL(acl)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if rs.HasIngressRules || rs.HasEgressRules {
		t.Errorf("Has*Rules must be false when both directions are nil: %+v", rs)
	}
	if len(rs.Ingress) != 0 || len(rs.Egress) != 0 {
		t.Errorf("expected zero rules, got %d ingress and %d egress", len(rs.Ingress), len(rs.Egress))
	}

	// Explicit empty list = deny-all (HasRules=true, count=0)
	emptyIngress := []juneauv1alpha1.NetworkACLRule{}
	acl2 := &juneauv1alpha1.NetworkACL{
		Status: juneauv1alpha1.NetworkACLStatus{ACLID: 8},
		Spec:   juneauv1alpha1.NetworkACLSpec{Vpc: "test", Ingress: &emptyIngress},
	}
	rs2, err := ExpandNetworkACL(acl2)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if !rs2.HasIngressRules {
		t.Error("HasIngressRules must be true when spec.ingress is explicitly []")
	}
}

func TestExpandNetworkACL_NoACLID(t *testing.T) {
	if _, err := ExpandNetworkACL(&juneauv1alpha1.NetworkACL{}); err == nil {
		t.Error("expected error when ACLID == 0")
	}
}

func TestExpandNetworkACL_InvalidCIDR(t *testing.T) {
	ingress := []juneauv1alpha1.NetworkACLRule{{
		Priority: 100,
		Action:   juneauv1alpha1.NetworkACLActionAllow,
		Protocol: juneauv1alpha1.NetworkACLProtocolAll,
		CIDR:     "not-a-cidr",
	}}
	acl := &juneauv1alpha1.NetworkACL{
		Status: juneauv1alpha1.NetworkACLStatus{ACLID: 1},
		Spec:   juneauv1alpha1.NetworkACLSpec{Vpc: "test", Ingress: &ingress},
	}
	if _, err := ExpandNetworkACL(acl); err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestExpandSecurityGroup_AnyPort(t *testing.T) {
	sg := &juneauv1alpha1.SecurityGroup{
		Status: juneauv1alpha1.SecurityGroupStatus{GroupID: 1},
		Spec: juneauv1alpha1.SecurityGroupSpec{
			Vpc: "test",
			Ingress: []juneauv1alpha1.SecurityGroupIngressRule{{
				From:     []juneauv1alpha1.SecurityGroupPeer{{CIDR: "0.0.0.0/0"}},
				Protocol: juneauv1alpha1.SecurityGroupProtocolAll,
			}},
		},
	}
	rs, err := ExpandSecurityGroup(sg, MapPeerResolver{})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(rs.Ingress) != 1 {
		t.Fatalf("got %d ingress entries, want 1", len(rs.Ingress))
	}
	r := rs.Ingress[0]
	if r.PortLo != 0 || r.PortHi != 0xFFFF {
		t.Errorf("port range = %d-%d want any", r.PortLo, r.PortHi)
	}
	if r.Proto != ProtoAny {
		t.Errorf("proto = %d want ProtoAny", r.Proto)
	}
	if r.PeerPrefixlen != 0 {
		t.Errorf("prefixlen = %d want 0 for /0", r.PeerPrefixlen)
	}
}
