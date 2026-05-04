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
	if rs.IngressCount != 4 {
		t.Errorf("ingress count = %d, want 4", rs.IngressCount)
	}
	if rs.EgressCount != 0 {
		t.Errorf("egress count = %d, want 0", rs.EgressCount)
	}
	if rs.HasEgressRules {
		t.Errorf("hasEgressRules should be false when spec.egress is nil")
	}

	// Sanity check: first rule is CIDR + port 80
	r0 := rs.Rules[0]
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
	for _, r := range rs.Rules {
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
	if rs.IngressCount != 1 {
		t.Errorf("ingress count = %d, want 1 (unresolved SG peer dropped)", rs.IngressCount)
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
	if rs.EgressCount != 0 {
		t.Errorf("egress count = %d, want 0", rs.EgressCount)
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
	if len(rs.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rs.Rules))
	}
	r := rs.Rules[0]
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
