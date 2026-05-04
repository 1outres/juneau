package policy

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

// PeerResolver translates a user-facing peer reference (CIDR or SG name)
// into the {Kind, V4/PrefixLen | SG ID} the BPF rule consumes. Returning
// an error from a SG lookup signals "rule must be dropped"; the caller
// records that in the SG's RulesValid condition rather than failing the
// whole reconcile.
type PeerResolver interface {
	// ResolveSG returns the GroupID for a SecurityGroup name. ok=false
	// means the SG does not exist or has not yet been allocated a
	// GroupID.
	ResolveSG(name string) (groupID uint32, ok bool)
}

// MapPeerResolver is a trivial PeerResolver backed by a map[name]groupID.
// Suitable for tests and for the daemon-side reconciler that maintains
// the cache itself.
type MapPeerResolver map[string]uint32

func (m MapPeerResolver) ResolveSG(name string) (uint32, bool) {
	gid, ok := m[name]
	if !ok || gid == 0 {
		return 0, false
	}
	return gid, true
}

// ExpandSecurityGroup flattens a SecurityGroup CRD into a RuleSet. peer
// references that do not resolve are dropped silently; callers that
// need to surface them on status should pre-validate.
//
// GroupID and RulesetVersion are taken from sg.Status.
//
// The expanded rule order is stable: ingress rules first, in CRD order,
// then egress; within each rule, peers cycle outermost and ports
// innermost. Stable order keeps BPF map updates idempotent.
func ExpandSecurityGroup(sg *juneauv1alpha1.SecurityGroup, peers PeerResolver) (RuleSet, error) {
	rs := RuleSet{
		GroupID:        sg.Status.GroupID,
		RulesetVersion: sg.Status.RulesetVersion,
		HasEgressRules: sg.Spec.Egress != nil,
	}
	if rs.GroupID == 0 {
		return rs, fmt.Errorf("SecurityGroup %q has no GroupID yet", sg.Name)
	}

	for _, rule := range sg.Spec.Ingress {
		expanded, err := expandRule(DirIngress, rule.From, rule.Protocol, rule.Ports, peers)
		if err != nil {
			return rs, err
		}
		rs.IngressCount += len(expanded)
		rs.Rules = append(rs.Rules, expanded...)
	}
	if sg.Spec.Egress != nil {
		for _, rule := range *sg.Spec.Egress {
			expanded, err := expandRule(DirEgress, rule.To, rule.Protocol, rule.Ports, peers)
			if err != nil {
				return rs, err
			}
			rs.EgressCount += len(expanded)
			rs.Rules = append(rs.Rules, expanded...)
		}
	}
	return rs, nil
}

func expandRule(dir Direction, peerSpec []juneauv1alpha1.SecurityGroupPeer, proto juneauv1alpha1.SecurityGroupProtocol, ports []juneauv1alpha1.SecurityGroupPort, resolver PeerResolver) ([]Rule, error) {
	protoNum := protoToNum(proto)
	portRanges := portsToRanges(ports)

	var out []Rule
	for _, peer := range peerSpec {
		base, ok := buildPeer(peer, resolver)
		if !ok {
			continue
		}
		for _, pr := range portRanges {
			rule := base
			rule.Direction = dir
			rule.Proto = protoNum
			rule.PortLo = pr.lo
			rule.PortHi = pr.hi
			rule.Verdict = VerdictAllow
			out = append(out, rule)
		}
	}
	return out, nil
}

func protoToNum(p juneauv1alpha1.SecurityGroupProtocol) uint8 {
	switch p {
	case juneauv1alpha1.SecurityGroupProtocolTCP:
		return ProtoTCP
	case juneauv1alpha1.SecurityGroupProtocolUDP:
		return ProtoUDP
	case juneauv1alpha1.SecurityGroupProtocolICMP:
		return ProtoICMP
	default:
		return ProtoAny
	}
}

type portRange struct {
	lo uint16
	hi uint16
}

func portsToRanges(ports []juneauv1alpha1.SecurityGroupPort) []portRange {
	if len(ports) == 0 {
		return []portRange{{lo: PortAnyLo, hi: PortAnyHi}}
	}
	out := make([]portRange, 0, len(ports))
	for _, p := range ports {
		switch {
		case p.Port != nil:
			out = append(out, portRange{lo: uint16(*p.Port), hi: uint16(*p.Port)})
		case p.PortRange != nil:
			out = append(out, portRange{lo: uint16(p.PortRange.From), hi: uint16(p.PortRange.To)})
		}
	}
	return out
}

func buildPeer(peer juneauv1alpha1.SecurityGroupPeer, resolver PeerResolver) (Rule, bool) {
	switch {
	case peer.CIDR != "":
		prefix, err := netip.ParsePrefix(peer.CIDR)
		if err != nil || !prefix.Addr().Is4() {
			return Rule{}, false
		}
		// Encode CIDR base in network byte order. Mask the address
		// down to the prefix length so the BPF compare is stable
		// regardless of how the user wrote the CIDR.
		//
		// The cilium/ebpf bpf2go-generated map writers serialize uint32
		// fields in native byte order; to land bytes [a,b,c,d] (network
		// order) in memory on a little-endian host, we encode the
		// numeric value via LittleEndian. This mirrors what
		// convert.IPv4ToBPFNetworkOrder does for the rest of the
		// daemon and matches what BPF C reads as __be32.
		addr4 := prefix.Masked().Addr().As4()
		return Rule{
			PeerKind:      PeerKindCIDR,
			PeerV4:        binary.LittleEndian.Uint32(addr4[:]),
			PeerPrefixlen: uint8(prefix.Bits()),
		}, true
	case peer.SecurityGroupRef != nil:
		gid, ok := resolver.ResolveSG(peer.SecurityGroupRef.Name)
		if !ok {
			return Rule{}, false
		}
		return Rule{
			PeerKind: PeerKindSG,
			PeerV4:   gid,
		}, true
	}
	return Rule{}, false
}
