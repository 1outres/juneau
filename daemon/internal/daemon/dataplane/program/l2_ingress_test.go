package program_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

// The addresses a ClusterIP flow out of the segment involves.
const (
	serviceAddress = "10.96.0.10"
	backendAddress = "10.61.0.7"
	servicePort    = 80
	backendPort    = 8080
	clientPort     = 40000
)

// testACLID is the NetworkACL these tests attach to the segment.
const testACLID = 3

// l2IngressPorts is the last stop before a frame reaches a workload on
// the segment: the workload's own veth, with the gateway of the segment
// declared so the program can tell which frames crossed the boundary.
type l2IngressPorts struct {
	segment    *l2Segment
	program    *ebpf.Program
	pod        bpftest.Device
	podMAC     net.HardwareAddr
	gateway    bpftest.Device
	gatewayMAC net.HardwareAddr
}

func newL2IngressPorts(t *testing.T) *l2IngressPorts {
	t.Helper()
	bpftest.Require(t)
	bpftest.Netns(t)

	segment := newL2Segment(t, bpf.LoadL2Ingress)
	ports := &l2IngressPorts{
		segment:    segment,
		program:    segment.objs.Program(t, "tc_l2_ingress"),
		pod:        bpftest.Dummy(t, "pod1"),
		podMAC:     bpftest.MAC(2),
		gateway:    bpftest.Dummy(t, "l2gw"),
		gatewayMAC: bpftest.MAC(0xfe),
	}
	segment.addLocalPort(t, ports.pod)
	segment.addGatewayPort(t, ports.gateway, ports.gatewayMAC)
	return ports
}

// denyInbound attaches an ACL that admits nothing on the way in and
// leaves the way out in default-allow.
//
// A direction with has_*_rules set and no rule that matches falls to a
// terminal deny, so an empty ingress window is the whole of "deny
// everything inbound".
func (p *l2IngressPorts) denyInbound(t *testing.T) {
	t.Helper()
	if err := p.segment.objs.Map(t, "acl_meta_map").Update(
		uint32(testACLID),
		&bpf.PodEgressAclMetaVal{HasIngressRules: 1},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("declare the ACL: %v", err)
	}
	p.segment.standUpGateway(t, p.gateway, p.gatewayMAC, 0, testACLID)
}

// installServiceReverse records what pod_egress installs on the gateway
// veth when it DNATs a ClusterIP: the reverse entry that turns the
// backend's address back into the Service's on the way home.
func (p *l2IngressPorts) installServiceReverse(t *testing.T, client string) {
	t.Helper()
	installServiceReverseInto(t, p.segment.objs.Map(t, "ct_map"), client)
}

func installServiceReverseInto(t *testing.T, ctMap *ebpf.Map, client string) {
	t.Helper()
	err := ctMap.Update(
		&bpf.PodEgressCtKey{
			Scope: testVpcID,
			Saddr: networkOrderIPv4(t, backendAddress),
			Daddr: networkOrderIPv4(t, client),
			Sport: bigEndianPort(backendPort),
			Dport: bigEndianPort(clientPort),
			Proto: 6,
		},
		&bpf.PodEgressCtVal{
			NewSaddr: networkOrderIPv4(t, serviceAddress),
			NewDaddr: networkOrderIPv4(t, client),
			NewSport: bigEndianPort(servicePort),
			NewDport: bigEndianPort(clientPort),
			Action:   2, // CT_ACTION_SNAT
		},
		ebpf.UpdateAny,
	)
	if err != nil {
		t.Fatalf("record the reverse entry of the Service flow: %v", err)
	}
}

// bigEndianPort is a port as the data plane stores it: a __be16 read
// back through a Go uint16.
func bigEndianPort(port uint16) uint16 { return port<<8 | port>>8 }

// gatewayFrame is a frame the gateway put on the segment: signed with
// the gateway's MAC, addressed to the workload.
func (p *l2IngressPorts) gatewayFrame(t *testing.T, source, destination string, sport, dport uint16) []byte {
	t.Helper()
	return bpftest.Frame(t, p.podMAC, p.gatewayMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, source, destination, sport, dport))
}

// segmentFrame is a frame one workload sent another. Nothing about it
// crossed the boundary of the Vpc.
func (p *l2IngressPorts) segmentFrame(t *testing.T, source, destination string, sport, dport uint16) []byte {
	t.Helper()
	return bpftest.Frame(t, p.podMAC, bpftest.MAC(3), bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, source, destination, sport, dport))
}

// The reply of a Service flow has to reach the workload carrying the
// address it wrote to. This is the hook that puts it back, because it
// is the one that always runs on the node the flow was opened from —
// the gateway port runs wherever the reply happened to be routed.
func TestL2IngressPutsTheServiceAddressBackOnAReply(t *testing.T) {
	ports := newL2IngressPorts(t)
	ports.installServiceReverse(t, host2Address)

	frame := ports.gatewayFrame(t, backendAddress, host2Address, backendPort, clientPort)
	verdict, out := bpftest.RunFrame(t, ports.program, frame, ports.pod)

	if verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the frame delivered (%d)", verdict, bpftest.ActOK)
	}
	if got := bpftest.SourceAddress(t, out); got != serviceAddress {
		t.Errorf("the reply reached the workload from %s, want the Service address %s", got, serviceAddress)
	}
	if got := bpftest.SourcePort(t, out); got != servicePort {
		t.Errorf("the reply reached the workload from port %d, want %d", got, servicePort)
	}
}

// A frame that never left the segment is not the gateway's, whatever
// conntrack happens to hold. Reading an address out of it would be the
// end of "juneau does not interpret L3 on an L2Network".
func TestL2IngressLeavesAFrameFromTheSegmentAlone(t *testing.T) {
	ports := newL2IngressPorts(t)
	ports.installServiceReverse(t, host2Address)

	frame := ports.segmentFrame(t, backendAddress, host2Address, backendPort, clientPort)
	verdict, out := bpftest.RunFrame(t, ports.program, frame, ports.pod)

	if verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the frame delivered (%d)", verdict, bpftest.ActOK)
	}
	if got := bpftest.SourceAddress(t, out); got != backendAddress {
		t.Errorf("a frame from the segment was rewritten to %s", got)
	}
}

// Nothing to undo is not a reason to drop. A packet the Vpc simply
// routed in has no reverse entry behind it.
func TestL2IngressLeavesAGatewayFrameWithNoConntrackAlone(t *testing.T) {
	ports := newL2IngressPorts(t)

	frame := ports.gatewayFrame(t, backendAddress, host2Address, backendPort, clientPort)
	verdict, out := bpftest.RunFrame(t, ports.program, frame, ports.pod)

	if verdict != bpftest.ActOK {
		t.Fatalf("verdict %d, want the frame delivered (%d)", verdict, bpftest.ActOK)
	}
	if got := bpftest.SourceAddress(t, out); got != backendAddress {
		t.Errorf("the packet reached the workload from %s, want the %s it arrived with", got, backendAddress)
	}
}

// A frame the gateway put on the segment with nothing recorded about it
// is a flow the Vpc is opening, and the ingress rules decide it.
//
// This is the shape the bug had: the same frame, on a node that holds
// no record of the flow. Judged there it was a fresh flow and the deny
// fired; judged here it is either fresh for real, or the flow's own
// record is present because this is the node that wrote it.
func TestL2IngressDropsWhatTheIngressRulesRefuse(t *testing.T) {
	ports := newL2IngressPorts(t)
	ports.denyInbound(t)

	frame := ports.gatewayFrame(t, outsideAddress, host2Address, clientPort, servicePort)
	if verdict := bpftest.Run(t, ports.program, frame, ports.pod); verdict != bpftest.ActShot {
		t.Errorf("verdict %d, want a drop (%d)", verdict, bpftest.ActShot)
	}
}

// The same ACL says nothing about a frame that stayed on the segment.
// An L2Network is a segment the user builds, and a rule written for the
// boundary must not start dropping frames between two NICs on it.
func TestL2IngressIgnoresTheACLForAFrameFromTheSegment(t *testing.T) {
	ports := newL2IngressPorts(t)
	ports.denyInbound(t)

	frame := ports.segmentFrame(t, host3Address, host2Address, clientPort, servicePort)
	if verdict := bpftest.Run(t, ports.program, frame, ports.pod); verdict != bpftest.ActOK {
		t.Errorf("verdict %d, want the frame delivered (%d)", verdict, bpftest.ActOK)
	}
}

// A segment with no gateway has no boundary to police, so nothing on it
// is ever judged.
func TestL2IngressIgnoresTheACLWhenNoGatewayIsDeclared(t *testing.T) {
	ports := newL2IngressPorts(t)
	ports.denyInbound(t)
	if err := ports.segment.objs.Map(t, "l2_gateway").Delete(
		&bpf.PodEgressL2GatewayKey{Vni: testVNI},
	); err != nil {
		t.Fatalf("take the gateway of the segment away: %v", err)
	}

	frame := ports.gatewayFrame(t, outsideAddress, host2Address, clientPort, servicePort)
	if verdict := bpftest.Run(t, ports.program, frame, ports.pod); verdict != bpftest.ActOK {
		t.Errorf("verdict %d, want the frame delivered (%d)", verdict, bpftest.ActOK)
	}
}

// Nothing on the segment carries an address for juneau to read unless
// the gateway signed it, so a non-IPv4 frame is delivered whatever the
// ACL says. An L2Network exists to carry them.
func TestL2IngressCarriesAnyEtherTypeThroughTheBoundary(t *testing.T) {
	ports := newL2IngressPorts(t)
	ports.denyInbound(t)

	frame := bpftest.Frame(t, ports.podMAC, ports.gatewayMAC, bpftest.EtherTypeIPv6, nil)
	if verdict := bpftest.Run(t, ports.program, frame, ports.pod); verdict != bpftest.ActOK {
		t.Errorf("verdict %d, want the frame delivered (%d)", verdict, bpftest.ActOK)
	}
}
