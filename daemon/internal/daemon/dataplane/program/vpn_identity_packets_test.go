package program_test

import (
	"testing"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/cilium/ebpf"
)

type vpnPacketPath struct {
	t         *testing.T
	objs      *bpftest.Objects
	first     bpftest.Device
	second    bpftest.Device
	pod       bpftest.Device
	firstID   bpf.PodEgressVpnIdentity
	otherID   bpf.PodEgressVpnIdentity
	outbound  *ebpf.Map
	returnFib *ebpf.Map
}

func newVPNPacketPath(t *testing.T) *vpnPacketPath {
	t.Helper()
	bpftest.Require(t)
	bpftest.Netns(t)
	p := &vpnPacketPath{
		t:       t,
		objs:    bpftest.Load(t, bpf.LoadPodEgress),
		first:   bpftest.Dummy(t, "vpn-first"),
		second:  bpftest.Dummy(t, "vpn-second"),
		pod:     bpftest.Dummy(t, "ordinary-pod"),
		firstID: bpf.PodEgressVpnIdentity{Bytes: [16]byte{1}},
		otherID: bpf.PodEgressVpnIdentity{Bytes: [16]byte{2}},
	}
	gatewayMAC := [6]byte{2, 0, 0, 0, 0, 1}
	podMAC := [6]byte{2, 0, 0, 0, 0, 2}
	for _, iface := range []struct {
		device  bpftest.Device
		address string
	}{
		{p.first, "10.1.0.5"},
		{p.second, "10.1.0.6"},
		{p.pod, "10.1.0.7"},
	} {
		p.update("ifindex_subnet", &bpf.PodEgressIfindexSubnetKey{Ifindex: uint32(iface.device.Index)}, &bpf.PodEgressIfindexSubnetVal{SubnetId: 17, Ipv4: ipv4Raw(t, iface.address)})
	}
	p.update("vpn_gateway", &bpf.PodEgressVpnGatewayKey{Ifindex: uint32(p.first.Index)}, &p.firstID)
	p.update("vpn_gateway", &bpf.PodEgressVpnGatewayKey{Ifindex: uint32(p.second.Index)}, &p.otherID)
	p.update("subnet_map", &bpf.PodEgressSubnetKey{SubnetId: 17}, &bpf.PodEgressSubnetVal{TableId: 41, VpcId: 7, GwMac: gatewayMAC})
	p.update("subnet_map", &bpf.PodEgressSubnetKey{SubnetId: 18}, &bpf.PodEgressSubnetVal{TableId: 42, VpcId: 7, GwMac: gatewayMAC})
	p.update("arp_table", &bpf.PodEgressArpTableKey{SubnetId: 18, Ipaddr: ipv4Host(t, "10.2.0.7")}, &bpf.PodEgressArpTableVal{Mac: podMAC})
	p.update("fdb", &bpf.PodEgressFdbKey{SubnetId: 18, Mac: podMAC}, &bpf.PodEgressFdbVal{Ifindex: uint32(p.pod.Index)})
	p.outbound = p.newFib(41)
	p.returnFib = p.newFib(42)
	p.route(p.outbound, "10.2.0.0", 24, bpf.PodEgressFibVal{Type: 1, SubnetId: 18, Smac: gatewayMAC})
	p.route(p.returnFib, "", 0, bpf.PodEgressFibVal{Type: 12, VpnId: p.firstID})
	return p
}

func (p *vpnPacketPath) update(name string, key, value any) {
	p.t.Helper()
	if err := p.objs.Map(p.t, name).Update(key, value, ebpf.UpdateAny); err != nil {
		p.t.Fatalf("update %s: %v", name, err)
	}
}

func (p *vpnPacketPath) newFib(table uint32) *ebpf.Map {
	p.t.Helper()
	inner, err := ebpf.NewMap(p.objs.MapSpec(p.t, "fib_inner"))
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { _ = inner.Close() })
	p.update("fib_map", &table, uint32(inner.FD()))
	return inner
}

func (p *vpnPacketPath) route(table *ebpf.Map, prefix string, length uint32, route bpf.PodEgressFibVal) {
	p.t.Helper()
	key := bpf.PodEgressFibKey{Prefixlen: length}
	if length != 0 {
		key.Dst = ipv4Raw(p.t, prefix)
	}
	if err := table.Update(&key, &route, ebpf.UpdateAny); err != nil {
		p.t.Fatal(err)
	}
}

func (p *vpnPacketPath) expectPort(device bpftest.Device, source, destination string, port uint16, want int) {
	p.t.Helper()
	frame := bpftest.Frame(p.t, bpftest.MAC(1), bpftest.MAC(5), bpftest.EtherTypeIPv4,
		bpftest.TCPv4(p.t, source, destination, 45000, port))
	got := bpftest.Run(p.t, p.objs.Program(p.t, "tc_pod_egress"), frame, device)
	if got != want {
		p.t.Errorf("%s: %s -> %s:%d: verdict = %d, want %d", device.Name, source, destination, port, got, want)
	}
}

func (p *vpnPacketPath) expect(device bpftest.Device, source, destination string, want int) {
	p.t.Helper()
	p.expectPort(device, source, destination, 443, want)
}

func TestVPNMultipleIdentitiesInSameVpc(t *testing.T) {
	p := newVPNPacketPath(t)
	p.expect(p.first, "192.0.2.5", "10.2.0.7", bpftest.ActRedirect)
	p.expect(p.second, "192.0.2.5", "10.2.0.7", bpftest.ActShot)
	p.route(p.returnFib, "198.51.100.0", 24, bpf.PodEgressFibVal{Type: 12, VpnId: p.otherID})
	p.expect(p.second, "198.51.100.5", "10.2.0.7", bpftest.ActRedirect)
	p.expect(p.first, "198.51.100.5", "10.2.0.7", bpftest.ActShot)
	p.expect(p.first, "192.0.2.5", "10.2.0.7", bpftest.ActRedirect)
}

func TestVPNRejectsMoreSpecificReturnRouteAndTransit(t *testing.T) {
	p := newVPNPacketPath(t)
	p.expect(p.first, "192.0.2.5", "10.2.0.7", bpftest.ActRedirect)
	p.route(p.returnFib, "192.0.2.0", 24, bpf.PodEgressFibVal{Type: 3})
	p.expect(p.first, "192.0.2.5", "10.2.0.7", bpftest.ActShot)
	p.expect(p.first, "192.0.3.5", "10.2.0.7", bpftest.ActRedirect)
	p.route(p.outbound, "198.19.54.0", 24, bpf.PodEgressFibVal{Type: 12, VpnId: p.otherID})
	p.expect(p.first, "192.0.3.5", "198.19.54.1", bpftest.ActShot)
}

func TestVPNDoesNotAuthorizeOrdinaryPodSpoofing(t *testing.T) {
	p := newVPNPacketPath(t)
	p.expect(p.first, "192.0.2.5", "10.2.0.7", bpftest.ActRedirect)
	p.expect(p.pod, "192.0.2.5", "10.2.0.7", bpftest.ActShot)
	p.expect(p.pod, "10.1.0.7", "10.2.0.7", bpftest.ActRedirect)
}

func TestVPNIngressStillPassesNetworkACLAndSecurityGroup(t *testing.T) {
	p := newVPNPacketPath(t)
	p.expect(p.first, "192.0.2.5", "10.2.0.7", bpftest.ActRedirect)
	aclID := uint32(102)
	p.update("subnet_map", &bpf.PodEgressSubnetKey{SubnetId: 17}, &bpf.PodEgressSubnetVal{TableId: 41, VpcId: 7, GwMac: [6]byte{2, 0, 0, 0, 0, 1}, AclId: aclID})
	p.update("acl_meta_map", &aclID, &bpf.PodEgressAclMetaVal{EgressCount: 1, HasEgressRules: 1})
	aclRules, err := ebpf.NewMap(p.objs.MapSpec(t, "acl_rules_inner_proto"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aclRules.Close() })
	aclSlot := uint32(16)
	if err := aclRules.Update(&aclSlot, &bpf.PodEgressAclRule{Proto: 6, PortLo: 80, PortHi: 80, Direction: 1, Verdict: 1}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	p.update("acl_rule_table", &aclID, uint32(aclRules.FD()))
	p.expect(p.first, "192.0.2.6", "10.2.0.7", bpftest.ActShot)
	p.expectPort(p.first, "192.0.2.6", "10.2.0.7", 80, bpftest.ActRedirect)
	p.update("subnet_map", &bpf.PodEgressSubnetKey{SubnetId: 17}, &bpf.PodEgressSubnetVal{TableId: 41, VpcId: 7, GwMac: [6]byte{2, 0, 0, 0, 0, 1}})
	p.expect(p.first, "192.0.2.6", "10.2.0.7", bpftest.ActRedirect)
	sgID := uint32(101)
	p.update("sg_membership_map", &bpf.PodEgressSgMembershipKey{VpcId: 7, Ipv4: ipv4Raw(t, "192.0.2.7")}, &bpf.PodEgressSgMembershipVal{Count: 1, Sgs: [2]uint32{sgID}})
	p.update("sg_meta_map", &sgID, &bpf.PodEgressSgMetaVal{EgressCount: 1, HasEgressRules: 1})
	rules, err := ebpf.NewMap(p.objs.MapSpec(t, "sg_rules_inner_proto"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rules.Close() })
	index := uint32(8)
	if err := rules.Update(&index, &bpf.PodEgressSgRule{Proto: 6, PortLo: 80, PortHi: 80, Direction: 1, Verdict: 1}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	p.update("sg_rule_table", &sgID, uint32(rules.FD()))
	p.expect(p.first, "192.0.2.7", "10.2.0.7", bpftest.ActShot)
	p.expectPort(p.first, "192.0.2.7", "10.2.0.7", 80, bpftest.ActRedirect)
	p.expect(p.first, "192.0.2.8", "10.2.0.7", bpftest.ActRedirect)
}
