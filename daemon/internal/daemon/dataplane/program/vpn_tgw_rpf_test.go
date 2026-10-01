package program_test

import (
	"net"
	"testing"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/cilium/ebpf"
)

func TestVPNTransitRequiresTargetReturnRouteToSameGateway(t *testing.T) {
	bpftest.Require(t)
	bpftest.Netns(t)
	source := bpftest.Dummy(t, "vpn-transit-source")
	sink := bpftest.Dummy(t, "vpn-transit-sink")
	obj := bpftest.Load(t, bpf.LoadPodEgress)
	update := func(name string, key, val any) {
		t.Helper()
		if err := obj.Map(t, name).Update(key, val, ebpf.UpdateAny); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	gwMAC := [6]byte{2, 0, 0, 0, 0, 1}
	podMAC := [6]byte{2, 0, 0, 0, 0, 2}
	identity := bpf.PodEgressVpnIdentity{Bytes: [16]byte{1, 2, 3}}
	update("ifindex_subnet", &bpf.PodEgressIfindexSubnetKey{Ifindex: uint32(source.Index)}, &bpf.PodEgressIfindexSubnetVal{SubnetId: 17, Ipv4: ipv4Raw(t, "10.1.0.5")})
	update("vpn_gateway", &bpf.PodEgressVpnGatewayKey{Ifindex: uint32(source.Index)}, &identity)
	update("subnet_map", &bpf.PodEgressSubnetKey{SubnetId: 17}, &bpf.PodEgressSubnetVal{TableId: 41, VpcId: 7, GwMac: gwMAC})
	update("subnet_map", &bpf.PodEgressSubnetKey{SubnetId: 18}, &bpf.PodEgressSubnetVal{TableId: 42, VpcId: 8, GwMac: gwMAC})
	update("arp_table", &bpf.PodEgressArpTableKey{SubnetId: 18, Ipaddr: ipv4Host(t, "10.2.0.7")}, &bpf.PodEgressArpTableVal{Mac: podMAC})
	update("fdb", &bpf.PodEgressFdbKey{SubnetId: 18, Mac: podMAC}, &bpf.PodEgressFdbVal{Ifindex: uint32(sink.Index)})
	newFib := func(name, inner string, id uint32) *ebpf.Map {
		t.Helper()
		m, err := ebpf.NewMap(obj.MapSpec(t, inner))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		update(name, &id, uint32(m.FD()))
		return m
	}
	srcFib := newFib("fib_map", "fib_inner", 41)
	dstFib := newFib("fib_map", "fib_inner", 42)
	srcTransit := newFib("tgw_fib_map", "tgw_fib_inner", 51)
	returnTransit := newFib("tgw_fib_map", "tgw_fib_inner", 52)
	set := func(m *ebpf.Map, key, val any) {
		t.Helper()
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	set(srcFib, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "10.2.0.0")}, &bpf.PodEgressFibVal{Type: 8, SubnetId: 51})
	set(srcTransit, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "10.2.0.0")}, &bpf.PodEgressFibVal{Type: 1, SubnetId: 18, Smac: gwMAC})
	set(dstFib, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 8, SubnetId: 52})
	set(returnTransit, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 12, SubnetId: 17, VpnId: identity, Smac: gwMAC, Dmac: [6]byte{2, 0, 0, 0, 0, 5}})
	frame := bpftest.Frame(t, net.HardwareAddr(gwMAC[:]), bpftest.MAC(5), bpftest.EtherTypeIPv4, bpftest.IPv4(t, "192.0.2.5", "10.2.0.7"))
	prog := obj.Program(t, "tc_pod_egress")
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActRedirect {
		t.Fatalf("valid return route = %d", got)
	}
	set(returnTransit, &bpf.PodEgressFibKey{Prefixlen: 0}, &bpf.PodEgressFibVal{Type: 12, SubnetId: 17, VpnId: identity})
	if err := returnTransit.Delete(&bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}); err != nil {
		t.Fatal(err)
	}
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActRedirect {
		t.Fatalf("default VPN return route = %d", got)
	}
	set(returnTransit, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 12, SubnetId: 17, VpnId: bpf.PodEgressVpnIdentity{Bytes: [16]byte{9}}})
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActShot {
		t.Fatalf("wrong VPN identity = %d", got)
	}
	set(returnTransit, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 12, SubnetId: 18, VpnId: identity})
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActShot {
		t.Fatalf("wrong gateway subnet = %d", got)
	}
	set(returnTransit, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 1, SubnetId: 17, VpnId: identity})
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActShot {
		t.Fatalf("other route type = %d", got)
	}
	set(srcTransit, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "10.2.0.0")}, &bpf.PodEgressFibVal{Type: 12, SubnetId: 18, VpnId: identity})
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActShot {
		t.Fatalf("other VPN transit = %d", got)
	}

	update("ifindex_subnet", &bpf.PodEgressIfindexSubnetKey{Ifindex: uint32(sink.Index)}, &bpf.PodEgressIfindexSubnetVal{SubnetId: 18, Ipv4: ipv4Raw(t, "10.2.0.7")})
	set(dstFib, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 8, SubnetId: 52})
	vpnMAC := [6]byte{2, 0, 0, 0, 0, 5}
	set(returnTransit, &bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 12, SubnetId: 17, VpnId: identity, Smac: gwMAC, Dmac: vpnMAC})
	update("fdb", &bpf.PodEgressFdbKey{SubnetId: 17, Mac: vpnMAC}, &bpf.PodEgressFdbVal{Ifindex: uint32(source.Index)})
	outbound := bpftest.Frame(t, net.HardwareAddr(gwMAC[:]), bpftest.MAC(6), bpftest.EtherTypeIPv4, bpftest.IPv4(t, "10.2.0.7", "192.0.2.5"))
	if got := bpftest.Run(t, prog, outbound, sink); got != bpftest.ActRedirect {
		t.Fatalf("other Vpc to VPN transit = %d", got)
	}
}
