package program_test

import (
	"encoding/binary"
	"net"
	"testing"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/cilium/ebpf"
)

func TestVPNIngressUsesDestinationSubnetLongestPrefixReturnRoute(t *testing.T) {
	bpftest.Require(t)
	bpftest.Netns(t)
	source := bpftest.Dummy(t, "vpn-source")
	sink := bpftest.Dummy(t, "vpn-target")
	obj := bpftest.Load(t, bpf.LoadPodEgress)
	update := func(name string, key, value any) {
		t.Helper()
		if err := obj.Map(t, name).Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	identity := bpf.PodEgressVpnIdentity{Bytes: [16]byte{1, 2, 3, 4}}
	update("ifindex_subnet", &bpf.PodEgressIfindexSubnetKey{Ifindex: uint32(source.Index)}, &bpf.PodEgressIfindexSubnetVal{SubnetId: 17, Ipv4: ipv4Raw(t, "10.1.0.5")})
	update("vpn_gateway", &bpf.PodEgressVpnGatewayKey{Ifindex: uint32(source.Index)}, &identity)
	gwMAC := [6]uint8{2, 0, 0, 0, 0, 1}
	podMAC := [6]uint8{2, 0, 0, 0, 0, 2}
	update("subnet_map", &bpf.PodEgressSubnetKey{SubnetId: 17}, &bpf.PodEgressSubnetVal{TableId: 41, VpcId: 7, GwMac: gwMAC})
	update("subnet_map", &bpf.PodEgressSubnetKey{SubnetId: 18}, &bpf.PodEgressSubnetVal{TableId: 42, VpcId: 7, GwMac: gwMAC})
	update("subnet_map", &bpf.PodEgressSubnetKey{SubnetId: 19}, &bpf.PodEgressSubnetVal{TableId: 43, VpcId: 8, GwMac: gwMAC})
	update("arp_table", &bpf.PodEgressArpTableKey{SubnetId: 18, Ipaddr: ipv4Host(t, "10.2.0.7")}, &bpf.PodEgressArpTableVal{Mac: podMAC})
	update("fdb", &bpf.PodEgressFdbKey{SubnetId: 18, Mac: podMAC}, &bpf.PodEgressFdbVal{Ifindex: uint32(sink.Index)})
	newFib := func(table uint32) *ebpf.Map {
		t.Helper()
		inner, err := ebpf.NewMap(obj.MapSpec(t, "fib_inner"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = inner.Close() })
		update("fib_map", &table, uint32(inner.FD()))
		return inner
	}
	srcFib := newFib(41)
	dstFib := newFib(42)
	if err := srcFib.Update(&bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "10.2.0.0")}, &bpf.PodEgressFibVal{Type: 1, SubnetId: 18, Smac: gwMAC}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := dstFib.Update(&bpf.PodEgressFibKey{Prefixlen: 0}, &bpf.PodEgressFibVal{Type: 12, VpnId: identity}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	frame := bpftest.Frame(t, net.HardwareAddr(gwMAC[:]), bpftest.MAC(5), bpftest.EtherTypeIPv4, bpftest.IPv4(t, "192.0.2.5", "10.2.0.7"))
	prog := obj.Program(t, "tc_pod_egress")
	if err := srcFib.Update(&bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "198.19.54.0")}, &bpf.PodEgressFibVal{Type: 12, VpnId: bpf.PodEgressVpnIdentity{Bytes: [16]byte{9}}}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	crossSite := bpftest.Frame(t, net.HardwareAddr(gwMAC[:]), bpftest.MAC(5), bpftest.EtherTypeIPv4, bpftest.IPv4(t, "192.0.2.5", "198.19.54.1"))
	if got := bpftest.Run(t, prog, crossSite, source); got != bpftest.ActShot {
		t.Fatalf("VPN-to-VPN transit verdict = %d", got)
	}
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActRedirect {
		t.Fatalf("default VPN return route verdict = %d", got)
	}
	if err := dstFib.Update(&bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 3}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActShot {
		t.Fatalf("more-specific non-VPN return route verdict = %d", got)
	}
	if err := dstFib.Update(&bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 12, VpnId: bpf.PodEgressVpnIdentity{Bytes: [16]byte{9}}}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActShot {
		t.Fatalf("other VPN return route verdict = %d", got)
	}
	peerFib := newFib(43)
	update("arp_table", &bpf.PodEgressArpTableKey{SubnetId: 19, Ipaddr: ipv4Host(t, "10.2.0.7")}, &bpf.PodEgressArpTableVal{Mac: podMAC})
	update("fdb", &bpf.PodEgressFdbKey{SubnetId: 19, Mac: podMAC}, &bpf.PodEgressFdbVal{Ifindex: uint32(sink.Index)})
	if err := srcFib.Update(&bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "10.2.0.0")}, &bpf.PodEgressFibVal{Type: 7, SubnetId: 19, Smac: gwMAC}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := peerFib.Update(&bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 13, SubnetId: 17, VpnId: identity}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActRedirect {
		t.Fatalf("direct peer VPN return verdict = %d", got)
	}
	if err := peerFib.Update(&bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 13, SubnetId: 18, VpnId: identity}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActShot {
		t.Fatalf("wrong gateway subnet verdict = %d", got)
	}
	if err := peerFib.Update(&bpf.PodEgressFibKey{Prefixlen: 24, Dst: ipv4Raw(t, "192.0.2.0")}, &bpf.PodEgressFibVal{Type: 12, SubnetId: 17, VpnId: identity}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActShot {
		t.Fatalf("peer without peering return verdict = %d", got)
	}
	if err := obj.Map(t, "vpn_gateway").Delete(&bpf.PodEgressVpnGatewayKey{Ifindex: uint32(source.Index)}); err != nil {
		t.Fatal(err)
	}
	if got := bpftest.Run(t, prog, frame, source); got != bpftest.ActShot {
		t.Fatalf("unready VPN gateway verdict = %d", got)
	}
}

func ipv4Raw(t *testing.T, s string) uint32 {
	t.Helper()
	ip := net.ParseIP(s).To4()
	if ip == nil {
		t.Fatalf("invalid IP %q", s)
	}
	return binary.NativeEndian.Uint32(ip)
}
func ipv4Host(t *testing.T, s string) uint32 {
	t.Helper()
	ip := net.ParseIP(s).To4()
	if ip == nil {
		t.Fatalf("invalid IP %q", s)
	}
	return binary.BigEndian.Uint32(ip)
}
