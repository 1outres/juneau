package program_test

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/l2"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// roundTripPinPath is where this test pins the maps of the objects it
// loads. It has to sit on bpffs and must not be the path a daemon on
// this host is using.
const roundTripPinPath = "/sys/fs/bpf/juneau-gateway-roundtrip"

// TestGatewayAnswersArpFromTheSegment drives the whole way in and out of
// a gateway port with the real programs, on the real hooks, in one run.
//
// A host on the segment broadcasts an ARP for the gateway address.
// l2_egress floods it, and the gateway's copy goes to the port's
// ingress rather than its egress — the one thing BPF_PROG_TEST_RUN
// cannot show, because a redirect it reports is never carried out.
// Here the copy is really delivered, so pod_egress runs on the gateway
// veth, answers for the address it owns, and sends the reply back out
// of the same veth. That lands on the veth's egress, where l2_gateway
// forwards it to the port the request came from.
//
// The proof is the frame arriving back at that port. Nothing else in
// the setup can put one there.
func TestGatewayAnswersArpFromTheSegment(t *testing.T) {
	bpftest.Require(t)
	bpftest.Netns(t)

	if err := os.RemoveAll(roundTripPinPath); err != nil {
		t.Fatalf("clear the pin path: %v", err)
	}
	if err := os.Mkdir(roundTripPinPath, 0o700); err != nil {
		t.Skipf("cannot pin under bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(roundTripPinPath) })

	podEgress, err := program.NewPodEgress(roundTripPinPath, 0)
	if err != nil {
		t.Fatalf("load pod_egress: %+v", err)
	}
	t.Cleanup(func() { _ = podEgress.Close() })

	l2Egress, err := program.NewL2Egress(roundTripPinPath)
	if err != nil {
		t.Fatalf("load l2_egress: %+v", err)
	}
	t.Cleanup(func() { _ = l2Egress.Close() })

	l2Gateway, err := program.NewL2Gateway(roundTripPinPath)
	if err != nil {
		t.Fatalf("load l2_gateway: %+v", err)
	}
	t.Cleanup(func() { _ = l2Gateway.Close() })

	fdb := l2.NewTable("fdb", l2Egress.Objs.L2Fdb, l2Egress.MapSpecs.L2FdbInner)
	bumLocal := l2.NewTable("bum-local", l2Egress.Objs.L2BumLocal, l2Egress.MapSpecs.L2BumLocalInner)
	bumRemote := l2.NewTable("bum-remote", l2Egress.Objs.L2BumRemote, l2Egress.MapSpecs.L2BumRemoteInner)
	arp := l2.NewTable("arp", l2Egress.Objs.L2Arp, l2Egress.MapSpecs.L2ArpInner)
	tables := []*l2.Table{fdb, bumLocal, bumRemote, arp}
	t.Cleanup(func() {
		for _, table := range tables {
			if err := table.CloseAll(); err != nil {
				t.Errorf("close the per-VNI tables: %v", err)
			}
		}
	})
	for _, table := range tables {
		if err := table.Ensure(testVNI); err != nil {
			t.Fatalf("build a per-VNI table: %v", err)
		}
	}

	host := bpftest.Dummy(t, "pod1")
	gateway := bpftest.Dummy(t, "l2gw")
	gatewayMAC := bpftest.MAC(0xfe)
	hostMAC := bpftest.MAC(1)

	if err := l2Egress.Objs.L2NetworkMap.Update(
		&bpf.PodEgressL2NetworkKey{Vni: testVNI},
		&bpf.PodEgressL2NetworkVal{VpcId: testVpcID},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("declare the L2Network: %v", err)
	}
	for _, device := range []bpftest.Device{host, gateway} {
		if err := l2Egress.Objs.L2Ifindex.Update(
			&bpf.PodEgressL2IfindexKey{Ifindex: uint32(device.Index)},
			&bpf.PodEgressL2IfindexVal{Vni: testVNI},
			ebpf.UpdateAny,
		); err != nil {
			t.Fatalf("name the segment behind %s: %v", device.Name, err)
		}
	}
	if err := bumLocal.AddMember(testVNI, uint32(host.Index)); err != nil {
		t.Fatalf("add the host to the local flood list: %v", err)
	}
	if err := bumLocal.Put(testVNI, uint32(gateway.Index), l2.PortFlagPresent|l2.PortFlagGateway); err != nil {
		t.Fatalf("add the gateway to the local flood list: %v", err)
	}
	if err := fdb.Put(testVNI, bpf.PodEgressL2FdbKey{Mac: macArray(t, gatewayMAC)},
		bpf.PodEgressL2FdbVal{Ifindex: uint32(gateway.Index), Flags: l2.FdbFlagGateway}); err != nil {
		t.Fatalf("write the forwarding entry of the gateway: %v", err)
	}
	if err := l2Egress.Objs.L2Gateway.Update(
		&bpf.PodEgressL2GatewayKey{Vni: testVNI},
		&bpf.PodEgressL2GatewayVal{Ifindex: uint32(gateway.Index), Mac: macArray(t, gatewayMAC)},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the gateway port of the segment: %v", err)
	}

	// What pod_egress needs of the gateway veth to treat it as the L3
	// boundary of the segment: the network behind the port, and the
	// address and MAC that port answers for.
	if err := podEgress.Objs.IfindexSubnet.Update(
		&bpf.PodEgressIfindexSubnetKey{Ifindex: uint32(gateway.Index)},
		&bpf.PodEgressIfindexSubnetVal{SubnetId: testVNI, Ipv4: networkOrderIPv4(t, gatewayAddress)},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the segment behind the gateway veth: %v", err)
	}
	if err := podEgress.Objs.SubnetMap.Update(
		&bpf.PodEgressSubnetKey{SubnetId: testVNI},
		&bpf.PodEgressSubnetVal{
			VpcId:  testVpcID,
			GwMac:  macArray(t, gatewayMAC),
			GwAddr: hostOrderIPv4(t, gatewayAddress),
			Mask:   0xffffff00,
		},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("describe the segment to pod_egress: %v", err)
	}

	ingress, err := ebpflink.AttachTCX(ebpflink.TCXOptions{
		Program:   podEgress.Objs.TcPodEgress,
		Interface: gateway.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		t.Fatalf("attach pod_egress to the gateway veth: %v", err)
	}
	t.Cleanup(func() { _ = ingress.Close() })

	egress, err := ebpflink.AttachTCX(ebpflink.TCXOptions{
		Program:   l2Gateway.Objs.TcL2Gateway,
		Interface: gateway.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		t.Fatalf("attach l2_gateway to the gateway veth: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })

	request := bpftest.Frame(t, bpftest.Broadcast, hostMAC, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, hostMAC, host2Address,
			net.HardwareAddr{0, 0, 0, 0, 0, 0}, gatewayAddress))

	watched := bpftest.WatchPorts(t, host)
	bpftest.Run(t, l2Egress.Objs.TcL2Egress, request, host)

	// The gateway's copy travels through the backlog, so the answer
	// lands a moment after the run returns.
	deadline := time.Now().Add(2 * time.Second)
	for watched.Delivered(t, host) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the gateway never answered the ARP for its own address")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if delivered := watched.Delivered(t, host); delivered != 1 {
		t.Errorf("the host was fed %d frames, want the one answer", delivered)
	}
}

// networkOrderIPv4 turns an address into the __be32 the policy stage
// compares against the addresses in a packet.
func networkOrderIPv4(t *testing.T, address string) uint32 {
	t.Helper()
	ip := net.ParseIP(address).To4()
	if ip == nil {
		t.Fatalf("%q is not an IPv4 address", address)
	}
	return binary.NativeEndian.Uint32(ip)
}
