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

// roundTripPinPath is where these tests pin the maps of the objects
// they load. It has to sit on bpffs and must not be the path a daemon
// on this host is using.
const roundTripPinPath = "/sys/fs/bpf/juneau-gateway-roundtrip"

// backendVNI is the Subnet the ClusterIP backend sits on, and
// serviceTableID names the route table the segment follows.
const (
	backendVNI     = 4243
	serviceTableID = 5
)

// gatewayPort is one L2Network gateway veth carrying the two programs
// the daemon attaches to it, in a network namespace of the test's own.
//
// Both hooks are real. The ingress runs pod_egress, which is the way out
// of the segment, and the egress runs l2_gateway, which is the way in.
// Everything is loaded under one pin path, so the maps are one kernel
// object the way they are on a node. That is what these tests are for:
// the halves only meet through the maps, and a test that gave each of
// them its own copy would agree with itself and with nothing else.
type gatewayPort struct {
	podEgress  *program.PodEgress
	l2Egress   *program.L2Egress
	l2Gateway  *program.L2Gateway
	fdb        *l2.Table
	arp        *l2.Table
	host       bpftest.Device
	hostMAC    net.HardwareAddr
	gateway    bpftest.Device
	gatewayMAC net.HardwareAddr
}

func newGatewayPort(t *testing.T) *gatewayPort {
	t.Helper()
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

	port := &gatewayPort{
		podEgress:  podEgress,
		l2Egress:   l2Egress,
		l2Gateway:  l2Gateway,
		fdb:        l2.NewTable("fdb", l2Egress.Objs.L2Fdb, l2Egress.MapSpecs.L2FdbInner),
		arp:        l2.NewTable("arp", l2Egress.Objs.L2Arp, l2Egress.MapSpecs.L2ArpInner),
		host:       bpftest.Dummy(t, "pod1"),
		hostMAC:    bpftest.MAC(1),
		gateway:    bpftest.Dummy(t, "l2gw"),
		gatewayMAC: bpftest.MAC(0xfe),
	}
	bumLocal := l2.NewTable("bum-local", l2Egress.Objs.L2BumLocal, l2Egress.MapSpecs.L2BumLocalInner)
	bumRemote := l2.NewTable("bum-remote", l2Egress.Objs.L2BumRemote, l2Egress.MapSpecs.L2BumRemoteInner)
	tables := []*l2.Table{port.fdb, port.arp, bumLocal, bumRemote}
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

	if err := l2Egress.Objs.L2NetworkMap.Update(
		&bpf.PodEgressL2NetworkKey{Vni: testVNI},
		&bpf.PodEgressL2NetworkVal{VpcId: testVpcID},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("declare the L2Network: %v", err)
	}
	for _, device := range []bpftest.Device{port.host, port.gateway} {
		if err := l2Egress.Objs.L2Ifindex.Update(
			&bpf.PodEgressL2IfindexKey{Ifindex: uint32(device.Index)},
			&bpf.PodEgressL2IfindexVal{Vni: testVNI},
			ebpf.UpdateAny,
		); err != nil {
			t.Fatalf("name the segment behind %s: %v", device.Name, err)
		}
	}
	if err := bumLocal.AddMember(testVNI, uint32(port.host.Index)); err != nil {
		t.Fatalf("add the host to the local flood list: %v", err)
	}
	if err := bumLocal.Put(testVNI, uint32(port.gateway.Index), l2.PortFlagPresent|l2.PortFlagGateway); err != nil {
		t.Fatalf("add the gateway to the local flood list: %v", err)
	}
	if err := port.fdb.Put(testVNI, bpf.PodEgressL2FdbKey{Mac: macArray(t, port.gatewayMAC)},
		bpf.PodEgressL2FdbVal{Ifindex: uint32(port.gateway.Index), Flags: l2.FdbFlagGateway}); err != nil {
		t.Fatalf("write the forwarding entry of the gateway: %v", err)
	}
	if err := l2Egress.Objs.L2Gateway.Update(
		&bpf.PodEgressL2GatewayKey{Vni: testVNI},
		&bpf.PodEgressL2GatewayVal{Ifindex: uint32(port.gateway.Index), Mac: macArray(t, port.gatewayMAC)},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the gateway port of the segment: %v", err)
	}

	// What pod_egress needs of the gateway veth to treat it as the L3
	// boundary of the segment: the network behind the port, and the
	// address and MAC that port answers for.
	if err := podEgress.Objs.IfindexSubnet.Update(
		&bpf.PodEgressIfindexSubnetKey{Ifindex: uint32(port.gateway.Index)},
		&bpf.PodEgressIfindexSubnetVal{SubnetId: testVNI, Ipv4: networkOrderIPv4(t, gatewayAddress)},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the segment behind the gateway veth: %v", err)
	}
	if err := podEgress.Objs.SubnetMap.Update(
		&bpf.PodEgressSubnetKey{SubnetId: testVNI},
		&bpf.PodEgressSubnetVal{
			TableId: serviceTableID,
			VpcId:   testVpcID,
			GwMac:   macArray(t, port.gatewayMAC),
			GwAddr:  hostOrderIPv4(t, gatewayAddress),
			Mask:    0xffffff00,
		},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("describe the segment to pod_egress: %v", err)
	}

	ingress, err := ebpflink.AttachTCX(ebpflink.TCXOptions{
		Program:   podEgress.Objs.TcPodEgress,
		Interface: port.gateway.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		t.Fatalf("attach pod_egress to the gateway veth: %v", err)
	}
	t.Cleanup(func() { _ = ingress.Close() })

	egress, err := ebpflink.AttachTCX(ebpflink.TCXOptions{
		Program:   l2Gateway.Objs.TcL2Gateway,
		Interface: port.gateway.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		t.Fatalf("attach l2_gateway to the gateway veth: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })

	return port
}

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
	port := newGatewayPort(t)

	request := bpftest.Frame(t, bpftest.Broadcast, port.hostMAC, bpftest.EtherTypeARP,
		bpftest.ARP(t, bpftest.ARPRequest, port.hostMAC, host2Address,
			net.HardwareAddr{0, 0, 0, 0, 0, 0}, gatewayAddress))

	watched := bpftest.WatchPorts(t, port.host)
	bpftest.Run(t, port.l2Egress.Objs.TcL2Egress, request, port.host)

	// The gateway's copy travels through the backlog, so the answer
	// lands a moment after the run returns.
	port.awaitDelivery(t, watched, port.host, "the gateway never answered the ARP for its own address")
	if delivered := watched.Delivered(t, port.host); delivered != 1 {
		t.Errorf("the host was fed %d frames, want the one answer", delivered)
	}
}

// TestGatewayCarriesAClusterIPFlowBothWays is the reason the gateway is
// a veth port and not a branch of its own: a workload on an L2Network
// reaches a Service the same way a Pod on a Subnet does.
//
// The way out runs pod_egress on the gateway veth, which is where the
// frame lands after l2_egress hands it to the port's ingress. It finds
// the Service route, picks the backend, rewrites the destination and
// records how to undo that.
//
// The way home is the half that was missing. Reverse NAT for a Subnet
// happens in pod_ingress on the veth of the Pod that asked, and an
// L2Network NIC carries no pod_ingress, so l2_gateway has to undo the
// rewrite as the reply crosses the port. The two halves only meet in
// ct_map, which is why they are driven in one test: the entry pod_egress
// writes has to be the entry l2_gateway reads, under a scope the two
// take from different maps.
func TestGatewayCarriesAClusterIPFlowBothWays(t *testing.T) {
	port := newGatewayPort(t)
	backend := bpftest.Dummy(t, "backend")
	backendMAC := bpftest.MAC(7)
	port.declareService(t, backend, backendMAC)
	port.arpFor(t, host2Address, port.hostMAC)
	port.learn(t, port.hostMAC, port.host)

	// The way out: a SYN to the ClusterIP, as it reaches the gateway's
	// ingress. Only the backend is reachable from here, so a redirect
	// says pod_egress resolved the Service and placed the packet.
	request := bpftest.Frame(t, port.gatewayMAC, port.hostMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, host2Address, serviceAddress, clientPort, servicePort))
	if verdict := bpftest.Run(t, port.podEgress.Objs.TcPodEgress, request, port.gateway); verdict != bpftest.ActRedirect {
		t.Fatalf("the Service request got verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}

	// The way home: the backend answers the address it was reached on.
	reply := bpftest.Frame(t, port.gatewayMAC, backendMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, backendAddress, host2Address, backendPort, clientPort))
	verdict, out := bpftest.RunFrame(t, port.l2Gateway.Objs.TcL2Gateway, reply, port.gateway)

	if verdict != bpftest.ActRedirect {
		t.Fatalf("verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}
	if got := bpftest.SourceAddress(t, out); got != serviceAddress {
		t.Errorf("the reply left with source %s, want the Service address %s the workload wrote to", got, serviceAddress)
	}
	if got := bpftest.SourcePort(t, out); got != servicePort {
		t.Errorf("the reply left with source port %d, want %d", got, servicePort)
	}
}

// declareService puts a ClusterIP with one Pod backend in front of the
// segment, and the routes that lead to both.
func (p *gatewayPort) declareService(t *testing.T, backend bpftest.Device, backendMAC net.HardwareAddr) {
	t.Helper()

	inner, err := ebpf.NewMap(p.podEgress.MapSpecs.FibInner.Copy())
	if err != nil {
		t.Fatalf("build the route table: %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	if err := p.podEgress.Objs.FibMap.Update(uint32(serviceTableID), uint32(inner.FD()), ebpf.UpdateAny); err != nil {
		t.Fatalf("install the route table: %v", err)
	}

	routes := []struct {
		dst string
		val bpf.PodEgressFibVal
	}{
		{serviceAddress, bpf.PodEgressFibVal{Type: 4}}, // FIB_ROUTE_TYPE_SERVICE
		{backendAddress, bpf.PodEgressFibVal{
			Type:     1, // FIB_ROUTE_TYPE_CONNECTED
			Smac:     macArray(t, p.gatewayMAC),
			SubnetId: backendVNI,
		}},
	}
	for _, route := range routes {
		key := bpf.PodEgressFibKey{Prefixlen: 32, Dst: networkOrderIPv4(t, route.dst)}
		if err := inner.Update(&key, &route.val, ebpf.UpdateAny); err != nil {
			t.Fatalf("write the route to %s: %v", route.dst, err)
		}
	}

	serviceKey := bpf.PodEgressServiceKey{
		ClusterIp: hostOrderIPv4(t, serviceAddress),
		Port:      servicePort,
		Proto:     6,
	}
	if err := p.podEgress.Objs.ServiceMap.Update(&serviceKey,
		&bpf.PodEgressServiceVal{OwnerVpcId: testVpcID, BackendCount: 1},
		ebpf.UpdateAny); err != nil {
		t.Fatalf("declare the Service: %v", err)
	}
	if err := p.podEgress.Objs.BackendMap.Update(
		&bpf.PodEgressBackendKey{
			ClusterIp: serviceKey.ClusterIp,
			Port:      serviceKey.Port,
			Proto:     serviceKey.Proto,
		},
		&bpf.PodEgressBackendVal{
			BackendIp:       hostOrderIPv4(t, backendAddress),
			BackendPort:     backendPort,
			BackendSubnetId: backendVNI,
		},
		ebpf.UpdateAny); err != nil {
		t.Fatalf("declare the backend: %v", err)
	}

	// What the Subnet side of the boundary needs to place the packet on
	// the backend's port once it has been rewritten.
	if err := p.podEgress.Objs.ArpTable.Update(
		&bpf.PodEgressArpTableKey{SubnetId: backendVNI, Ipaddr: hostOrderIPv4(t, backendAddress)},
		&bpf.PodEgressArpTableVal{Mac: macArray(t, backendMAC)},
		ebpf.UpdateAny); err != nil {
		t.Fatalf("record the address of the backend: %v", err)
	}
	if err := p.podEgress.Objs.Fdb.Update(
		&bpf.PodEgressFdbKey{SubnetId: backendVNI, Mac: macArray(t, backendMAC)},
		&bpf.PodEgressFdbVal{Ifindex: uint32(backend.Index)},
		ebpf.UpdateAny); err != nil {
		t.Fatalf("record the port of the backend: %v", err)
	}
}

// arpFor records what the gateway would have snooped off the segment.
func (p *gatewayPort) arpFor(t *testing.T, address string, mac net.HardwareAddr) {
	t.Helper()
	if err := p.arp.Put(testVNI, bpf.PodEgressL2ArpKey{Ipv4: hostOrderIPv4(t, address)},
		bpf.PodEgressL2ArpVal{Mac: macArray(t, mac)}); err != nil {
		t.Fatalf("record %s on the segment: %v", address, err)
	}
}

// learn records where a MAC on the segment lives.
func (p *gatewayPort) learn(t *testing.T, mac net.HardwareAddr, device bpftest.Device) {
	t.Helper()
	if err := p.fdb.Put(testVNI, bpf.PodEgressL2FdbKey{Mac: macArray(t, mac)},
		bpf.PodEgressL2FdbVal{Ifindex: uint32(device.Index)}); err != nil {
		t.Fatalf("record %s on %s: %v", mac, device.Name, err)
	}
}

// awaitDelivery waits for a frame to reach a device. A frame handed to
// an ingress travels through the backlog, so it lands a moment after
// the run that sent it returns.
func (p *gatewayPort) awaitDelivery(t *testing.T, watched *bpftest.Ports, device bpftest.Device, missing string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for watched.Delivered(t, device) == 0 {
		if time.Now().After(deadline) {
			t.Fatal(missing)
		}
		time.Sleep(10 * time.Millisecond)
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
