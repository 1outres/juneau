package program_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/l2"
)

// testVNI is the segment every L2 test builds. Any non-zero number
// works; a recognisable one makes a failed map dump easier to read.
const testVNI = 4242

// testVpcID is what the trace events of the segment are stamped with.
// The forwarding path never reads it.
const testVpcID = 7

// l2Segment is one L2Network as the data plane sees it: the tables it
// reads, and the devices that stand in for its ports.
type l2Segment struct {
	objs      *bpftest.Objects
	fdb       *l2.Table
	bumLocal  *l2.Table
	bumRemote *l2.Table
	arp       *l2.Table
}

// newL2Segment loads one generated object, builds the three per-VNI
// tables through the same code the daemon uses, and declares testVNI
// an L2Network.
func newL2Segment(t *testing.T, load func() (*ebpf.CollectionSpec, error)) *l2Segment {
	t.Helper()

	objs := bpftest.Load(t, load)
	seg := &l2Segment{
		objs:      objs,
		fdb:       l2.NewTable("fdb", objs.Map(t, "l2_fdb"), objs.MapSpec(t, "l2_fdb_inner")),
		bumLocal:  l2.NewTable("bum-local", objs.Map(t, "l2_bum_local"), objs.MapSpec(t, "l2_bum_local_inner")),
		bumRemote: l2.NewTable("bum-remote", objs.Map(t, "l2_bum_remote"), objs.MapSpec(t, "l2_bum_remote_inner")),
		arp:       l2.NewTable("arp", objs.Map(t, "l2_arp"), objs.MapSpec(t, "l2_arp_inner")),
	}
	t.Cleanup(func() {
		for _, table := range []*l2.Table{seg.fdb, seg.bumLocal, seg.bumRemote, seg.arp} {
			if err := table.CloseAll(); err != nil {
				t.Errorf("close the per-VNI tables: %v", err)
			}
		}
	})

	for _, table := range []*l2.Table{seg.fdb, seg.bumLocal, seg.bumRemote, seg.arp} {
		if err := table.Ensure(testVNI); err != nil {
			t.Fatalf("build a per-VNI table: %v", err)
		}
	}

	if err := objs.Map(t, "l2_network_map").Update(
		&bpf.PodEgressL2NetworkKey{Vni: testVNI},
		&bpf.PodEgressL2NetworkVal{VpcId: testVpcID},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("declare the L2Network: %v", err)
	}
	return seg
}

// addLocalPort makes a device a port of the segment: the data plane
// can look the segment up from it, and a flooded frame reaches it.
func (s *l2Segment) addLocalPort(t *testing.T, device bpftest.Device) {
	t.Helper()
	if err := s.objs.Map(t, "l2_ifindex").Update(
		&bpf.PodEgressL2IfindexKey{Ifindex: uint32(device.Index)},
		&bpf.PodEgressL2IfindexVal{Vni: testVNI},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the segment behind %s: %v", device.Name, err)
	}
	if err := s.bumLocal.AddMember(testVNI, uint32(device.Index)); err != nil {
		t.Fatalf("add %s to the local flood list: %v", device.Name, err)
	}
}

// addGatewayPort makes a device the gateway port of the segment: it is
// a local port like any other, plus the entries that say the router
// lives behind it — the flood-list flag that sends its copy to the
// port's ingress, the forwarding entry the daemon writes because a
// gateway sends no frame to learn it from, and the MAC the port signs
// with.
func (s *l2Segment) addGatewayPort(t *testing.T, device bpftest.Device, mac net.HardwareAddr) {
	t.Helper()
	if err := s.objs.Map(t, "l2_ifindex").Update(
		&bpf.PodEgressL2IfindexKey{Ifindex: uint32(device.Index)},
		&bpf.PodEgressL2IfindexVal{Vni: testVNI},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the segment behind %s: %v", device.Name, err)
	}
	if err := s.bumLocal.Put(testVNI, uint32(device.Index), l2.PortFlagPresent|l2.PortFlagGateway); err != nil {
		t.Fatalf("add %s to the local flood list: %v", device.Name, err)
	}
	if err := s.objs.Map(t, "l2_gateway").Update(
		&bpf.PodEgressL2GatewayKey{Vni: testVNI},
		&bpf.PodEgressL2GatewayVal{Ifindex: uint32(device.Index), Mac: macArray(t, mac)},
		ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the gateway port of the segment: %v", err)
	}
	s.withFdb(t, func(inner *ebpf.Map) {
		if err := inner.Update(
			&bpf.PodEgressL2FdbKey{Mac: macArray(t, mac)},
			&bpf.PodEgressL2FdbVal{Ifindex: uint32(device.Index), Flags: l2.FdbFlagGateway},
			ebpf.UpdateAny,
		); err != nil {
			t.Fatalf("write the forwarding entry of the gateway: %v", err)
		}
	})
}

// resolve records an address on the segment as the gateway would have
// snooped it out of an ARP frame.
func (s *l2Segment) resolve(t *testing.T, address string, mac net.HardwareAddr) {
	t.Helper()
	if err := s.arp.Put(testVNI, bpf.PodEgressL2ArpKey{Ipv4: hostOrderIPv4(t, address)},
		bpf.PodEgressL2ArpVal{Mac: macArray(t, mac)}); err != nil {
		t.Fatalf("record %s on the segment: %v", address, err)
	}
}

// resolved reads back what the segment knows about one address.
func (s *l2Segment) resolved(t *testing.T, address string) (net.HardwareAddr, bool) {
	t.Helper()
	var (
		val   bpf.PodEgressL2ArpVal
		found bool
	)
	s.arp.ForEachInner(func(vni uint32, inner *ebpf.Map) {
		if vni != testVNI {
			return
		}
		found = inner.Lookup(&bpf.PodEgressL2ArpKey{Ipv4: hostOrderIPv4(t, address)}, &val) == nil
	})
	if !found {
		return nil, false
	}
	return net.HardwareAddr(val.Mac[:]), true
}

// addRemoteNode puts a node's underlay address on the remote flood
// list, which is what makes a broadcast leave this host.
func (s *l2Segment) addRemoteNode(t *testing.T, address string) {
	t.Helper()
	if err := s.bumRemote.AddMember(testVNI, hostOrderIPv4(t, address)); err != nil {
		t.Fatalf("add %s to the remote flood list: %v", address, err)
	}
}

// useTunnelDevice tells the data plane which device carries frames to
// other nodes.
func (s *l2Segment) useTunnelDevice(t *testing.T, device bpftest.Device) {
	t.Helper()
	if err := s.objs.Map(t, "vxlan_ifindex").Update(
		uint32(0), uint32(device.Index), ebpf.UpdateAny,
	); err != nil {
		t.Fatalf("name the tunnel device: %v", err)
	}
}

// withFdb runs fn against the forwarding table of the segment. Table
// hands its inner maps out only while it holds its own lock, so the
// test reaches one the same way the aging sweep does.
func (s *l2Segment) withFdb(t *testing.T, fn func(inner *ebpf.Map)) {
	t.Helper()
	found := false
	s.fdb.ForEachInner(func(vni uint32, inner *ebpf.Map) {
		if vni != testVNI {
			return
		}
		found = true
		fn(inner)
	})
	if !found {
		t.Fatalf("the segment has no forwarding table for VNI %d", testVNI)
	}
}

// learn writes a forwarding entry by hand, standing in for a frame the
// data plane would have learned it from.
func (s *l2Segment) learn(t *testing.T, mac net.HardwareAddr, ifindex uint32, vtep string) {
	t.Helper()
	var vtepIP uint32
	if vtep != "" {
		vtepIP = hostOrderIPv4(t, vtep)
	}
	s.withFdb(t, func(inner *ebpf.Map) {
		if err := inner.Update(
			&bpf.PodEgressL2FdbKey{Mac: macArray(t, mac)},
			&bpf.PodEgressL2FdbVal{Ifindex: ifindex, VtepIp: vtepIP},
			ebpf.UpdateAny,
		); err != nil {
			t.Fatalf("write a forwarding entry: %v", err)
		}
	})
}

// lookup reads back what the segment knows about one MAC.
func (s *l2Segment) lookup(t *testing.T, mac net.HardwareAddr) (bpf.PodEgressL2FdbVal, bool) {
	t.Helper()
	var (
		val   bpf.PodEgressL2FdbVal
		found bool
	)
	s.withFdb(t, func(inner *ebpf.Map) {
		found = inner.Lookup(&bpf.PodEgressL2FdbKey{Mac: macArray(t, mac)}, &val) == nil
	})
	if !found {
		return bpf.PodEgressL2FdbVal{}, false
	}
	return val, true
}

func macArray(t *testing.T, mac net.HardwareAddr) [6]uint8 {
	t.Helper()
	if len(mac) != 6 {
		t.Fatalf("a MAC is 6 bytes, got %d", len(mac))
	}
	var out [6]uint8
	copy(out[:], mac)
	return out
}

// hostOrderIPv4 turns an address into the number the data plane hands
// to bpf_tunnel_key.remote_ipv4, which the kernel byte-swaps itself.
func hostOrderIPv4(t *testing.T, address string) uint32 {
	t.Helper()
	ip := net.ParseIP(address).To4()
	if ip == nil {
		t.Fatalf("%q is not an IPv4 address", address)
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
