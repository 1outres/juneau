package serviceloadbalancer

import (
	"net"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
)

// newLBMaps allocates in-process HASH maps shaped like the real
// lb_service_map / lb_backend_map. Tests skip cleanly on hosts where
// the BPF userspace API is not available (e.g. unprivileged CI).
func newLBMaps(t *testing.T) (svc, backend *ebpf.Map) {
	t.Helper()
	svcMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(bpf.PodEgressLbServiceKey{})),
		ValueSize:  uint32(unsafe.Sizeof(bpf.PodEgressLbServiceVal{})),
		MaxEntries: 32,
	})
	if err != nil {
		t.Skipf("ebpf.NewMap unavailable on this host: %v", err)
	}
	t.Cleanup(func() { _ = svcMap.Close() })

	beMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(bpf.PodEgressLbBackendKey{})),
		ValueSize:  uint32(unsafe.Sizeof(bpf.PodEgressLbBackendVal{})),
		MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("ebpf.NewMap unavailable on this host: %v", err)
	}
	t.Cleanup(func() { _ = beMap.Close() })

	return svcMap, beMap
}

func vipBE(ip string) uint32 {
	v, err := convert.IPv4ToBPFNetworkOrder(net.ParseIP(ip))
	if err != nil {
		panic(err)
	}
	return v
}

func TestIPv4MapEncodingMatchesPacketMemory(t *testing.T) {
	got := vipBE("203.0.113.10")
	const want uint32 = 0x0a7100cb
	if got != want {
		t.Fatalf("VIP BPF encoding: want %#08x, got %#08x", want, got)
	}
}

func TestBPFProgrammer_WritesAndPrunes(t *testing.T) {
	svcMap, beMap := newLBMaps(t)
	if svcMap == nil {
		return
	}
	prog := NewBPFProgrammer(svcMap, beMap)

	desired := &LBService{
		Key: "app/web",
		VIP: net.ParseIP("203.0.113.10").To4(),
		Ports: []LBServicePort{
			{Port: 80, Protocol: corev1.ProtocolTCP, TargetPort: 8080},
		},
		Backends: []LBBackend{
			{
				PodIP:       net.ParseIP("10.99.0.1").To4(),
				ServicePort: 80,
				TargetPort:  8080,
				Protocol:    corev1.ProtocolTCP,
				SubnetID:    100,
			},
			{
				PodIP:       net.ParseIP("10.99.0.2").To4(),
				ServicePort: 80,
				TargetPort:  8080,
				Protocol:    corev1.ProtocolTCP,
				SubnetID:    100,
			},
		},
	}
	if err := prog.Apply(desired.Key, desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Verify lb_service_map content.
	var sval bpf.PodEgressLbServiceVal
	skey := bpf.PodEgressLbServiceKey{Vip: vipBE("203.0.113.10"), Port: 80, Proto: 6}
	if err := svcMap.Lookup(&skey, &sval); err != nil {
		t.Fatalf("Lookup service: %v", err)
	}
	if sval.BackendCount != 2 {
		t.Errorf("backend_count: want 2, got %d", sval.BackendCount)
	}

	// Verify both backends exist.
	for i := uint32(0); i < 2; i++ {
		bkey := bpf.PodEgressLbBackendKey{Vip: vipBE("203.0.113.10"), Port: 80, Proto: 6, Index: i}
		var bval bpf.PodEgressLbBackendVal
		if err := beMap.Lookup(&bkey, &bval); err != nil {
			t.Fatalf("Lookup backend %d: %v", i, err)
		}
		if bval.BackendSubnetId != 100 {
			t.Errorf("backend[%d] subnet: %d", i, bval.BackendSubnetId)
		}
	}

	// Shrink: re-apply with one backend; the second key must be pruned.
	shrunk := *desired
	shrunk.Backends = desired.Backends[:1]
	if err := prog.Apply(shrunk.Key, &shrunk); err != nil {
		t.Fatalf("Apply (shrunk): %v", err)
	}
	bkey := bpf.PodEgressLbBackendKey{Vip: vipBE("203.0.113.10"), Port: 80, Proto: 6, Index: 1}
	if err := beMap.Lookup(&bkey, &bpf.PodEgressLbBackendVal{}); err == nil {
		t.Errorf("backend index 1 must be deleted on shrink, got entry still present")
	}

	// Delete: must clear all entries for the key.
	if err := prog.Apply(shrunk.Key, nil); err != nil {
		t.Fatalf("Apply nil: %v", err)
	}
	if err := svcMap.Lookup(&skey, &sval); err == nil {
		t.Errorf("lb_service_map entry must be deleted on Apply(nil)")
	}
}

func TestBPFProgrammer_DropsBackendsWithoutMatchingPort(t *testing.T) {
	svcMap, beMap := newLBMaps(t)
	if svcMap == nil {
		return
	}
	prog := NewBPFProgrammer(svcMap, beMap)

	// One declared port (80/TCP) but a backend records a different
	// port — likely a controller bug. The Programmer must not emit a
	// backend entry under a port the Service doesn't declare.
	desired := &LBService{
		Key: "app/web",
		VIP: net.ParseIP("203.0.113.10").To4(),
		Ports: []LBServicePort{
			{Port: 80, Protocol: corev1.ProtocolTCP, TargetPort: 8080},
		},
		Backends: []LBBackend{
			{PodIP: net.ParseIP("10.99.0.1").To4(), ServicePort: 443, TargetPort: 8443, Protocol: corev1.ProtocolTCP, SubnetID: 100},
		},
	}
	if err := prog.Apply(desired.Key, desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	bkey := bpf.PodEgressLbBackendKey{Vip: vipBE("203.0.113.10"), Port: 443, Proto: 6, Index: 0}
	if err := beMap.Lookup(&bkey, &bpf.PodEgressLbBackendVal{}); err == nil {
		t.Errorf("backend with unrecognised port must be dropped, got entry present")
	}
}
