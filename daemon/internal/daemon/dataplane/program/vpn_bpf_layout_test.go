package program_test

import (
	"testing"
	"unsafe"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

func TestVPNBPFMapLayout(t *testing.T) {
	spec, err := bpf.LoadPodEgress()
	if err != nil {
		t.Fatal(err)
	}
	gateway := spec.Maps["vpn_gateway"]
	if gateway == nil || gateway.KeySize != uint32(unsafe.Sizeof(bpf.PodEgressVpnGatewayKey{})) || gateway.ValueSize != uint32(unsafe.Sizeof(bpf.PodEgressVpnIdentity{})) {
		t.Fatalf("VPN gateway source map has wrong layout: %+v", gateway)
	}
	fib := spec.Maps["fib_inner"]
	if fib == nil || fib.ValueSize != uint32(unsafe.Sizeof(bpf.PodEgressFibVal{})) {
		t.Fatalf("VPN FIB next hop has wrong layout: %+v", fib)
	}
	if fib.ValueSize <= 24 {
		t.Fatal("FIB cannot hold gateway identity")
	}
}
