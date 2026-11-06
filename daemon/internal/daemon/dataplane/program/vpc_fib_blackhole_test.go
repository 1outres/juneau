package program_test

import (
	"testing"

	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/bpftest"
)

// Destinations of the two routes these tests install: one the route
// table drops and one it hands to an endpoint.
const (
	blackholeAddress = "10.77.0.5"
	endpointAddress  = "10.78.0.5"
	blackholeType    = 9 // FIB_ROUTE_TYPE_BLACKHOLE
	endpointType     = 2 // FIB_ROUTE_TYPE_ENDPOINT
)

// installBlackholeAndEndpointRoutes writes the route table the segment
// follows: 10.77.0.0/16 is a blackhole and 10.78.0.0/16 leads to the
// router endpoint. Only the endpoint is reachable, so a redirect proves the
// packet got as far as the route table.
func installBlackholeAndEndpointRoutes(t *testing.T, port *gatewayPort, router bpftest.Device) {
	t.Helper()

	inner, err := ebpf.NewMap(port.podEgress.MapSpecs.FibInner.Copy())
	if err != nil {
		t.Fatalf("build the route table: %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	if err := port.podEgress.Objs.FibMap.Update(uint32(serviceTableID), uint32(inner.FD()), ebpf.UpdateAny); err != nil {
		t.Fatalf("install the route table: %v", err)
	}

	routerMAC := bpftest.MAC(0x30)
	routes := []struct {
		dst string
		val bpf.PodEgressFibVal
	}{
		{"10.77.0.0", bpf.PodEgressFibVal{Type: blackholeType}},
		{"10.78.0.0", bpf.PodEgressFibVal{
			Type:     endpointType,
			Dmac:     macArray(t, routerMAC),
			Smac:     macArray(t, port.gatewayMAC),
			SubnetId: backendVNI,
		}},
	}
	for _, route := range routes {
		key := bpf.PodEgressFibKey{Prefixlen: 16, Dst: networkOrderIPv4(t, route.dst)}
		if err := inner.Update(&key, &route.val, ebpf.UpdateAny); err != nil {
			t.Fatalf("write the route to %s/16: %v", route.dst, err)
		}
	}

	if err := port.podEgress.Objs.Fdb.Update(
		&bpf.PodEgressFdbKey{SubnetId: backendVNI, Mac: macArray(t, routerMAC)},
		&bpf.PodEgressFdbVal{Ifindex: uint32(router.Index)},
		ebpf.UpdateAny); err != nil {
		t.Fatalf("record the port of the router: %v", err)
	}
}

// A RouteTable route whose endpoint is gone is installed as a blackhole,
// and so is a route the user asked to drop. pod_egress has no branch of
// its own for that type in a Vpc route table; the packet has to be
// dropped all the same.
func TestPodEgressDropsTrafficForABlackholeRoute(t *testing.T) {
	port := newGatewayPort(t)
	router := bpftest.Dummy(t, "router")
	installBlackholeAndEndpointRoutes(t, port, router)

	toEndpoint := bpftest.Frame(t, port.gatewayMAC, port.hostMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, host2Address, endpointAddress, clientPort, servicePort))
	if verdict := bpftest.Run(t, port.podEgress.Objs.TcPodEgress, toEndpoint, port.gateway); verdict != bpftest.ActRedirect {
		t.Fatalf("the packet for the endpoint route got verdict %d, want a redirect (%d)", verdict, bpftest.ActRedirect)
	}

	toBlackhole := bpftest.Frame(t, port.gatewayMAC, port.hostMAC, bpftest.EtherTypeIPv4,
		bpftest.TCPv4(t, host2Address, blackholeAddress, clientPort, servicePort))
	if verdict := bpftest.Run(t, port.podEgress.Objs.TcPodEgress, toBlackhole, port.gateway); verdict != bpftest.ActShot {
		t.Errorf("the packet for the blackhole route got verdict %d, want it dropped (%d)", verdict, bpftest.ActShot)
	}
}
