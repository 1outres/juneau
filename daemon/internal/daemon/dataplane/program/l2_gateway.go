package program

import (
	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// L2Gateway wraps the eBPF objects for the l2-gateway program. It runs
// at the egress of the veth juneau builds as the router port of an
// L2Network — the way out of the Vpc and into the segment — where it
// addresses a routed packet to the host that owns the destination and
// forwards it on the segment's own tables.
//
// The ingress of that same veth runs PodEgress, so everything the Vpc
// already does for a Subnet applies to the segment unchanged.
type L2Gateway struct {
	Objs bpf.L2GatewayObjects
}

// NewL2Gateway loads the l2-gateway program. Every map it touches is
// pinned by name and shared with the other programs, so pinPath must
// match what NewPodEgress uses.
func NewL2Gateway(pinPath string) (*L2Gateway, error) {
	p := &L2Gateway{}

	if err := bpf.LoadL2GatewayObjects(&p.Objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *L2Gateway) Close() error { return p.Objs.Close() }
