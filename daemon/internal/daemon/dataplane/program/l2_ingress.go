package program

import (
	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// L2Ingress wraps the eBPF objects for the l2-ingress program. It runs
// at the egress of the host side of a veth whose NIC joined an
// L2Network — the last stop before the frame reaches the workload —
// and records the delivery for the trace timeline.
type L2Ingress struct {
	Objs bpf.L2IngressObjects
}

// NewL2Ingress loads the l2-ingress program. It shares l2_ifindex and
// l2_network_map with the other programs by pin name, so pinPath must
// match what NewPodEgress uses.
func NewL2Ingress(pinPath string) (*L2Ingress, error) {
	p := &L2Ingress{}
	if err := bpf.LoadL2IngressObjects(&p.Objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *L2Ingress) Close() error { return p.Objs.Close() }
