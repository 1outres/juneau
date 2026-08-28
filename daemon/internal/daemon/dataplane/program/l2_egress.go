package program

import (
	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// L2Egress wraps the eBPF objects for the l2-egress program. It runs
// at the ingress of the host side of a veth whose NIC joined an
// L2Network — the path frames take out of the workload — where it
// learns source MACs and forwards on the destination MAC alone.
//
// MapSpecs carries the inner-map layouts the per-VNI tables are minted
// from; dataplane/l2.Table needs them to build a table for a network.
type L2Egress struct {
	Objs     bpf.L2EgressObjects
	MapSpecs bpf.L2EgressMapSpecs
}

// NewL2Egress loads the l2-egress program. Every map it touches is
// pinned by name and shared with the other programs, so pinPath must
// match what NewPodEgress uses.
func NewL2Egress(pinPath string) (*L2Egress, error) {
	p := &L2Egress{}

	spec, err := bpf.LoadL2Egress()
	if err != nil {
		return nil, err
	}
	if err := spec.Assign(&p.MapSpecs); err != nil {
		return nil, err
	}

	if err := bpf.LoadL2EgressObjects(&p.Objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *L2Egress) Close() error { return p.Objs.Close() }
