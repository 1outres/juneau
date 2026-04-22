package program

import (
	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// PodEgress bundles the eBPF objects and map specs for the pod-egress
// program. It is loaded once at startup; per-pod TC attachments live in the
// link package.
type PodEgress struct {
	Objs     bpf.PodEgressObjects
	MapSpecs bpf.PodEgressMapSpecs
}

// NewPodEgress loads the pod-egress program, pins its maps under pinPath,
// and writes the host-interface constant used by the program.
func NewPodEgress(pinPath string, hostIfindex int, hostMac [6]uint8) (*PodEgress, error) {
	p := &PodEgress{}

	spec, err := bpf.LoadPodEgress()
	if err != nil {
		return nil, err
	}
	if err := spec.Assign(&p.MapSpecs); err != nil {
		return nil, err
	}

	if err := bpf.LoadPodEgressObjects(&p.Objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		return nil, err
	}

	if err := p.Objs.HostIface.Update(uint32(0), &bpf.PodEgressHostIfaceVal{
		Ifindex: uint32(hostIfindex),
		Mac:     hostMac,
	}, ebpf.UpdateAny); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *PodEgress) Close() error { return p.Objs.Close() }
