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

// NewPodEgress loads the pod-egress program and pins its maps under
// pinPath. nodeUnderlayBE is the node's underlay IPv4 in network byte
// order; it is written to the host_underlay map so handle_service can
// stamp host-network Service flows with the correct source IP.
func NewPodEgress(pinPath string, nodeUnderlayBE uint32) (*PodEgress, error) {
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

	if err := p.Objs.HostUnderlay.Update(uint32(0), nodeUnderlayBE, ebpf.UpdateAny); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *PodEgress) Close() error { return p.Objs.Close() }
