package program

import (
	"github.com/cilium/ebpf"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// PodIngress wraps the eBPF objects for the pod-ingress program. It is
// attached to the egress side of each Pod's host-side veth peer (i.e.
// the path packets take into the Pod), where it applies the reverse
// SNAT recorded in conntrack so Service responses carry the ClusterIP
// rather than the backend Pod IP.
type PodIngress struct {
	Objs bpf.PodIngressObjects
}

// NewPodIngress loads the pod-ingress program. It shares ct_map,
// subnet_map, and ifindex_subnet via PIN_BY_NAME with the other
// programs, so the pinPath must match what NewPodEgress uses.
func NewPodIngress(pinPath string) (*PodIngress, error) {
	p := &PodIngress{}
	if err := bpf.LoadPodIngressObjects(&p.Objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *PodIngress) Close() error { return p.Objs.Close() }
