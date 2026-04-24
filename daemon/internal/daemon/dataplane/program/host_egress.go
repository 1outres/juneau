package program

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// HostEgress bundles the host-egress program's eBPF objects and its TC
// attachment to the host interface.
type HostEgress struct {
	Objs bpf.HostEgressObjects
	link link.Link
}

// NewHostEgress loads host-egress, writes the vxlan-ifindex constant and
// attaches the TC program to the host interface.
func NewHostEgress(pinPath string, hostIfindex int, vxlanIfindex int) (*HostEgress, error) {
	p := &HostEgress{}

	if err := bpf.LoadHostEgressObjects(&p.Objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		return nil, err
	}

	if err := p.Objs.VxlanIfindex.Update(uint32(0), uint32(vxlanIfindex), ebpf.UpdateAny); err != nil {
		return nil, err
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   p.Objs.TcHostEgress,
		Interface: hostIfindex,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, err
	}
	p.link = l

	return p, nil
}

func (p *HostEgress) Close() error {
	var errs []error
	if p.link != nil {
		if err := p.link.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := p.Objs.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
