package program

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// VxlanIngress bundles the vxlan-ingress program objects and its TC
// attachment to the vxlan interface.
type VxlanIngress struct {
	Objs bpf.VxlanIngressObjects
	link link.Link
}

func NewVxlanIngress(pinPath string, vxlanIfindex int) (*VxlanIngress, error) {
	p := &VxlanIngress{}

	if err := bpf.LoadVxlanIngressObjects(&p.Objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		return nil, err
	}

	// vxlan_ifindex is a pinned, shared map every program reads to
	// know which iface to redirect packets that need VXLAN encap to.
	// Owned by the program that manages the vxlan iface.
	if err := p.Objs.VxlanIfindex.Update(uint32(0), uint32(vxlanIfindex), ebpf.UpdateAny); err != nil {
		return nil, err
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   p.Objs.TcVxlanIngressEntry,
		Interface: vxlanIfindex,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, err
	}
	p.link = l

	return p, nil
}

func (p *VxlanIngress) Close() error {
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
