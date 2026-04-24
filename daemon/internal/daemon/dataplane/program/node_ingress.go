package program

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

// NodeIngress bundles the node-ingress program objects and its TC
// attachment to the node ingress interface.
type NodeIngress struct {
	Objs bpf.NodeIngressObjects
	link link.Link
}

func NewNodeIngress(pinPath string, nodeIngressIfindex int) (*NodeIngress, error) {
	p := &NodeIngress{}

	if err := bpf.LoadNodeIngressObjects(&p.Objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		return nil, err
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   p.Objs.TcNodeIngress,
		Interface: nodeIngressIfindex,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, err
	}
	p.link = l

	return p, nil
}

func (p *NodeIngress) Close() error {
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
