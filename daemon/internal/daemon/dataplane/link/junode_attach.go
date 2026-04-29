package link

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// JuneauNodeAttacher attaches the PodEgress program at TCX ingress and
// the PodIngress program at TCX egress of the juneau_node iface so the
// host's pseudo-pod participates in the regular Pod data plane.
type JuneauNodeAttacher struct {
	egressLink  ebpflink.Link
	ingressLink ebpflink.Link
}

// AttachJuneauNode attaches both programs and returns a handle that the
// caller can Close on shutdown.
func AttachJuneauNode(podEgress *program.PodEgress, podIngress *program.PodIngress, ifindex int) (*JuneauNodeAttacher, error) {
	egressLink, err := attachTCX(podEgress.Objs.TcPodEgress, ifindex,
		ebpf.AttachTCXIngress, "pod-egress (juneau_node)")
	if err != nil {
		return nil, err
	}
	ingressLink, err := attachTCX(podIngress.Objs.TcPodIngress, ifindex,
		ebpf.AttachTCXEgress, "pod-ingress (juneau_node)")
	if err != nil {
		if egressLink != nil {
			_ = egressLink.Close()
		}
		return nil, err
	}
	return &JuneauNodeAttacher{egressLink: egressLink, ingressLink: ingressLink}, nil
}

// Close detaches the BPF programs from juneau_node.
func (a *JuneauNodeAttacher) Close() error {
	var errs []error
	if a.egressLink != nil {
		if err := a.egressLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close juneau_node pod-egress link: %w", err))
		}
	}
	if a.ingressLink != nil {
		if err := a.ingressLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close juneau_node pod-ingress link: %w", err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
