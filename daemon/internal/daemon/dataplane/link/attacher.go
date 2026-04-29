package link

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/bootstrap"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// PodAttacher attaches the PodEgress and PodIngress TC programs to each
// local pod interface and detaches them when the endpoint is deleted or
// migrates off this node.
//
// PodEgress runs at the host-side veth peer's ingress (packets leaving
// the Pod) and applies forward DNAT for Service flows. PodIngress runs
// at the egress (packets entering the Pod) and applies the reverse SNAT
// recorded in conntrack so Service responses carry the original
// ClusterIP.
//
// Unlike map reconcilers, PodAttacher owns file descriptors (ebpflink.Link
// handles) rather than eBPF map entries. It still implements the
// runner.Reconciler contract so the workqueue machinery can drive it.
type PodAttacher struct {
	client     client.Client
	podEgress  *program.PodEgress
	podIngress *program.PodIngress
	nodeName   string

	mu        sync.Mutex
	snapshots map[string]attacherSnapshot
}

type attacherSnapshot struct {
	ifindex     int
	egressLink  ebpflink.Link // nil if pre-attached by another owner
	ingressLink ebpflink.Link
}

func NewPodAttacher(cl client.Client, podEgress *program.PodEgress, podIngress *program.PodIngress, nodeName string) *PodAttacher {
	return &PodAttacher{
		client:     cl,
		podEgress:  podEgress,
		podIngress: podIngress,
		nodeName:   nodeName,
		snapshots:  make(map[string]attacherSnapshot),
	}
}

func (p *PodAttacher) Name() string { return "pod-attacher" }

func (p *PodAttacher) Reconcile(ctx context.Context, key string) error {
	namespace, name, err := toolscache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	var nwep juneauv1alpha1.NetworkEndpoint
	err = p.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &nwep)
	if apierrors.IsNotFound(err) {
		return p.detach(key)
	}
	if err != nil {
		return err
	}

	if nwep.Spec.NodeName != p.nodeName {
		return p.detach(key)
	}
	return p.attach(key, nwep.Spec.Ifindex)
}

// CloseAll detaches every tracked link. Used by Manager on shutdown.
func (p *PodAttacher) CloseAll() error {
	p.mu.Lock()
	snaps := p.snapshots
	p.snapshots = make(map[string]attacherSnapshot)
	p.mu.Unlock()

	var errs []error
	for _, snap := range snaps {
		errs = append(errs, p.closeSnapshot(snap)...)
	}
	return errors.Join(errs...)
}

func (p *PodAttacher) attach(key string, ifindex int) error {
	p.mu.Lock()
	old, hadOld := p.snapshots[key]
	p.mu.Unlock()

	if hadOld && old.ifindex == ifindex {
		return nil
	}

	if hadOld {
		if errs := p.closeSnapshot(old); len(errs) > 0 {
			return errors.Join(errs...)
		}
	}

	// Loosen rp_filter / set accept_local on the Pod's host-side veth
	// before pod_egress starts running. handle_service_host_local hands
	// the rewritten packet to the kernel on this veth with src=PodIP,
	// but PodIP is only reverse-routable via juneau_node_h — a strict
	// per-iface rp_filter would drop it at ip_rcv_finish
	// (LINUX_MIB_IPRPFILTER). The kernel evaluates max(all, iface), so
	// the global "all" scope is set in ConfigureSysctl; this per-iface
	// setting is what survives if a reload bumps `all` back to strict.
	if iface, err := net.InterfaceByIndex(ifindex); err == nil {
		if err := bootstrap.ConfigureLooseRPFilter(iface.Name); err != nil {
			zap.S().Warnf("configure rp_filter on %s: %v", iface.Name, err)
		}
	} else {
		zap.S().Warnf("lookup ifname for ifindex %d: %v", ifindex, err)
	}

	egressLink, err := attachTCX(p.podEgress.Objs.TcPodEgress, ifindex,
		ebpf.AttachTCXIngress, "pod-egress")
	if err != nil {
		return err
	}

	ingressLink, err := attachTCX(p.podIngress.Objs.TcPodIngress, ifindex,
		ebpf.AttachTCXEgress, "pod-ingress")
	if err != nil {
		// Roll back the egress attach to keep the data plane symmetric.
		if egressLink != nil {
			_ = egressLink.Close()
		}
		return err
	}

	p.mu.Lock()
	p.snapshots[key] = attacherSnapshot{
		ifindex:     ifindex,
		egressLink:  egressLink,
		ingressLink: ingressLink,
	}
	p.mu.Unlock()
	return nil
}

// attachTCX attaches a single program at the given direction. Returns
// (nil, nil) if the program was already attached by another owner so
// the caller can record an empty link without re-rolling back.
func attachTCX(prog *ebpf.Program, ifindex int, attach ebpf.AttachType, label string) (ebpflink.Link, error) {
	l, err := ebpflink.AttachTCX(ebpflink.TCXOptions{
		Program:   prog,
		Interface: ifindex,
		Attach:    attach,
	})
	if err != nil {
		if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
			zap.S().Debugf("%s already attached to pod interface (ifindex: %d)", label, ifindex)
			return nil, nil
		}
		return nil, fmt.Errorf("attach %s to ifindex %d: %w", label, ifindex, err)
	}
	zap.S().Infof("attached %s to pod interface (ifindex: %d)", label, ifindex)
	return l, nil
}

func (p *PodAttacher) detach(key string) error {
	p.mu.Lock()
	snap, ok := p.snapshots[key]
	if ok {
		delete(p.snapshots, key)
	}
	p.mu.Unlock()
	if !ok {
		return nil
	}
	if errs := p.closeSnapshot(snap); len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (p *PodAttacher) closeSnapshot(snap attacherSnapshot) []error {
	var errs []error
	if snap.egressLink != nil {
		if err := snap.egressLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close pod-egress link (ifindex %d): %w", snap.ifindex, err))
		}
	}
	if snap.ingressLink != nil {
		if err := snap.ingressLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close pod-ingress link (ifindex %d): %w", snap.ifindex, err))
		}
	}
	return errs
}
