package link

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// PodAttacher attaches the PodEgress TC program to each local pod
// interface and detaches it when the endpoint is deleted or migrates off
// this node.
//
// Unlike map reconcilers, PodAttacher owns file descriptors (ebpflink.Link
// handles) rather than eBPF map entries. It still implements the
// runner.Reconciler contract so the workqueue machinery can drive it.
type PodAttacher struct {
	client    client.Client
	podEgress *program.PodEgress
	nodeName  string

	mu        sync.Mutex
	snapshots map[string]attacherSnapshot
}

type attacherSnapshot struct {
	ifindex int
	link    ebpflink.Link // nil if the program was pre-attached by another owner
}

func NewPodAttacher(cl client.Client, podEgress *program.PodEgress, nodeName string) *PodAttacher {
	return &PodAttacher{
		client:    cl,
		podEgress: podEgress,
		nodeName:  nodeName,
		snapshots: make(map[string]attacherSnapshot),
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
		if snap.link == nil {
			continue
		}
		if err := snap.link.Close(); err != nil {
			errs = append(errs, err)
		}
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
		if err := p.closeLink(old); err != nil {
			return err
		}
	}

	l, err := ebpflink.AttachTCX(ebpflink.TCXOptions{
		Program:   p.podEgress.Objs.TcPodEgress,
		Interface: ifindex,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
			zap.S().Debugf("TC program already attached to pod interface (ifindex: %d)", ifindex)
			p.mu.Lock()
			p.snapshots[key] = attacherSnapshot{ifindex: ifindex, link: nil}
			p.mu.Unlock()
			return nil
		}
		return fmt.Errorf("attach TCX to ifindex %d: %w", ifindex, err)
	}

	zap.S().Infof("attached TC program to pod interface (ifindex: %d)", ifindex)
	p.mu.Lock()
	p.snapshots[key] = attacherSnapshot{ifindex: ifindex, link: l}
	p.mu.Unlock()
	return nil
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
	return p.closeLink(snap)
}

func (p *PodAttacher) closeLink(snap attacherSnapshot) error {
	if snap.link == nil {
		return nil
	}
	if err := snap.link.Close(); err != nil {
		return fmt.Errorf("close TC link (ifindex %d): %w", snap.ifindex, err)
	}
	return nil
}
