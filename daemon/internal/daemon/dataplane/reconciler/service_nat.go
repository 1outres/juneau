package reconciler

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/internal/convert"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/program"
)

// ServiceNAT mirrors the local Node's ServiceNATAttachment.assignedIP
// into the service_nat_ip BPF map so pod_egress.handle_service_shared
// can stamp shared-Service flows with this Node's SNAT source IP.
//
// The map is a single-entry array shared across the whole dataplane
// for this Node. The reconciler only writes the slot for events keyed
// to its own Node; cluster-wide informer fan-out for other Nodes'
// attachments is filtered out by planAction so we don't clobber our
// own slot when reacting to unrelated objects.
type ServiceNAT struct {
	client    client.Client
	podEgress *program.PodEgress
	nodeName  string

	mu        sync.Mutex
	installed bool
}

func NewServiceNAT(cl client.Client, podEgress *program.PodEgress, nodeName string) *ServiceNAT {
	return &ServiceNAT{
		client:    cl,
		podEgress: podEgress,
		nodeName:  nodeName,
	}
}

func (r *ServiceNAT) Name() string { return "service_nat" }

// natAction enumerates the possible reactions to a ServiceNATAttachment
// event. Decoupling the decision from the side effect lets planAction
// be unit-tested without touching the eBPF map.
type natAction uint8

const (
	natNoop natAction = iota
	natWrite
	natClear
)

// planAction decides what to do with an incoming reconcile event.
//
// The shared informer delivers events for every Node's
// ServiceNATAttachment, but each daemon only owns one slot in
// service_nat_ip (its own Node's). Events for other Nodes are
// completely irrelevant to that slot, so they must be a no-op —
// in particular, calling clear() on them would wipe the slot we just
// filled for our own Node.
//
// When the event IS for our Node:
//   - missing object → clear (the attachment was deleted)
//   - spec.NodeName moved to a different Node → clear (defensive: the
//     name<->NodeName convention should keep this from happening, but
//     if it does, we're no longer the owner)
//   - empty assignedIP → clear (controller hasn't allocated yet)
//   - valid IPv4 assignedIP → write
//   - non-IPv4 assignedIP → error (caller decides whether to retry)
func planAction(key, ourNode string, attachment *juneauv1alpha1.ServiceNATAttachment, notFound bool) (natAction, string, error) {
	if key != ourNode {
		return natNoop, "", nil
	}
	if notFound {
		return natClear, "", nil
	}
	if attachment.Spec.NodeName != ourNode {
		return natClear, "", nil
	}
	address := strings.TrimSpace(attachment.Status.AssignedIP)
	if address == "" {
		return natClear, "", nil
	}
	parsed := net.ParseIP(address)
	if parsed == nil || parsed.To4() == nil {
		return natNoop, "", fmt.Errorf("invalid assignedIP %q on ServiceNATAttachment %q", address, key)
	}
	return natWrite, address, nil
}

func (r *ServiceNAT) Reconcile(ctx context.Context, key string) error {
	var attachment juneauv1alpha1.ServiceNATAttachment
	err := r.client.Get(ctx, client.ObjectKey{Name: key}, &attachment)
	notFound := apierrors.IsNotFound(err)
	if err != nil && !notFound {
		return err
	}

	action, address, err := planAction(key, r.nodeName, &attachment, notFound)
	if err != nil {
		return err
	}

	switch action {
	case natNoop:
		return nil
	case natClear:
		return r.clear(key)
	case natWrite:
		hostIP, err := convert.IPv4ToBPFNetworkOrder(net.ParseIP(address))
		if err != nil {
			return fmt.Errorf("parse assignedIP %q: %w", address, err)
		}
		if err := r.podEgress.Objs.ServiceNatIp.Update(uint32(0), hostIP, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update service_nat_ip: %w", err)
		}
		r.mu.Lock()
		r.installed = true
		r.mu.Unlock()
		return nil
	}
	return nil
}

func (r *ServiceNAT) clear(_ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.installed {
		return nil
	}
	// service_nat_ip is a single-entry ARRAY map, so we cannot delete
	// the slot — overwrite with 0, which the BPF-side check treats as
	// "no SNAT IP available" and drops shared-Service traffic.
	if err := r.podEgress.Objs.ServiceNatIp.Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear service_nat_ip: %w", err)
	}
	r.installed = false
	return nil
}

// CloseAll resets the BPF map to 0 on shutdown so traffic doesn't get
// stamped with a stale source IP if the daemon restarts before the
// reconciler converges.
func (r *ServiceNAT) CloseAll() error {
	return r.clear("")
}
